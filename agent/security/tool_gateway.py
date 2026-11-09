"""Cyranta Project 3: in-process gateway for SIMULATED business tools.

Security boundary: untrusted LLM output is a *request*, never an authorization grant.
All principal objects, scoped tokens and approvals must come from trusted server code.
This is an educational local lab, not a production authentication service.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import Any
from uuid import uuid4

from agent.tools.mock_tools import TOOL_NAMES, MockRetailTools, MockToolError

SERVICE_ID = "cyranta-ops-agent"
REFUND_LIMIT = Decimal("100.00")
ROLE_PERMISSIONS = {
    "support_readonly": frozenset({"lookup_order", "lookup_inventory"}),
    "support_editor": frozenset({"lookup_order", "lookup_inventory", "create_return_request",
                                  "send_customer_message", "update_order_note"}),
    "refund_specialist": frozenset({"lookup_order", "lookup_inventory", "issue_refund"}),
}
HIGH_IMPACT = frozenset({"issue_refund"})
# Explicitly configured local supervisor fixture; only trusted server code may call approve_refund().
MOCK_SUPERVISORS = frozenset({"CYR-SUP-01"})


@dataclass(frozen=True)
class Principal:
    """Trusted session identity. Never construct this from model-supplied arguments."""
    user_id: str
    role: str
    agent_id: str
    order_ids: frozenset[str]
    skus: frozenset[str]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    request_id: str
    tool: str
    resource: str | None
    result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "code": self.code,
            "request_id": self.request_id,
            "tool": self.tool,
            "resource": self.resource,
            "result": self.result,
        }


class ToolGateway:
    """Policy enforcement plus in-memory capability and approval registries.

    The registries, issue_capability, and approve_refund are TRUSTED BACKEND methods.
    They must NOT be exposed as LLM tools or HTTP endpoints without real authn/authz.
    """

    def __init__(self, tools: MockRetailTools, *, now: Callable[[], float] | None = None) -> None:
        self._tools = tools
        self._now = now or time.time
        self._lock = threading.RLock()
        self._caps: dict[str, dict[str, Any]] = {}
        self._approvals: dict[str, dict[str, Any]] = {}
        self._emergency_revoked = False
        self.audit: list[dict[str, Any]] = []

    @staticmethod
    def _resource(tool: str, arguments: Mapping[str, Any]) -> str | None:
        key = "sku" if tool == "lookup_inventory" else "order_id"
        value = arguments.get(key)
        return value if isinstance(value, str) and 0 < len(value) <= 80 else None

    @staticmethod
    def _scope_ok(principal: Principal, tool: str, resource: str | None) -> bool:
        if principal.agent_id != SERVICE_ID or principal.role not in ROLE_PERMISSIONS:
            return False
        if tool not in ROLE_PERMISSIONS[principal.role]:
            return False
        if resource is None:
            return False
        if tool == "lookup_inventory":
            return resource in principal.skus
        return resource in principal.order_ids

    def _record(self, principal: Principal, tool: str, resource: str | None,
                allowed: bool, code: str, result: dict[str, Any] | None = None) -> Decision:
        request_id = str(uuid4())
        # Never log arguments, notes, capability bearer strings or approval bearer strings.
        self.audit.append({
            "request_id": request_id,
            "time_epoch": self._now(),
            "user_id": principal.user_id,
            "agent_id": principal.agent_id,
            "role": principal.role,
            "tool": tool,
            "resource": resource,
            "allowed": allowed,
            "decision_code": code,
        })
        return Decision(allowed, code, request_id, tool, resource, result)

    @staticmethod
    def _digest(token: str) -> str:
        return sha256(token.encode("utf-8")).hexdigest()

    def issue_capability(self, principal: Principal, tool: str, resource: str, *, ttl_seconds: int = 60) -> str:
        """Trusted issuer; model must never be able to request grants directly."""
        with self._lock:
            if self._emergency_revoked:
                raise PermissionError("EMERGENCY_REVOKED")
            if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 300:
                raise ValueError("Capability TTL must be 1..300 seconds")
            if not self._scope_ok(principal, tool, resource):
                raise PermissionError("CAPABILITY_ISSUE_DENIED")
            token = secrets.token_urlsafe(32)
            self._caps[self._digest(token)] = {
                "user": principal.user_id, "role": principal.role,
                "agent": principal.agent_id, "tool": tool, "resource": resource,
                "expires": self._now() + ttl_seconds, "revoked": False,
            }
            return token

    def revoke_capability(self, token: str) -> None:
        with self._lock:
            item = self._caps.get(self._digest(token))
            if item is not None:
                item["revoked"] = True

    def emergency_revoke(self) -> None:
        with self._lock:
            self._emergency_revoked = True
            self._caps.clear()
            self._approvals.clear()

    def approve_refund(self, principal: Principal, *, order_id: str,
                       amount: str | float | Decimal, approved_by: str,
                       ttl_seconds: int = 90) -> str:
        """Out-of-band supervisor action. Deliberately not registered as an LLM tool.

        The trusted lab harness calls this method to emulate an independent supervisor.
        A production version would require verified supervisor auth and durable approval.
        """
        with self._lock:
            if self._emergency_revoked:
                raise PermissionError("EMERGENCY_REVOKED")
            if approved_by not in MOCK_SUPERVISORS or approved_by == principal.user_id:
                raise PermissionError("SUPERVISOR_UNAUTHORIZED")
            if not self._scope_ok(principal, "issue_refund", order_id):
                raise PermissionError("APPROVAL_ISSUE_DENIED")
            if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 300:
                raise ValueError("Approval TTL must be 1..300 seconds")
            amount_value = self._refund_amount(amount)
            self._check_refund_business_rules(order_id, amount_value)
            token = secrets.token_urlsafe(32)
            self._approvals[self._digest(token)] = {
                "user": principal.user_id, "agent": principal.agent_id,
                "tool": "issue_refund", "resource": order_id,
                "amount": str(amount_value), "supervisor": approved_by,
                "expires": self._now() + ttl_seconds, "used": False,
            }
            return token

    @staticmethod
    def _refund_amount(raw: Any) -> Decimal:
        if isinstance(raw, bool) or not isinstance(raw, (int, float, str, Decimal)):
            raise ValueError("INVALID_AMOUNT")  # noqa: TRY004
        try:
            amount = Decimal(str(raw))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("INVALID_AMOUNT") from exc
        if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -2:
            raise ValueError("INVALID_AMOUNT")
        return amount.quantize(Decimal("0.01"))

    def _check_refund_business_rules(self, order_id: str, amount: Decimal) -> None:
        order = self._tools.orders.get(order_id)
        if order is None:
            raise ValueError("UNKNOWN_ORDER")
        if amount > REFUND_LIMIT or amount > Decimal(order["total_amount"]):
            raise ValueError("REFUND_LIMIT_EXCEEDED")
        if any(r["order_id"] == order_id for r in self._tools.refunds):
            raise ValueError("DUPLICATE_REFUND")

    def execute(self, principal: Principal, tool: str, arguments: Mapping[str, Any], *,
                capability: str | None = None, approval: str | None = None) -> Decision:
        """The only tool execution entrypoint for the hardened demonstration."""
        with self._lock:
            args = arguments if isinstance(arguments, Mapping) else {}
            resource = self._resource(tool, args)

            def deny(code: str) -> Decision:
                return self._record(principal, tool, resource, False, code)

            if self._emergency_revoked:
                return deny("EMERGENCY_REVOKED")
            if tool not in TOOL_NAMES:
                return deny("UNKNOWN_TOOL")
            if principal.agent_id != SERVICE_ID:
                return deny("AGENT_IDENTITY_DENIED")
            if principal.role not in ROLE_PERMISSIONS or tool not in ROLE_PERMISSIONS[principal.role]:
                return deny("ROLE_TOOL_DENIED")
            if not self._scope_ok(principal, tool, resource):
                return deny("RESOURCE_DENIED")
            if not isinstance(capability, str):
                return deny("CAPABILITY_REQUIRED")
            grant = self._caps.get(self._digest(capability))
            if grant is None or grant["revoked"] or grant["expires"] <= self._now():
                return deny("CAPABILITY_INVALID_OR_EXPIRED")
            if (grant["user"] != principal.user_id or grant["role"] != principal.role
                    or grant["agent"] != principal.agent_id or grant["tool"] != tool
                    or grant["resource"] != resource):
                return deny("CAPABILITY_SCOPE_MISMATCH")

            approval_record = None
            if tool in HIGH_IMPACT:
                try:
                    amount = self._refund_amount(args.get("amount"))
                    self._check_refund_business_rules(resource, amount)
                except ValueError as exc:
                    return deny(str(exc))
                if not isinstance(approval, str):
                    return deny("APPROVAL_REQUIRED")
                approval_record = self._approvals.get(self._digest(approval))
                if (approval_record is None or approval_record["used"]
                        or approval_record["expires"] <= self._now()):
                    return deny("APPROVAL_INVALID_OR_EXPIRED")
                if (approval_record["user"] != principal.user_id
                        or approval_record["agent"] != principal.agent_id
                        or approval_record["tool"] != tool
                        or approval_record["resource"] != resource
                        or approval_record["amount"] != str(amount)):
                    return deny("APPROVAL_SCOPE_MISMATCH")

            try:
                result = self._tools.dispatch(tool, args)
            except (MockToolError, ValueError, TypeError):
                return deny("TOOL_INPUT_REJECTED")
            if approval_record is not None:
                approval_record["used"] = True
            return self._record(principal, tool, resource, True, "ALLOWED", result)
