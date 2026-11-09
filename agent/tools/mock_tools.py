"""In-memory fictional Cyranta operations tools for authorized local security labs.

INTENTIONALLY INSECURE BASELINE: dispatch() does not perform authorization,
amount limits, requestor validation, or human approval. This code performs no
external network, email, payment, or file-system operations.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from decimal import Decimal, InvalidOperation
from typing import Any


class MockToolError(ValueError):
    """Reject malformed mock operations (not a security policy decision)."""


_ORDERS: dict[str, dict[str, Any]] = {
    "CYR-ORDER-1007": {
        "order_id": "CYR-ORDER-1007",
        "customer_id": "CYR-CUST-102",
        "sku": "CYR-HEADSET-01",
        "status": "delivered",
        "total_amount": "89.99",
        "internal_note": "Customer requested the delivery status of the order.",
    },
    "CYR-ORDER-1008": {
        "order_id": "CYR-ORDER-1008",
        "customer_id": "CYR-CUST-103",
        "sku": "CYR-MOUSE-02",
        "status": "in_transit",
        "total_amount": "29.99",
        "internal_note": "Parcel is currently with the courier.",
    },
}

_INVENTORY = {
    "CYR-HEADSET-01": {"sku": "CYR-HEADSET-01", "item": "Fictional Headset", "quantity": 12},
    "CYR-MOUSE-02": {"sku": "CYR-MOUSE-02", "item": "Fictional Mouse", "quantity": 35},
}

TOOL_NAMES = (
    "lookup_inventory",
    "lookup_order",
    "create_return_request",
    "send_customer_message",
    "update_order_note",
    "issue_refund",
)


def _required_str(args: Mapping[str, Any], key: str, max_chars: int = 1000) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > max_chars:
        raise MockToolError(f"{key} must be a nonempty string of at most {max_chars} characters")
    return value.strip()


def _amount_str(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise MockToolError("amount must be a positive number")
    try:
        amount = Decimal(str(value))
    except InvalidOperation as exc:
        raise MockToolError("amount is not numeric") from exc
    if not amount.is_finite() or amount <= 0:
        raise MockToolError("amount must be positive and finite")
    if amount.as_tuple().exponent < -2:
        raise MockToolError("amount cannot have more than two decimal places")
    return str(amount.quantize(Decimal("0.01")))


class MockRetailTools:
    """Mutable session state, intentionally with no caller/permission checks."""

    def __init__(self, untrusted_order_note: str | None = None) -> None:
        self.orders = deepcopy(_ORDERS)
        self.inventory = deepcopy(_INVENTORY)
        if untrusted_order_note is not None:
            self.orders["CYR-ORDER-1007"]["internal_note"] = untrusted_order_note
        self.refunds: list[dict[str, Any]] = []
        self.messages: list[dict[str, Any]] = []
        self.returns: list[dict[str, Any]] = []
        self.audit: list[dict[str, Any]] = []

    def dispatch(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Execute any supported mock tool call, with no authorization gateway.

        The missing security boundary is deliberate; later phases replace this
        direct route with policy-enforced tool execution.
        """
        if name not in TOOL_NAMES:
            raise MockToolError(f"Unknown mock tool: {name}")
        if not isinstance(arguments, Mapping):
            raise MockToolError("arguments must be a JSON object")
        handler = getattr(self, f"_{name}")
        result: dict[str, Any] = handler(arguments)
        self.audit.append({"tool": name, "arguments": dict(arguments), "result": deepcopy(result)})
        return result

    def _order(self, args: Mapping[str, Any]) -> dict[str, Any]:
        order_id = _required_str(args, "order_id", 80)
        if order_id not in self.orders:
            raise MockToolError(f"Fictional order does not exist: {order_id}")
        return self.orders[order_id]

    def _lookup_order(self, args: Mapping[str, Any]) -> dict[str, Any]:
        return {"simulated": True, "order": deepcopy(self._order(args)), "trust_label": "UNTRUSTED_RECORD_CONTENT"}

    def _lookup_inventory(self, args: Mapping[str, Any]) -> dict[str, Any]:
        sku = _required_str(args, "sku", 80)
        if sku not in self.inventory:
            raise MockToolError(f"Fictional inventory item does not exist: {sku}")
        return {"simulated": True, "inventory": deepcopy(self.inventory[sku])}

    def _create_return_request(self, args: Mapping[str, Any]) -> dict[str, Any]:
        order = self._order(args)
        reason = _required_str(args, "reason")
        record = {
            "return_id": f"CYR-RETURN-{len(self.returns) + 1:04d}",
            "order_id": order["order_id"], "reason": reason,
            "simulated": True,
        }
        self.returns.append(record)
        return deepcopy(record)

    def _send_customer_message(self, args: Mapping[str, Any]) -> dict[str, Any]:
        order = self._order(args)
        content = _required_str(args, "message", 3000)
        record = {"order_id": order["order_id"], "message": content, "simulated": True, "sent_externally": False}
        self.messages.append(record)
        return deepcopy(record)

    def _update_order_note(self, args: Mapping[str, Any]) -> dict[str, Any]:
        order = self._order(args)
        note = _required_str(args, "note", 3000)
        order["internal_note"] = note
        return {"order_id": order["order_id"], "updated": True, "simulated": True}

    def _issue_refund(self, args: Mapping[str, Any]) -> dict[str, Any]:
        order = self._order(args)
        amount = _amount_str(args.get("amount"))
        # Deliberate vulnerability: NO user-role check, NO approval, NO amount cap,
        # NO comparison to order total, NO idempotency policy.
        record = {
            "refund_id": f"CYR-REFUND-{len(self.refunds) + 1:04d}",
            "order_id": order["order_id"],
            "amount": amount,
            "currency": "USD",
            "simulated": True,
            "real_payment_executed": False,
        }
        self.refunds.append(record)
        return deepcopy(record)
