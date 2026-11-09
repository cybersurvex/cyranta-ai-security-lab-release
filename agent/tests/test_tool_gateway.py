"""CYR-AGENT-001 regression tests; deterministic, no network or money."""
import json

import pytest

from agent.app import hardened_agent as ha
from agent.app import vulnerable_agent as va
from agent.security.tool_gateway import SERVICE_ID, Principal, ToolGateway
from agent.tools.mock_tools import MockRetailTools

NOTE = va.ATTACK_NOTE.read_text(encoding="utf-8")
REPLAY = json.loads(va.REPLAY_CALL.read_text(encoding="utf-8"))


def principal(role="support_readonly", *, order_ids=None, agent_id=SERVICE_ID, user_id="CYR-EMP-RO-01"):
    return Principal(user_id=user_id, role=role, agent_id=agent_id,
                     order_ids=frozenset(order_ids or {va.ORDER_ID}),
                     skus=frozenset({"CYR-HEADSET-01"}))


def test_same_replay_blocked_no_refund():
    out = ha.run_hardened(mode="replay", attack_note=NOTE, replay_call=REPLAY)
    assert out["suggested_tool"] == "issue_refund"
    assert out["gateway_decision_code"] == "ROLE_TOOL_DENIED"
    assert out["gateway_allowed"] is False
    assert out["simulated_refund_executed"] is False
    assert out["mock_refunds"] == []
    assert out["proposal_source"] == "synthetic_fixture_not_llm_output"


def test_live_model_mocked_proposal_is_blocked(monkeypatch):
    # NOT real Ollama, only application gateway behavior.
    monkeypatch.setattr(va, "request_ollama_tool_call", lambda *a, **kw: (
        {"name": "issue_refund", "arguments": {"order_id": va.ORDER_ID, "amount": "499.99"}}, ""))
    out = ha.run_hardened(mode="ollama", attack_note=NOTE)
    assert out["proposal_source"] == "live_local_ollama_structured_tool_call"
    assert out["gateway_decision_code"] == "ROLE_TOOL_DENIED"
    assert out["simulated_refund_executed"] is False


def test_no_model_call_means_no_tool_execution(monkeypatch):
    monkeypatch.setattr(va, "request_ollama_tool_call", lambda *a, **kw: (None, "Nothing to do"))
    out = ha.run_hardened(mode="ollama", attack_note=NOTE)
    assert out["gateway_decision_code"] == "NO_TOOL_PROPOSED"
    assert out["simulated_refund_executed"] is False


def test_authorized_read_and_trust_label():
    tools = MockRetailTools(untrusted_order_note=NOTE)
    gateway = ToolGateway(tools)
    actor = principal()
    cap = gateway.issue_capability(actor, "lookup_order", va.ORDER_ID)
    result = gateway.execute(actor, "lookup_order", {"order_id": va.ORDER_ID}, capability=cap)
    assert result.allowed is True
    assert result.result["trust_label"] == "UNTRUSTED_RECORD_CONTENT"
    assert len(gateway.audit) == 1


def test_readonly_cannot_issue_refund_capability():
    gw = ToolGateway(MockRetailTools())
    with pytest.raises(PermissionError, match="CAPABILITY_ISSUE_DENIED"):
        gw.issue_capability(principal(), "issue_refund", va.ORDER_ID)


def test_model_cannot_override_role_with_arguments():
    gw = ToolGateway(MockRetailTools())
    user = principal()
    cap = gw.issue_capability(user, "lookup_order", va.ORDER_ID)
    result = gw.execute(user, "issue_refund", {
        "order_id": va.ORDER_ID, "amount": "10.00", "role": "refund_specialist",
        "approved": True,
    }, capability=cap)
    assert result.code == "ROLE_TOOL_DENIED"
    assert not gw._tools.refunds


def test_resource_level_order_scoping():
    gw = ToolGateway(MockRetailTools())
    actor = principal(order_ids={va.ORDER_ID})
    cap = gw.issue_capability(actor, "lookup_order", va.ORDER_ID)
    result = gw.execute(actor, "lookup_order", {"order_id": "CYR-ORDER-1008"}, capability=cap)
    assert result.code == "RESOURCE_DENIED"


def test_invalid_service_identity_denied():
    gw = ToolGateway(MockRetailTools())
    wrong = principal(agent_id="unknown-service")
    result = gw.execute(wrong, "lookup_order", {"order_id": va.ORDER_ID})
    assert result.code == "AGENT_IDENTITY_DENIED"


def test_missing_capability_denied():
    gw = ToolGateway(MockRetailTools())
    result = gw.execute(principal(), "lookup_order", {"order_id": va.ORDER_ID})
    assert result.code == "CAPABILITY_REQUIRED"


def test_forged_capability_denied():
    gw = ToolGateway(MockRetailTools())
    result = gw.execute(principal(), "lookup_order", {"order_id": va.ORDER_ID}, capability="forged")
    assert result.code == "CAPABILITY_INVALID_OR_EXPIRED"


def test_capability_bound_to_actor():
    gw = ToolGateway(MockRetailTools())
    cap = gw.issue_capability(principal(), "lookup_order", va.ORDER_ID)
    other = principal(user_id="CYR-EMP-RO-02")
    result = gw.execute(other, "lookup_order", {"order_id": va.ORDER_ID}, capability=cap)
    assert result.code == "CAPABILITY_SCOPE_MISMATCH"


def test_capability_expires_and_revoked():
    clock = [1000.0]
    gw = ToolGateway(MockRetailTools(), now=lambda: clock[0])
    actor = principal()
    cap = gw.issue_capability(actor, "lookup_order", va.ORDER_ID, ttl_seconds=5)
    assert gw.execute(actor, "lookup_order", {"order_id": va.ORDER_ID}, capability=cap).allowed
    clock[0] += 5
    assert gw.execute(actor, "lookup_order", {"order_id": va.ORDER_ID}, capability=cap).code == "CAPABILITY_INVALID_OR_EXPIRED"
    cap = gw.issue_capability(actor, "lookup_order", va.ORDER_ID)
    gw.revoke_capability(cap)
    assert gw.execute(actor, "lookup_order", {"order_id": va.ORDER_ID}, capability=cap).code == "CAPABILITY_INVALID_OR_EXPIRED"


def test_high_impact_needs_separate_approval():
    tools = MockRetailTools()
    gw = ToolGateway(tools)
    actor = principal("refund_specialist")
    cap = gw.issue_capability(actor, "issue_refund", va.ORDER_ID)
    result = gw.execute(actor, "issue_refund", {"order_id": va.ORDER_ID, "amount": "30.00"}, capability=cap)
    assert result.code == "APPROVAL_REQUIRED"
    assert tools.refunds == []


def test_supervisor_grant_is_bound_to_exact_amount_and_order():
    tools = MockRetailTools()
    gw = ToolGateway(tools)
    actor = principal("refund_specialist")
    cap = gw.issue_capability(actor, "issue_refund", va.ORDER_ID)
    approval = gw.approve_refund(actor, order_id=va.ORDER_ID, amount="20.00", approved_by="CYR-SUP-01")
    result = gw.execute(actor, "issue_refund", {"order_id": va.ORDER_ID, "amount": "30.00"},
                        capability=cap, approval=approval)
    assert result.code == "APPROVAL_SCOPE_MISMATCH"
    assert tools.refunds == []


def test_human_approval_cannot_be_self_issued():
    gw = ToolGateway(MockRetailTools())
    actor = principal("refund_specialist")
    with pytest.raises(PermissionError, match="SUPERVISOR_UNAUTHORIZED"):
        gw.approve_refund(actor, order_id=va.ORDER_ID, amount="20.00", approved_by=actor.user_id)


def test_authorized_refund_requires_approval_and_is_one_use():
    tools = MockRetailTools()
    gw = ToolGateway(tools)
    actor = principal("refund_specialist")
    cap = gw.issue_capability(actor, "issue_refund", va.ORDER_ID)
    approval = gw.approve_refund(actor, order_id=va.ORDER_ID, amount="20", approved_by="CYR-SUP-01")
    args = {"order_id": va.ORDER_ID, "amount": "20.00"}
    result = gw.execute(actor, "issue_refund", args, capability=cap, approval=approval)
    assert result.allowed and tools.refunds[0]["real_payment_executed"] is False
    second = gw.execute(actor, "issue_refund", args, capability=cap, approval=approval)
    assert second.allowed is False
    assert second.code == "DUPLICATE_REFUND"
    assert len(tools.refunds) == 1


def test_refund_cannot_exceed_order_total_even_with_approval():
    gw = ToolGateway(MockRetailTools())
    actor = principal("refund_specialist")
    cap = gw.issue_capability(actor, "issue_refund", va.ORDER_ID)
    args = {"order_id": va.ORDER_ID, "amount": "499.99"}
    result = gw.execute(actor, "issue_refund", args, capability=cap)
    assert result.code == "REFUND_LIMIT_EXCEEDED"
    with pytest.raises(ValueError, match="REFUND_LIMIT_EXCEEDED"):
        gw.approve_refund(actor, order_id=va.ORDER_ID, amount="499.99", approved_by="CYR-SUP-01")


def test_approval_expiry():
    clock = [200.0]
    tools = MockRetailTools()
    gw = ToolGateway(tools, now=lambda: clock[0])
    actor = principal("refund_specialist")
    cap = gw.issue_capability(actor, "issue_refund", va.ORDER_ID, ttl_seconds=120)
    approval = gw.approve_refund(actor, order_id=va.ORDER_ID, amount="10", approved_by="CYR-SUP-01", ttl_seconds=5)
    clock[0] += 5
    result = gw.execute(actor, "issue_refund", {"order_id": va.ORDER_ID, "amount": "10"},
                        capability=cap, approval=approval)
    assert result.code == "APPROVAL_INVALID_OR_EXPIRED"


def test_emergency_revoke_denies_all_actions_and_grant_issuance():
    tools = MockRetailTools()
    gw = ToolGateway(tools)
    actor = principal()
    cap = gw.issue_capability(actor, "lookup_order", va.ORDER_ID)
    gw.emergency_revoke()
    assert gw.execute(actor, "lookup_order", {"order_id": va.ORDER_ID}, capability=cap).code == "EMERGENCY_REVOKED"
    with pytest.raises(PermissionError, match="EMERGENCY_REVOKED"):
        gw.issue_capability(actor, "lookup_order", va.ORDER_ID)


def test_audit_excludes_bearer_tokens_and_untrusted_note():
    tools = MockRetailTools(untrusted_order_note=NOTE)
    gw = ToolGateway(tools)
    actor = principal()
    cap = gw.issue_capability(actor, "lookup_order", va.ORDER_ID)
    gw.execute(actor, "lookup_order", {"order_id": va.ORDER_ID}, capability=cap)
    log = json.dumps(gw.audit)
    assert cap not in log
    assert NOTE not in log
    assert "user_id" in gw.audit[0] and "decision_code" in gw.audit[0]


def test_counterfactual_benign_note_is_separate_run(monkeypatch):
    captured = []
    def fake_llm(record, **kwargs):
        captured.append(record["order"]["internal_note"])
        return None, "Checked"
    monkeypatch.setattr(va, "request_ollama_tool_call", fake_llm)
    out = ha.run_hardened(mode="ollama", attack_note=NOTE, control_no_injection=True)
    assert out["control_no_injection"] is True
    assert captured == [ha.BENIGN_NOTE]
    assert out["simulated_refund_executed"] is False
