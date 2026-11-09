"""Tests describe observed broken security controls, not desired production behavior."""
import json

import pytest

from agent.app import vulnerable_agent as va
from agent.tools.mock_tools import MockRetailTools, MockToolError

NOTE = va.ATTACK_NOTE.read_text(encoding="utf-8")
REPLAY = json.loads(va.REPLAY_CALL.read_text(encoding="utf-8"))


def test_replay_exposes_unapproved_refund_execution():
    outcome = va.run_baseline(mode="replay", attack_note=NOTE, replay_call=REPLAY)
    assert outcome["proposal_source"] == "synthetic_fixture_not_llm_output"
    assert outcome["simulated_refund_executed"] is True
    assert outcome["authorization_enforced"] is False
    assert outcome["human_approval_enforced"] is False
    assert outcome["mock_refunds"][0]["amount"] == "499.99"
    assert outcome["tool_result"]["real_payment_executed"] is False


def test_lookup_order_marks_record_untrusted():
    tools = MockRetailTools(untrusted_order_note=NOTE)
    result = tools.dispatch("lookup_order", {"order_id": va.ORDER_ID})
    assert result["trust_label"] == "UNTRUSTED_RECORD_CONTENT"
    assert "issue_refund" in result["order"]["internal_note"]


def test_legitimate_inventory_read_still_works():
    tools = MockRetailTools()
    result = tools.dispatch("lookup_inventory", {"sku": "CYR-HEADSET-01"})
    assert result["inventory"]["quantity"] == 12
    assert tools.refunds == []


def test_write_action_is_possible_even_for_nominal_readonly_actor():
    outcome = va.run_baseline(
        mode="replay", attack_note=NOTE,
        replay_call={"name": "update_order_note", "arguments": {
            "order_id": va.ORDER_ID, "note": "unauthorized overwrite"}},
    )
    assert outcome["tool_execution_occurred"] is True
    assert outcome["tool_result"]["updated"] is True


def test_invalid_amount_cannot_crash_or_create_refund():
    tools = MockRetailTools()
    with pytest.raises(MockToolError):
        tools.dispatch("issue_refund", {"order_id": va.ORDER_ID, "amount": "NaN"})
    assert tools.refunds == []


def test_refund_larger_than_order_total_is_allowed_on_purpose():
    tools = MockRetailTools()
    item = tools.dispatch("issue_refund", {"order_id": va.ORDER_ID, "amount": 499.99})
    assert item["amount"] == "499.99"
    assert item["real_payment_executed"] is False


def test_non_local_ollama_is_rejected():
    with pytest.raises(ValueError):
        va._verify_loopback_ollama_url("https://api.example.com/api/chat")
    with pytest.raises(ValueError):
        va._verify_loopback_ollama_url("http://127.0.0.1:11434/api/chat?redirect=1")


def test_ollama_without_model_tool_call_is_not_counted_as_exploit(monkeypatch):
    monkeypatch.setattr(va, "request_ollama_tool_call", lambda *a, **k: (None, "No refund needed"))
    outcome = va.run_baseline(mode="ollama", attack_note=NOTE)
    assert outcome["tool_execution_occurred"] is False
    assert outcome["simulated_refund_executed"] is False
    assert outcome["proposal_source"] == "live_local_ollama_no_tool_call"


def test_ollama_structured_tool_call_can_execute_without_approval(monkeypatch):
    # MOCKED LLM RESPONSE: tests the orchestrator, not live Ollama compromise.
    monkeypatch.setattr(va, "request_ollama_tool_call", lambda *a, **k: (
        {"name": "issue_refund", "arguments": {"order_id": va.ORDER_ID, "amount": 499.99}}, ""))
    outcome = va.run_baseline(mode="ollama", attack_note=NOTE)
    assert outcome["simulated_refund_executed"] is True
    assert outcome["proposal_source"] == "live_local_ollama_structured_tool_call"


def test_mock_tools_have_no_external_side_effects():
    tools = MockRetailTools()
    message = tools.dispatch("send_customer_message", {"order_id": va.ORDER_ID, "message": "Hello"})
    assert message["sent_externally"] is False
    assert len(tools.messages) == 1
