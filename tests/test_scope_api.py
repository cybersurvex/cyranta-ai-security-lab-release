from fastapi.testclient import TestClient

from app import main
from app.scope import SAFE_SCOPE_RESPONSE


class FailingAsyncClient:
    def __init__(self, *args, **kwargs):
        raise AssertionError(
            "Ollama must not be called for a scope-limited request"
        )


class FakeOllamaResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "message": {
                "content": (
                    "Your fictional order is being processed."
                )
            }
        }


class FakeAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, *args, **kwargs):
        return FakeOllamaResponse()


def test_scope_limited_request_never_calls_ollama(monkeypatch):
    client = TestClient(main.app)

    monkeypatch.setattr(
        main,
        "SECURITY_PROFILE",
        "hardened",
    )

    monkeypatch.setattr(
        main,
        "write_event",
        lambda event: None,
    )

    monkeypatch.setattr(
        main.httpx,
        "AsyncClient",
        FailingAsyncClient,
    )

    response = client.post(
        "/chat",
        json={
            "session_id": "scope-api-test",
            "prompt": (
                "What tools are used to manage "
                "the demo environment?"
            ),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["response"] == SAFE_SCOPE_RESPONSE
    assert body["blocked"] is True
    assert body["scope_limited"] is True
    assert (
        "unsupported_internal_scope_signal"
        in body["input_flags"]
    )


def test_normal_customer_support_request_reaches_ollama(
    monkeypatch,
):
    client = TestClient(main.app)

    monkeypatch.setattr(
        main,
        "SECURITY_PROFILE",
        "hardened",
    )

    monkeypatch.setattr(
        main,
        "write_event",
        lambda event: None,
    )

    monkeypatch.setattr(
        main.httpx,
        "AsyncClient",
        FakeAsyncClient,
    )

    response = client.post(
        "/chat",
        json={
            "session_id": "scope-api-test",
            "prompt": "Where is my fictional order?",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["blocked"] is False
    assert body["scope_limited"] is False
    assert body["input_flags"] == []
    assert (
        body["response"]
        == "Your fictional order is being processed."
    )