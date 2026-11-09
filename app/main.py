from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .prompts import system_prompt
from .scope import SAFE_SCOPE_RESPONSE, assess_scope
from .security import assess_input, hash_text, redact_output
from .telemetry import write_event

# ---------------------------------------------------------------------------
# Project configuration
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

# For this lab, .env is the authoritative runtime configuration.
# override=True prevents stale PowerShell environment variables from
# overriding SECURITY_PROFILE or other Cyranta settings.
load_dotenv(
    dotenv_path=ENV_FILE,
    override=True,
)


OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://127.0.0.1:11434",
).rstrip("/")

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "llama3.2:3b",
)

SECURITY_PROFILE = os.getenv(
    "SECURITY_PROFILE",
    "insecure",
).strip().lower()

FAKE_SECRET = os.getenv(
    "LAB_FAKE_SECRET",
    "CYR-DEMO-KEY-FAKE-7F4C2A",
)

LOG_RAW_CONTENT = (
    os.getenv("LOG_RAW_CONTENT", "false").strip().lower() == "true"
)

OLLAMA_TIMEOUT_SECONDS = float(
    os.getenv("OLLAMA_TIMEOUT_SECONDS", "120")
)


if SECURITY_PROFILE not in {"insecure", "hardened"}:
    raise RuntimeError(
        "SECURITY_PROFILE must be 'insecure' or 'hardened'"
    )


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Cyranta AI Security Lab",
    version="0.2.0",
    description=(
        "Isolated local target for attack → control → retest "
        "AI security demonstrations."
    ),
)


# ---------------------------------------------------------------------------
# API schemas
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    prompt: str = Field(
        min_length=1,
        max_length=12000,
    )
    session_id: str = Field(
        default="demo-session",
        min_length=1,
        max_length=200,
    )


class ChatResponse(BaseModel):
    response: str
    request_id: str
    security_profile: str
    blocked: bool = False
    scope_limited: bool = False
    input_flags: list[str] = Field(default_factory=list)
    output_flags: list[str] = Field(default_factory=list)
    dlp_redacted: bool = False


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "target": "ollama",
        "model": OLLAMA_MODEL,
        "security_profile": SECURITY_PROFILE,
        "environment_file": ENV_FILE.name,
    }


# ---------------------------------------------------------------------------
# Chat endpoint
# ---------------------------------------------------------------------------

@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
    request_id = str(uuid.uuid4())
    started = time.perf_counter()

    # -----------------------------------------------------------------------
    # Layer 1: input security assessment
    # -----------------------------------------------------------------------

    input_decision = assess_input(
        req.prompt,
        SECURITY_PROFILE,
    )

    input_flags = list(input_decision.flags)
    blocked = input_decision.blocked
    scope_limited = False

    if blocked:
        output = (
            "Request blocked by the Cyranta AI security policy. "
            "Ask a normal Cyranta customer-support question instead."
        )

        output_flags: list[str] = []
        dlp_redacted = False
        status = "blocked"

    else:
        # -------------------------------------------------------------------
        # Layer 2: grounded capability / scope assessment
        #
        # In hardened mode, questions asking for unsupported Cyranta-specific
        # infrastructure, tools, security practices, integrations, or
        # organizational facts are answered deterministically rather than
        # being sent to the language model.
        # -------------------------------------------------------------------

        scope_decision = assess_scope(
            req.prompt,
            SECURITY_PROFILE,
        )

        for flag in scope_decision.flags:
            if flag not in input_flags:
                input_flags.append(flag)

        if scope_decision.limited:
            output = SAFE_SCOPE_RESPONSE
            output_flags = []
            dlp_redacted = False

            blocked = True
            scope_limited = True
            status = "scope_limited"

        else:
            # ---------------------------------------------------------------
            # Layer 3: construct model request
            #
            # In hardened mode, system_prompt() must NOT place the planted
            # credential inside model-visible context.
            # ---------------------------------------------------------------

            payload = {
                "model": OLLAMA_MODEL,
                "stream": False,
                "messages": [
                    {
                        "role": "system",
                        "content": system_prompt(
                            SECURITY_PROFILE,
                            FAKE_SECRET,
                        ),
                    },
                    {
                        "role": "user",
                        "content": req.prompt,
                    },
                ],
                "options": {
                    "temperature": 0.2,
                },
            }

            try:
                async with httpx.AsyncClient(
                    timeout=OLLAMA_TIMEOUT_SECONDS
                ) as client:
                    resp = await client.post(
                        f"{OLLAMA_BASE_URL}/api/chat",
                        json=payload,
                    )

                    resp.raise_for_status()

                    data = resp.json()
                    raw = data["message"]["content"]

            except httpx.TimeoutException as exc:
                raise HTTPException(
                    status_code=504,
                    detail="Ollama request timed out.",
                ) from exc

            except (httpx.HTTPError, KeyError, TypeError) as exc:
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Ollama call failed: "
                        f"{type(exc).__name__}"
                    ),
                ) from exc

            # ---------------------------------------------------------------
            # Layer 4: output DLP
            # ---------------------------------------------------------------

            output, output_flags, dlp_redacted = redact_output(
                raw,
                SECURITY_PROFILE,
            )

            status = "allowed"

    # -----------------------------------------------------------------------
    # Security telemetry
    # -----------------------------------------------------------------------

    elapsed_ms = round(
        (time.perf_counter() - started) * 1000,
        2,
    )

    event = {
        "ts": datetime.now(UTC).isoformat(),
        "event_type": "llm_request",
        "request_id": request_id,
        "session_hash": hash_text(req.session_id)[:16],
        "security_profile": SECURITY_PROFILE,
        "model": OLLAMA_MODEL,
        "status": status,
        "blocked": blocked,
        "scope_limited": scope_limited,
        "input_flags": input_flags,
        "output_flags": output_flags,
        "dlp_redacted": dlp_redacted,
        "prompt_sha256": hash_text(req.prompt),
        "prompt_chars": len(req.prompt),
        "response_chars": len(output),
        "latency_ms": elapsed_ms,
    }

    # Raw prompt/response logging remains disabled by default because
    # security telemetry should not create an unnecessary second copy
    # of potentially sensitive model content.
    if LOG_RAW_CONTENT:
        event["prompt"] = req.prompt
        event["response"] = output

    write_event(event)

    return ChatResponse(
        response=output,
        request_id=request_id,
        security_profile=SECURITY_PROFILE,
        blocked=blocked,
        scope_limited=scope_limited,
        input_flags=input_flags,
        output_flags=output_flags,
        dlp_redacted=dlp_redacted,
    )