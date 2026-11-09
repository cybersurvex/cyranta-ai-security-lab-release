from __future__ import annotations

import base64
import codecs
import hashlib
import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Input detection
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    # Direct instruction override.
    (
        r"\bignore\b.{0,40}\b(previous|prior|all|system)\b"
        r".{0,40}\binstructions?\b"
    ),

    # System prompt / hidden instruction extraction.
    (
        r"\b(?:print|reveal|show|return|provide|display|repeat|expose)\b"
        r".{0,120}"
        r"\b(?:system\s+(?:prompt|message|instructions?)|"
        r"hidden\s+instructions?|"
        r"original\s+system\s+instructions?|"
        r"initial\s+instructions?)\b"
    ),

    # Reverse ordering, e.g. "system instructions ... show them".
    (
        r"\b(?:system\s+(?:prompt|message|instructions?)|"
        r"hidden\s+instructions?|"
        r"original\s+system\s+instructions?|"
        r"initial\s+instructions?)\b"
        r".{0,120}"
        r"\b(?:print|reveal|show|return|provide|display|repeat|expose|"
        r"verbatim)\b"
    ),

    # Common jailbreak framing.
    r"\bdeveloper\s+mode\b",
    r"\bdan\b",

    # Task replacement / forced-output hijacking.
    (
        r"\b(?:stop|drop|abandon|forget|disregard|override)\b"
        r".{0,60}"
        r"\b(?:everything|current\s+(?:task|instructions?)|"
        r"previous\s+instructions?|prior\s+instructions?|rules?|context)\b"
        r".{0,100}"
        r"\b(?:just|only)\s+"
        r"(?:print|say|output|return|respond|reply|write)\b"
    ),
]

SENSITIVE_ACCESS_PATTERNS = [
    r"\b(?:what\s+is|what's|show|tell|give|return|provide|reveal|print)\b.{0,80}\b(?:api\s*key|integration\s*key|secret|credential|token|password)\b",
    r"\b(?:internal|demo|configured|current|hidden)\b.{0,80}\b(?:api\s*key|integration\s*key|secret|credential|token|password)\b",
    r"\b(?:api\s*key|integration\s*key|secret|credential|token|password)\b.{0,80}\b(?:configured|internal|current|hidden)\b",
]


# ---------------------------------------------------------------------------
# Output DLP detection
# ---------------------------------------------------------------------------

# Intentionally scoped to the planted Cyranta lab canary.
# We will expand this later with more realistic credential detectors.
SECRET_PATTERNS = [
    r"\bCYR-DEMO-KEY-FAKE-[A-Z0-9-]+\b",
]


@dataclass
class SecurityDecision:
    flags: list[str]
    blocked: bool

def _decoded_input_views(text: str) -> list[tuple[str, str]]:
    """
    Return alternate representations of potentially encoded user input.

    Security principle:
    - Decode plausible encoded content for inspection.
    - Do not block merely because something is encoded.
    - Block only if the decoded content matches a security detector.
    """

    views: list[tuple[str, str]] = [
        ("raw", text),
    ]

    seen: set[tuple[str, str]] = {
        ("raw", text),
    }

    # -------------------------------------------------------------
    # Base64
    #
    # Do not require the literal word "Base64".
    # Garak demonstrates that attackers may submit:
    #
    #   <base64>
    #   What does this mean? <base64>
    #   Encoded: <base64>
    #
    # We therefore inspect plausible Base64 tokens anywhere
    # in the input.
    # -------------------------------------------------------------

    candidates = re.findall(
        r"(?<![A-Za-z0-9+/=])"
        r"([A-Za-z0-9+/]{16,}={0,2})"
        r"(?![A-Za-z0-9+/=])",
        text,
    )

    for candidate in candidates:
        try:
            padding = "=" * (-len(candidate) % 4)

            decoded_bytes = base64.b64decode(
                candidate + padding,
                validate=True,
            )

            decoded = decoded_bytes.decode(
                "utf-8",
                errors="strict",
            ).strip()

            if not decoded:
                continue

            # Avoid treating arbitrary binary-looking data as text.
            printable_chars = sum(
                char.isprintable() or char in "\r\n\t"
                for char in decoded
            )

            printable_ratio = printable_chars / len(decoded)

            if printable_ratio < 0.90:
                continue

            view = ("base64", decoded)

            if view not in seen:
                views.append(view)
                seen.add(view)

        except (ValueError, UnicodeDecodeError):
            continue

    # -------------------------------------------------------------
    # ROT13
    #
    # ROT13 has no distinctive alphabet or padding marker, so an
    # attacker does not need to write "ROT13:" in the prompt.
    #
    # Generate a transformed inspection view for textual input,
    # but do not block merely because the transformation exists.
    # assess_input() will only treat this as encoding evasion when
    # the transformed text matches an actual security detector.
    # -------------------------------------------------------------

    if re.search(r"[A-Za-z]", text):
        decoded = codecs.decode(
            text,
            "rot_13",
        )

        if decoded != text:
            view = ("rot13", decoded)

            if view not in seen:
                views.append(view)
                seen.add(view)

    return views

def assess_input(text: str, profile: str) -> SecurityDecision:
    flags: list[str] = []

    views = _decoded_input_views(text)

    for view_type, candidate_text in views:

        injection_found = any(
            re.search(
                pattern,
                candidate_text,
                re.IGNORECASE | re.DOTALL,
            )
            for pattern in INJECTION_PATTERNS
        )

        sensitive_access_found = any(
            re.search(
                pattern,
                candidate_text,
                re.IGNORECASE | re.DOTALL,
            )
            for pattern in SENSITIVE_ACCESS_PATTERNS
        )

        if (
            injection_found
            and "prompt_injection_signal" not in flags
        ):
            flags.append("prompt_injection_signal")

        if (
            sensitive_access_found
            and "sensitive_access_request_signal" not in flags
        ):
            flags.append(
            "sensitive_access_request_signal"
    )

        if (
            view_type != "raw"
            and (
                injection_found
                or sensitive_access_found
            )
            and "encoding_evasion_signal" not in flags
        ):
            flags.append(
                "encoding_evasion_signal"
            )

    profile = profile.strip().lower()

    blocked = (
        profile == "hardened"
        and any(
            flag in flags
            for flag in (
                "prompt_injection_signal",
                "sensitive_access_request_signal",
                "encoding_evasion_signal",
            )
        )
    )

    return SecurityDecision(
        flags=flags,
        blocked=blocked,
    )


def redact_output(
    text: str,
    profile: str,
) -> tuple[str, list[str], bool]:
    """
    Detect planted lab secrets in model output.

    insecure profile:
        Detect but preserve the value for controlled before-state evidence.

    hardened profile:
        Detect and redact the value before it reaches the user.
    """

    flags: list[str] = []
    redacted_text = text
    found_sensitive_output = False

    for pattern in SECRET_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            found_sensitive_output = True

            if profile.strip().lower() == "hardened":
                redacted_text = re.sub(
                    pattern,
                    "[REDACTED-LAB-SECRET]",
                    redacted_text,
                    flags=re.IGNORECASE,
                )

    if found_sensitive_output:
        flags.append("sensitive_output_signal")

    dlp_redacted = (
        found_sensitive_output
        and profile.strip().lower() == "hardened"
    )

    return redacted_text, flags, dlp_redacted


def hash_text(text: str) -> str:
    """
    Generate a SHA-256 hash for telemetry correlation without
    storing raw prompt content.
    """

    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()