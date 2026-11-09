from __future__ import annotations

import re
from dataclasses import dataclass

SCOPE_FLAG = "unsupported_internal_scope_signal"

SAFE_SCOPE_RESPONSE = (
    "I can only help with fictional Cyranta product, order, delivery, "
    "and return questions. I don't have grounded information about "
    "accounts, authentication, internal systems, demo environments, "
    "security controls, integrations, or organizational processes."
)


# These topics are explicitly outside the grounded capabilities of the lab.
# They take precedence even if a prompt also contains a supported word such
# as "product" or "order".
UNSUPPORTED_SCOPE_PATTERNS = [
    (
    r"\b(?:account|password|passcode|login|log\s*in|"
    r"sign\s*in|sign\s*out)\b"
    ),

    r"\b(?:device|browser|cookies?|local\s+storage)\b",

    r"\b(?:demo|internal|production)\b",

    (
    r"\b(?:infrastructure|security|encryption|backups?|audits?|"
    r"penetration\s+testing)\b"
    ),

    (
    r"\b(?:apis?|databases?|integrations?|external\s+partners?|"
    r"access\s+controls?)\b"
    ),

    (
    r"\b(?:data\s+handling|data\s+storage|data\s+retention|"
    r"personal\s+data|pii)\b"
    ),

    r"\b(?:our|your)\s+team\b",
]


# This is the actual application scope defined by the Cyranta system prompt.
SUPPORTED_SCOPE_PATTERNS = [
    r"\borders?\b",
    r"\bordering\b",
    r"\breturns?\b",
    r"\brefund(?:s|ed|ing)?\b",
    r"\bproducts?\b",
    r"\bitems?\b",
    r"\bshipping\b",
    r"\bdelivery\b",
    r"\btrack(?:ing)?\b",
    r"\bavailability\b",
    r"\bsiz(?:e|es|ing)\b",
    r"\bcolou?rs?\b",
    r"\bprices?\b",
    r"\bpricing\b",
]


SMALL_TALK_PATTERN = (
    r"^\s*(?:hi|hello|hey|thanks|thank\s+you|"
    r"good\s+morning|good\s+afternoon|good\s+evening)"
    r"[!. ]*$"
)


@dataclass(frozen=True)
class ScopeDecision:
    limited: bool
    flags: list[str]


def _matches_any(text: str, patterns: list[str]) -> bool:
    return any(
        re.search(
            pattern,
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        for pattern in patterns
    )


def assess_scope(text: str, profile: str) -> ScopeDecision:
    """
    Enforce Cyranta's explicitly supported application scope.

    Hardened mode uses a default-deny model:
    - known unsupported capability/internal topics are scope-limited;
    - explicitly supported retail-support topics are allowed;
    - simple greetings are allowed;
    - everything else is scope-limited.

    Insecure mode intentionally bypasses this control so before/after
    security demonstrations remain possible.
    """

    if profile != "hardened":
        return ScopeDecision(
            limited=False,
            flags=[],
        )

    if _matches_any(
        text,
        UNSUPPORTED_SCOPE_PATTERNS,
    ):
        return ScopeDecision(
            limited=True,
            flags=[SCOPE_FLAG],
        )

    if _matches_any(
        text,
        SUPPORTED_SCOPE_PATTERNS,
    ):
        return ScopeDecision(
            limited=False,
            flags=[],
        )

    if re.fullmatch(
        SMALL_TALK_PATTERN,
        text,
        flags=re.IGNORECASE,
    ):
        return ScopeDecision(
            limited=False,
            flags=[],
        )

    # Default deny: the model should not invent Cyranta-specific facts
    # merely because an unknown topic was phrased conversationally.
    return ScopeDecision(
        limited=True,
        flags=[SCOPE_FLAG],
    )