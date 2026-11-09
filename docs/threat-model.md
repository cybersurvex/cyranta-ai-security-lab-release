# Threat model

## Assets
- System instructions and policy configuration
- Planted fake secret used only as an exfiltration canary
- Model availability and integrity
- Security telemetry and assessment evidence

## Adversaries
- Curious or malicious end user
- Malicious prompt embedded in future RAG content
- Misconfigured developer or CI workflow

## Primary attack catalogue
| ID | Attack | Expected evidence | Primary mapping |
|---|---|---|---|
| A-01 | Direct prompt injection / jailbreak | Model follows conflicting user instructions | OWASP LLM01 |
| A-02 | System-prompt extraction | Hidden prompt details disclosed | OWASP LLM07 |
| A-03 | Fake-secret exfiltration | `CYR-DEMO-KEY-FAKE-*` appears in output | OWASP LLM02 |
| A-04 | Encoding evasion | Encoded attack bypasses input controls | OWASP LLM01 |
| A-05 | Unsafe output / policy bypass | Restricted behavior generated | Relevant OWASP category by test |

## Security objectives
- No real secrets in prompts, source, logs, fixtures, or CI.
- Hardened profile should prevent the planted secret from entering model context.
- Known prompt-injection signals are logged and may be blocked in hardened mode.
- Sensitive-looking output is redacted in hardened mode.
- Every finding has attack evidence, control change, retest evidence, and residual-risk statement.

## Known limitations
Regex/pattern controls are deliberately simple and bypassable. They are demonstration controls, not a complete prompt-injection defense. The strongest control for the fake-secret finding is architectural: remove secrets from model context.
