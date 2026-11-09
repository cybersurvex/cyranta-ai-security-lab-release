# CYR-AGENT-001 — Evidence add-on

This overlay adds **new files only** to the existing Cyranta Project 3 repository:

- `agent/findings/CYR-AGENT-001-CONTROL-VALIDATION.md` — security finding based on actual user-provided before/after output (does not invent benign-control results).
- `agent/attacks/run_counterfactual.ps1` — optional paired local Ollama comparisons (poisoned vs. benign, vulnerable vs. hardened), default three trials per scenario.

## Install

Extract the ZIP at the repository root on **`project3-secure-agent`**. It does not replace prior code. Use a clean or backed-up worktree and review extracted files before committing.

```powershell
cd C:\AI-Security\cyranta-ai-security-lab
$zip = "$env:USERPROFILE\Downloads\cyranta-project3-evidence-addon.zip"
Expand-Archive -LiteralPath $zip -DestinationPath . -Force
```

## Verify gateway tests and run counterfactual

```powershell
python -m pytest .\agent\tests -q
Set-ExecutionPolicy -Scope Process Bypass
.\agent\attacks\run_counterfactual.ps1 -Iterations 3 -Model llama3.2:3b
```

The script performs **12 local-model requests** (four scenarios × three trials). It is deliberately slow on a laptop; use `-Iterations 1` for a smoke check. The vulnerable path may execute only **simulated** tool actions. Read the outputs in `agent/results/local/CYR-AGENT-001-counterfactual-*/`.

A benign-note comparison is evidence about the *effect of the injected text*. The successfully blocked live test is already evidence for the *authorization boundary*. They answer different questions.

## Validate separate approval/limit/revocation tests

```powershell
python -m pytest .\agent\tests\test_tool_gateway.py -q
```

These unit tests exercise supervisor approval, capability scopes/TTL, refund limits, duplicate refund denial, revocation and audit sanitization without relying on a stochastic model proposal. Review test source and the in-process fixture limitations before asserting coverage.

## Git hygiene

```powershell
git status --short
git check-ignore .venv-agent/ agent/results/local/
git add README-EVIDENCE-CYR-AGENT-001.md agent/findings/CYR-AGENT-001-CONTROL-VALIDATION.md agent/attacks/run_counterfactual.ps1
git diff --cached --check
git diff --cached --stat
```

Do not add model logs/raw JSON to the public repository without a separate review and sanitization step. All actions remain simulated and local; no real payments are processed.
