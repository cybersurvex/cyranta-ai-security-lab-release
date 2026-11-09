# Cyranta Project 3 — CYR-AGENT-001 evidence refresh

This overlay **updates documentation only**. It does not alter any agent application, tool gateway, tests, or attack scripts.

The four updated findings and one curated JSON evidence summary supersede "pending live" / "pending benign control" wording from earlier scaffold docs.

## Installation (PowerShell; repository root)

First confirm `git branch --show-current` is `project3-secure-agent`. Preserve a copy of changed finding files if you have manually edited them since the last ZIP.

```powershell
$zip = "$env:USERPROFILE\Downloads\cyranta-project3-validation-closure.zip"
Expand-Archive -LiteralPath $zip -DestinationPath . -Force
```

## Include all gateway source files in the commit

The user's previous staged-stat listing omitted the security gateway. Assuming you have the previously supplied gateway add-on extracted, stage these paths explicitly:

```powershell
git add -- README-PROJECT3-GATEWAY.md agent/app/hardened_agent.py agent/security agent/tests/test_tool_gateway.py agent/attacks/benign_order_note.txt agent/docs/SECURITY_MODEL_GATEWAY.md agent/findings/CYR-AGENT-001-LIVE-EVIDENCE.md agent/findings/CYR-AGENT-001-RETEST.md
```

Then stage the refreshed documents:

```powershell
git add -- README-VALIDATION-CLOSURE.md agent/findings/CYR-AGENT-001.md agent/findings/CYR-AGENT-001-CONTROL-VALIDATION.md agent/findings/CYR-AGENT-001-COUNTERFACTUAL-SUMMARY.json
```

Check that Python environments and raw evidence are still ignored before the commit:

```powershell
git check-ignore .venv-agent/ agent/results/local/
python -m pytest .\agent\tests -q
git diff --cached --check
git diff --cached --stat
git status --short
```

If `git diff --cached --check` finds whitespace in any other staged files, fix those source files and stage them again. Do not disable whitespace checking.

Only after reviewing the staged paths and ensuring you are not on the frozen Project 2 branch, you may commit with a message such as:

```powershell
git commit -m "feat(agent): validate least-privilege gateway and document CYR-AGENT-001"
```

Do not publish `agent/results/local/` unreviewed. Do not claim enterprise authn, transaction safety, or full coverage outside this isolated local model and test fixture.
