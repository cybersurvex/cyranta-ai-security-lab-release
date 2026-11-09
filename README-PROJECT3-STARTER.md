# Cyranta AI Security Lab — Project 3 Starter

**Based on the Project 2 freeze:** `v0.10.0-rag-authority-ranking` (as reported by project owner).

**Branch:** `project3-secure-agent`

**Current milestone:** Vulnerable *simulated* tool executor with `CYR-AGENT-001` finding candidate. **No hardened gateway yet.**

This is an **add-on** for your existing Cyranta repository, not a replacement. Keep your existing Project 1/2 files and `.env` unchanged.

## Before extracting

Open PowerShell in your repository (`C:\AI-Security\cyranta-ai-security-lab`). Confirm that your work is clean and the expected tag exists:

```powershell
git status --short
git tag --list v0.10.0-rag-authority-ranking
git branch --show-current
```

If you are still on the frozen Project 2 branch, create the new branch (do not repeat if it already exists):

```powershell
git switch -c project3-secure-agent
```

If the branch already exists, use `git switch project3-secure-agent` instead.

Extract the starter ZIP from your repository root. If you've already made Project 3 files, **review before overwriting**.

```powershell
Expand-Archive -Path .\cyranta-project3-secure-agent-starter.zip -DestinationPath . -Force
```

> The ZIP contains the `agent/` directory, `requirements-agent.txt`, and this README. It doesn't contain a `.env` or modify Project 2.

## Dedicated agent Python environment

```powershell
# If an earlier virtualenv is active, run: deactivate
py -3.11 -m venv .venv-agent
.\.venv-agent\Scripts\Activate.ps1
python -m pip install -r .\requirements-agent.txt
```

Add the environment to your existing `.gitignore` **once**:

```powershell
if (-not (Select-String -Path .\.gitignore -Pattern '^\.venv-agent/$' -Quiet)) {
    Add-Content .\.gitignore '.venv-agent/'
}
git check-ignore .venv-agent/
```

## 1. Run unit tests

```powershell
python -m pytest agent\tests -q
```

## 2. Deterministic vulnerable replay (requires no Ollama)

```powershell
python -m agent.app.vulnerable_agent --mode replay
```

Expected fields (actual JSON includes more):

```json
{
  "proposal_source": "synthetic_fixture_not_llm_output",
  "authorization_enforced": false,
  "human_approval_enforced": false,
  "simulated_refund_executed": true
}
```

**Interpretation:** A *synthetic* model-proposed refund action can execute with no application authorization. This proves the unsafe tool-execution boundary, not that your local LLM was attacked successfully.

## 3. Optional real Ollama attack (on your laptop)

Confirm Ollama is running locally and has `llama3.2:3b`. Then:

```powershell
python -m agent.app.vulnerable_agent --mode ollama --model llama3.2:3b
```

This sends the fictional, attacker-controlled order note to your **local** model through `http://127.0.0.1:11434/api/chat`. Only a genuine structured model `issue_refund` call followed by a simulated refund counts as a live indirect prompt-injection exploit. Otherwise, record a failed attempt and keep the baseline vulnerability finding separate.

To capture a local evidence copy (review before sharing):

```powershell
New-Item -ItemType Directory -Force .\agent\results\local | Out-Null
python -m agent.app.vulnerable_agent --mode replay |
    Tee-Object -FilePath .\agent\results\local\CYR-AGENT-001-replay.json
```

Do not commit `agent/results/local/`: these are raw local execution artifacts. If you want to publish them later, sanitize and move reviewed artifacts into a tracked evidence folder.

## Folder contents

```text
agent/
├── app/
│   └── vulnerable_agent.py
├── tools/
│   └── mock_tools.py
├── attacks/
│   ├── poisoned_order_note.txt
│   └── replayed_model_call.json
├── tests/
│   └── test_vulnerable_agent.py
├── findings/
├── results/
└── docs/
    └── SECURITY_MODEL.md
requirements-agent.txt
```

## Before your first commit

```powershell
git status --short
python -m pytest agent\tests -q
git diff --check
```

**Next milestone:** Build the application-owned tool gateway, deny unauthorized access at the execution boundary, require a separately validated human approval for high-impact actions, and perform the exact replay on the hardened path.
