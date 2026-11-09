# Cyranta Project 6.5 — Public hosted-only portfolio edition

**Research-only and unapproved for production release.** This public snapshot is
reviewed independently of the original private repository. Its Git history is
new and contains only explicitly inspected files. It must not carry over
private Actions history, self-hosted runner configuration or raw attack outputs.

## Public CI boundary

- `.github/workflows/ci.yml` is the only allowed workflow. It runs `push` on
  `main` and `pull_request` checks on GitHub-hosted Ubuntu with `contents: read`
  permissions and nonpersistent checkout credentials.
- `.github/workflows/local-redteam.yml`, `scripts/local_redteam_gate.ps1`,
  and `results/local-redteam/` must be absent from the published source tree.
- `validation/project6/portfolio.py` checks this boundary offline, rejects
  unexpected workflows and ensures `.env.example` matches an exact reviewed
  placeholder template; the check does not inspect historical GitHub settings.
- `scripts/security_gate.sh` retains compileall, Ruff, pytest, Bandit, and
  core/agent pip-audit. The ChromaDB RAG dependency remains a separately open,
  unaccepted risk, not a green audit conclusion.

The local `check` makes no GitHub API calls and does not execute a model or
an actual attack. The `build` and `verify` operations emit **unsigned** local
evidence in Git-ignored `telemetry/governance/` folders. Build refuses to
overwrite prior evidence. A clean commit and matching hashes are not an
independent attestation, release authorization, or security certification.

## Validate this public snapshot

```powershell
$py = 'C:\AI-Security\cyranta-ai-security-lab\.venv-agent\Scripts\python.exe'
& $py -m validation.project6.portfolio check
& $py -m pytest validation/project6/tests/test_portfolio.py -q
& $py -m pytest -q
& $py -m ruff check .
& $py -m bandit -q validation/project6/portfolio.py
```

Run commands from the **public candidate root** with its path on `PYTHONPATH`.
Use a clean Python environment for CI and verify the core, agent and RAG
requirements separately; local commands above are examples rather than a
record of executed tests. Do not reuse the private 667-test result as proof
that this changed public code has passed.

## Explicit limitations

- The Project 6.2 RAG tests use in-memory mocks, not live ChromaDB/Ollama.
- Project 6.3 alerts and incidents are fictional demonstrations.
- Historical findings are not independently verified or approved mappings.
- `CYRANTA-DEP-001` remains open/pending review; asset and control owners
  still need assignment.
- Actions are version-tagged rather than pinned to full commit SHAs.
- External GitHub settings, runner associations, fork policy, branch rules,
  reviewer decisions, license permissions and final public exposure are
  outside the checks in this edition.

See [Public Edition Review](docs/phase7/PUBLIC-EDITION-REVIEW.md) and
[Project 6 portfolio](docs/project6/PORTFOLIO-AND-REPRODUCIBILITY.md).
