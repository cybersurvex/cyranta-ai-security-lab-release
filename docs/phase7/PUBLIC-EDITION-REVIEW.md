# Cyranta Public Edition — Independent Disclosure Review

This is a **public hosted-only** candidate with a fresh history. It is not the
original private repository and does not carry its earlier CI logs, runner
metadata or local generated attack evidence.

## Scope reviewed by the offline policy guard

- Exactly one GitHub workflow: `.github/workflows/ci.yml`, running only on
  GitHub-hosted Ubuntu and using read-only content permissions.
- No `.github/workflows/local-redteam.yml`, no `scripts/local_redteam_gate.ps1`
  and no `results/local-redteam/` in this candidate.
- The `.env.example` content matches fixed, obviously nonproduction placeholders.
- The open `CYRANTA-DEP-001` risk remains pending review, with no assurance
  that live ChromaDB/Ollama integration is secure.
- Test fixtures, alerts, scenarios and finding documents remain fictional.

## Human review required before initial publication

1. Audit every candidate path for personal data, IP, third-party materials,
   credentials, and references to private host infrastructure.
2. Independently run `gitleaks dir` against the **entire candidate directory**.
   Do not copy `.git`, private `.env`, virtual environments, raw telemetry or
   evidence. Do not assume a scanner finding of zero is proof of safety.
3. Re-run the complete unit suite, Ruff, Bandit and hosted CI for this edition.
   The private repo's 667 passing cases cannot substitute for new tests.
4. Confirm the new repository's Actions permissions and absence of self-hosted
   runners, environment secrets, repository-level secrets and unsafe webhooks.
5. Review the LICENSE and all third-party dependency/license obligations.
6. Resolve or explicitly disclose remaining dependency/governance limitations;
   do not claim compliance certification or production security assurance.
7. Obtain an independent human publication decision before creating or making
   the new repository public.

## Historical provenance and test boundaries

Private Project 6.5 merge SHA: `e9d401264d3ab36da37996059d89ab48405268e8`.
The private verification had 667 passing local tests and successful matching
`security-gate` GitHub CI. This public edition intentionally changes a workflow
and its validator; its test and scan results must be gathered afresh.

Avoid importing any private repository Git history or GitHub Actions artifacts.
No publication authorization is recorded by this document or code.
