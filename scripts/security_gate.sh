#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo
echo "=== Cyranta AI Security Gate ==="
echo

echo "[1/6] Python syntax validation"
python -m compileall -q app tests redteam/pyrit rag agent monitoring governance validation

echo "[2/6] Ruff static analysis"
ruff check .

echo "[3/6] Offline workflow and governance guard"
python -m validation.project6.portfolio check

echo "[4/6] Security regression suite"
python -m pytest -q

echo "[5/6] Bandit application security scan"
bandit -q -r app rag/app agent/security agent/tools monitoring/detector.py monitoring/gateway_detection.py monitoring/dashboard.py monitoring/incident_simulation.py agent/app/hardened_agent.py governance/project5/registry.py governance/project5/control_mapping.py governance/project5/assurance_checks.py governance/project5/governance_dashboard.py validation/project6/schema.py validation/project6/runner.py validation/project6/correlation.py validation/project6/traceability.py validation/project6/portfolio.py

echo "[6/6] Core and agent dependency audit (RAG risk separately tracked)"
pip-audit -r requirements.txt
pip-audit -r requirements-agent.txt

echo
echo "CYRANTA SECURITY GATE: PASSED"
echo