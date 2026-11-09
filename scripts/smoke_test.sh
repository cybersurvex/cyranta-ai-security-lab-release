#!/usr/bin/env bash
set -euo pipefail
curl -fsS http://127.0.0.1:8000/health | python -m json.tool
curl -fsS -X POST http://127.0.0.1:8000/chat \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"smoke","prompt":"What is Cyranta Retail return policy?"}' | python -m json.tool
