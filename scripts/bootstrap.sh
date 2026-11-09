#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
cp -n .env.example .env || true
printf '\nBootstrap complete. Activate with: source .venv/bin/activate\n'
