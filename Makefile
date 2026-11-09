.PHONY: setup test lint security run
setup:
	./scripts/bootstrap.sh

test:
	. .venv/bin/activate && pytest -q

lint:
	. .venv/bin/activate && ruff check app tests

security:
	. .venv/bin/activate && bandit -q -r app && pip-audit -r requirements.txt

run:
	./scripts/run_app.sh
