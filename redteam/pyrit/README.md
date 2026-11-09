# PyRIT track

PyRIT is the deeper orchestration/scoring layer. Keep it separate from the application virtual environment.

```bash
python3 -m venv .venv-pyrit
source .venv-pyrit/bin/activate
python -m pip install -U pip pyrit
mkdir -p ~/.pyrit
```

For a local Ollama endpoint, configure PyRIT's OpenAI-compatible target with:

```text
OPENAI_CHAT_ENDPOINT=http://127.0.0.1:11434/v1
OPENAI_CHAT_KEY=ollama
OPENAI_CHAT_MODEL=<your-local-model>
```

Use SQLite memory for durable local evidence and build a small scenario around the planted fake secret, refusal scoring, and converters. Commit scenario code, never local env files or databases containing sensitive material.
