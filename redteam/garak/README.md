# Garak track

Garak is kept in its own Python environment because its dependency graph is large and changes independently from the app.

Recommended local setup:

```bash
python3 -m venv .venv-garak
source .venv-garak/bin/activate
python -m pip install -U pip garak
garak --list_probes
```

Start with a local Ollama generator after checking the installed version's generator names:

```bash
garak --list_generators | grep -i ollama
```

Then run a small, reproducible subset such as the prompt-injection and encoding families. Save the generated JSONL/hit logs under `results/garak/` and record the exact garak version and command in the finding.

Do not run every probe by default on a laptop. Begin with low generations and expand intentionally.
