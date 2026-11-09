# Windows 10 Laptop Deployment Profile

This profile is designed for a Windows 10 Pro laptop with an Intel Core i7-7700HQ, 32 GB RAM, and an NVIDIA GTX 1060 6 GB.

## Recommended topology

- **Windows host:** Ollama + NVIDIA driver + VS Code/Git.
- **Native PowerShell:** FastAPI app, unit tests, and Promptfoo are supported and easiest for the first milestone.
- **WSL2 Ubuntu:** recommended later for Garak because Garak is primarily developed/tested on Linux/macOS and has a heavier Python/ML dependency tree.
- **Separate virtual environments:** app, Garak, and PyRIT must not share one Python environment.

## Resource guardrails

- Start with `llama3.2:3b`.
- Keep Ollama model concurrency at one while establishing the baseline.
- Do not run Promptfoo, Garak, and PyRIT simultaneously.
- Close browsers/IDEs with large memory footprints before long scans.
- Keep at least 25–30 GB free disk for models, Python environments, Node cache, logs, and result artifacts.
- Keep raw prompt/response logging disabled unless the content is entirely fictional.

## Phase 1 topology

```text
PowerShell / Promptfoo / FastAPI
            |
            | HTTP localhost:8000
            v
      Cyranta AI App
            |
            | HTTP localhost:11434
            v
      Ollama on Windows
            |
            v
      GTX 1060 6 GB
```

## Phase 2 topology

```text
Windows 10 Host
  |- Ollama (GPU inference)
  |- FastAPI / Promptfoo (PowerShell)
  `- WSL2 Ubuntu
       |- Garak environment
       `- PyRIT environment (optional; native Windows also works)
```

The lab is intentionally local-first. Use only fictional Cyranta data and planted fake secrets.
