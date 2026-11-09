# Architecture and trust boundaries

```mermaid
flowchart LR
    U[User / Red Team Tool] -->|untrusted prompt| API[FastAPI Chat Boundary]
    API --> IG[Input Risk Signals]
    IG -->|allowed| PB[Prompt Builder]
    IG -->|blocked| R[Refusal]
    PB --> O[Local Ollama Model]
    O --> OG[Output DLP / Validation]
    OG --> U
    API --> T[(JSONL Security Telemetry)]
    IG --> T
    OG --> T
    PF[Promptfoo] --> API
    G[Garak] --> O
    P[PyRIT] --> O
    T --> D[Detection Rules / Future OpenSearch]
    D --> E[Evidence Register / Risk Register]
```

## Trust boundaries

1. **User / red-team tool → API**: attacker-controlled input.
2. **API → model**: application-owned policy and prompt construction.
3. **Model → output validator**: model output is untrusted until checked.
4. **Telemetry → analyst/governance artifacts**: logs are evidence and must be privacy-minimized.
5. **CI → local model runner**: self-hosted red-team execution must never accept arbitrary public PR code.

The insecure profile intentionally plants a fake secret inside the system prompt to create measurable "before" evidence. The hardened profile removes the secret from the model context entirely and adds input/output controls.
