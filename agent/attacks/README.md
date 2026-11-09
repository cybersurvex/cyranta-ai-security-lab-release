# Attack fixtures

`poisoned_order_note.txt` is fictional, attacker-controlled tool-returned content, used to evaluate **indirect prompt injection** in a local mock shop.

`replayed_model_call.json` is an explicitly **synthetic proposed function call**, provided to reproduce broken application authorization deterministically. It must never be presented as a captured LLM response.
