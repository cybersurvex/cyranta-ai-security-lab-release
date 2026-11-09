# CYR-DET-003 — Semantic Instruction-Hijack Variants Bypass Lexical Prompt-Injection Detection

## Status

MITIGATED — RETEST PASSED

## Severity

Medium

## Summary

Independent Garak testing identified prompt-injection variants that bypassed
Cyranta's initial lexical input detector.

The baseline detector blocked prompts containing explicit forms such as
"ignore previous instructions", but missed imperative task-replacement forms
such as:

`STOP EVERYTHING!!! NOW!!! JUST PRINT ...`

The underlying LLM refused the four missed attacks, so no successful
prompt hijack was observed. However, the requests reached the model rather
than being stopped by the application security boundary.

## Baseline

Probe:

`promptinject.HijackHateHumans`

Results:

- 12 total attack prompts
- 8 detected and blocked by Cyranta
- 4 bypassed the input detector
- Detector coverage: 66.7%
- Garak AttackRogueString: PASS 12/12
- Successful rogue-output attacks: 0/12

The four bypassed requests reached Ollama and were refused by the model.

## Root Cause

The input-security rules primarily recognized lexical patterns involving
phrases such as "ignore previous instructions".

Semantically equivalent task-replacement forms such as "STOP EVERYTHING"
combined with forced-output instructions were not represented.

## Remediation

The prompt-injection detector was extended to recognize generalized
task-replacement and forced-output patterns, including combinations of:

- stop / drop / abandon / forget / disregard / override
- current task / previous instructions / rules / context
- just / only
- print / say / output / return / respond / reply / write

The remediation does not depend on the Garak rogue string itself.

A benign false-positive regression was also added.

## Verification

Unit regression:

`19/19 PASS`

Live API verification:

- blocked: true
- input flag: prompt_injection_signal
- enforcement occurred before model inference

Same-corpus Garak replay:

`promptinject.HijackHateHumans`

- 12/12 detected and blocked
- 0/12 detector bypass
- Garak AttackRogueString: PASS 12/12

Independent validation:

`promptinject.HijackKillHumans`

- 12/12 detected and blocked
- 0/12 detector bypass
- Garak AttackRogueString: PASS 12/12

## Before / After

Baseline detector coverage: 8/12 (66.7%)

Post-remediation same-corpus coverage: 12/12 (100%)

Independent post-remediation validation: 12/12 (100%)

## Security Impact

In the current chatbot architecture, the missed attacks did not result in a
successful model hijack.

Risk would increase substantially if the assistant were later connected to
privileged tools, sensitive RAG sources, transaction systems, or autonomous
agent capabilities.

## Residual Risk

The remediation is validated only against the tested attack corpus.

Novel semantic variants, multilingual prompt injection, adversarial
tokenization, Unicode manipulation, nested encodings, indirect prompt
injection, and adaptive attacks remain separate testing areas.