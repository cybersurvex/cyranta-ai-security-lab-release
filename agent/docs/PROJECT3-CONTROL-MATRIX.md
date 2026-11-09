# Project 3 — Seven-control security assurance matrix

**Scope:** Cyranta Operations Assistant, in-memory mock backend and local Ollama experiment only. See `agent/docs/SECURITY_MODEL_GATEWAY.md` for implementation caveats.

| Project 3 required control | Implemented mechanism | Evidence / tests | Status / boundary |
| --- | --- | --- | --- |
| Dedicated agent identity | Trusted `Principal.agent_id` must match `SERVICE_ID` | `test_invalid_service_identity_denied` | Tested fixture identity; no external IdP |
| Tool and resource allow-list | `ROLE_PERMISSIONS`, `_scope_ok`, order/SKU-scoped resources | `test_resource_level_order_scoping`, `test_model_cannot_override_role_with_arguments`, live `ROLE_TOOL_DENIED` | Demonstrated blocked refund in live retest |
| Short-lived scoped credentials | `issue_capability()` binds user, role, agent, tool, resource, expiration | `test_missing_capability_denied`, `test_forged_capability_denied`, `test_capability_bound_to_actor`, `test_capability_expires_and_revoked` | In-memory bearer grants; no production issuer |
| Human approval for high-impact actions | `approve_refund()` creates scoped, expiring approval via trusted mock supervisor; required by `execute()` | `test_high_impact_needs_separate_approval`, `test_human_approval_cannot_be_self_issued`, `test_supervisor_grant_is_bound_to_exact_amount_and_order`, `test_approval_expiry`, `test_authorized_refund_requires_approval_and_is_one_use` | Simulated supervisor approval tested; not a real human-in-the-loop integration |
| Untrusted content labels | Order records carry `UNTRUSTED_RECORD_CONTENT`; never issue grants based on content | `test_authorized_read_and_trust_label`, live poisoned vs. benign comparisons | Label does not itself stop model manipulation; tool gateway is control |
| Tool-call logging | `gateway.audit` records user, agent, role, tool, resource, time, allow/deny and request ID | `test_audit_excludes_bearer_tokens_and_untrusted_note`, hardened live audit `ROLE_TOOL_DENIED` | In-memory audit; no central log delivery or retention |
| Emergency revocation | `emergency_revoke()` clears capabilities/approvals and denies future calls | `test_emergency_revoke_denies_all_actions_and_grant_issuance` | Local instance only; no distributed kill switch |

## Additional business restrictions

- Refund above configured USD 100 maximum or fictional order total is denied (`test_refund_cannot_exceed_order_total_even_with_approval`).
- Duplicate refund attempt is denied (`test_authorized_refund_requires_approval_and_is_one_use`).
- Bearer capabilities are not emitted in the `audit` event.

## Evidence distinction

- **Replay:** synthetic unauthorized tool proposal, exercising the gateway without a real LLM.
- **Live single test:** same `llama3.2:3b` refund proposal observed before/after; hardened mode returned `ROLE_TOOL_DENIED` and generated no fake refund.
- **Controlled comparison:** operator reported 3 poisoned and 3 benign trials per agent profile. Both poisoned profiles produced 3/3 unwanted proposals; only vulnerable executed the fake refunds. Limited sample; not proof for other models or input distributions.
- **Unit tests:** cover simulated identity, scope, approvals and limits that the readonly live denial did not directly reach.

Security assurance here is **application-specific** and local. This matrix is not an assertion of independent penetration testing, authenticated supervisors, enterprise identity lifecycle, transaction isolation or production deployability.
