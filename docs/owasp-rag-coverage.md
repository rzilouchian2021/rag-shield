# OWASP RAG Security Cheat Sheet: coverage

Every recommendation in the [OWASP RAG Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html),
mapped to what RAG Shield does, where, and which test shows it. Checked on 2026-11-22.

| Mark | Meaning |
| --- | --- |
| ✅ | Built and tested |
| ◐ | Partly built; the gap is stated |
| ✗ | Not built; stated as a limitation |
| N/A | Does not apply to this system, with the reason |

Tests: `tests/test_owasp_rag.py` (red-team tests for this sheet), `tests/test_portal.py`
(policy, access, scenarios A–F), `tests/test_signoff.py`, `tests/test_shield.py`. All run in CI
(`.github/workflows/tests.yml`).

## Implementation priority (the sheet's own order)

| Tier | Item | Status |
| --- | --- | --- |
| Immediate | Provenance and integrity against a protected baseline (§1) | ✅ |
| Immediate | Context protection: delimiters, chunk limits (§3) | ✅ |
| Immediate | Access control on every chunk (§4) | ✅ (resolved from the signed registry at query time, see §4) |
| Immediate | Tenant and classification isolation (§6) | ◐ one collection, isolation inside the search |
| Immediate | Query normalization and abuse detection (§8) | ✅ |
| Immediate | Output validation and policy enforcement (§9) | ✅ |
| Immediate | Full pipeline observability and logging (§12) | ✅ |
| Immediate | Fail-closed behavior (§14) | ✅ |
| Next | Signed source attribution (§5) | ✅ |
| Next | Index integrity monitoring and access control (§7) | ✅ |
| Next | Tool invocation controls (§10) | N/A (no tools) |
| Next | Cache isolation and invalidation (§11) | N/A (no cache) |
| Next | Supply chain vetting for connectors (§13) | ◐ no connectors; versions pinned |
| Next | Deletion and retention (§4, §11) | ✅ deletion; retention N/A |
| Advanced | Embedding distribution monitoring, cross-model validation (§2) | ◐ / ✗ |
| Advanced | Embedding privacy, differential privacy (§2) | ◐ / N/A |

---

## §1 Document poisoning

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| SHA-256 of each approved document in a separately controlled manifest | ✅ | `config/kb_registry.json`; re-hashed on every question (`src/shield.py verify_provenance`). Test: `test_poisoned_documents_are_excluded_and_signed_versions_restored` |
| Manifest protected by a signature whose keys are outside the document store's write path; verify before retrieval, reject, alert | ◐ | Two-person Ed25519 signatures, keyring signed by a root key (`src/signoff.py`); failures are excluded and alerted (`document_tampered`). **Gap:** keys sit in `keys/` on the same machine and OS user as the documents (see `limitations.md`) |
| A matching hash means "unchanged", not "safe"; baseline updates authorized separately | ✅ | New or changed baselines need two approvers, one from the owning team. Signatures now also cover `allowed_roles`, `site` and `sensitivity`. Tests: `test_editing_an_access_list_breaks_the_signatures`, `test_editing_a_station_tag_breaks_the_signatures` |
| Track provenance: uploader, time, source, approval | ✅ | Registry: owner, source, upload time, signers. Uploads: uploader and size in a sealed `document_uploaded` alert. Test: `test_upload_that_is_not_text_is_rejected_and_uploader_recorded` |
| Scan for injection markers, hidden instructions, invisible characters | ✅ | Injection rules (`src/shield.py`); invisible and zero-width characters (`src/rag_controls.py hidden_characters`). Test: `test_document_with_hidden_characters_is_excluded_and_alerted` |
| Allowlist trusted sources, reject unknown ones | ◐ | Unknown sources are labelled untrusted and excluded from safety answers, but not rejected outright, so the demo can show them being caught |
| Approval workflow before new sources | ✅ | `python -m src.signoff sign` by two approvers |
| Don't ingest untrusted sources without scanning | ✅ | Every chunk is inspected before it can reach the model |
| Don't trust extension or MIME type alone | ✅ | Uploads with control characters are rejected as not text; ingestion also checks type, size, path and symlinks (`src/ingestion.py safe_path`) |
| Don't allow bulk uploads without review | ✅ | One document per upload, untrusted until signed; a sudden index jump raises `index_size_change`. Test: `test_sudden_index_growth_raises_an_alert` |
| Don't store documents without integrity verification | ✅ | Re-hash at query time |

## §2 Embedding manipulation and privacy

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Monitor embedding distribution for documents near many unrelated queries | ◐ | The retrieval-concentration monitor (`src/monitoring.py check_retrieval`) runs after every portal question and alerts when one document suddenly appears in most answers. It measures retrieval share, not embedding geometry |
| Detect drift when re-embedding moves a document | ✗ | Not built (advanced tier) |
| Cross-check with several embedding models (high security) | ✗ | Not built: one local MiniLM model |
| Log the embedding model per document; flag shifts after model updates | ◐ | The model name is part of each document's index fingerprint, so a model change re-embeds everything; it is not raised as an alert |
| Don't assume benign text gives a benign embedding | ✅ | Retrieval is never trusted; every retrieved chunk is inspected |
| Don't rely on one embedding model in high-security settings | ✗ | As above |
| Don't give untrusted users direct embedding access | ✅ | No embedding or vector endpoint exists; the server binds to 127.0.0.1 |
| Same access controls for embeddings as for documents | ✅ | Vectors are reachable only through the policy layer |
| Encrypt embeddings at rest | ✗ | Chroma files are plain on disk; relies on OS disk encryption |
| Cap similarity exposure with top-k and relevance thresholds | ✅ | 12 candidates, 4 to the model, similarity floor 0.2 (`src/policy.py MIN_SIMILARITY`). Test: `test_unrelated_question_gets_no_sources` |
| Differential privacy for medical, financial, legal data | N/A | All data is synthetic; no regulated data |
| Don't treat embeddings as irreversible | ✅ | Treated as sensitive as the text: never exposed |
| Don't expose embedding APIs publicly | ✅ | None exist |
| Don't store embeddings unencrypted in regulated environments | N/A | Not a regulated environment (see the encryption-at-rest row) |

## §3 Context window attacks

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Reinforce system instructions after retrieved content; test per model | ✅ | `build_hardened_prompt` (`src/rag_pipeline.py`) ends with a reminder; rehearsed A–F on `llama3.1:8b` on 2026-11-22. The measured evaluation keeps its original prompt |
| Wrap retrieved content in data delimiters | ✅ | `<retrieved_data>` / `<retrieved_document id=…>`; a document can't close them. Test: `test_retrieved_text_is_delimited_and_cannot_close_the_delimiter` |
| Cap chunks (3–5) and tokens (2,000–4,000) | ✅ | 4 chunks of 120 words (~650 tokens) |
| Scan chunks before inclusion | ✅ | Injection, key facts, hidden characters, index integrity |
| Add a reminder that retrieved content is data | ✅ | Same as the first row |
| Don't rely on prompt position without testing | ✅ | Rehearsed; scenario C is the per-model test |
| Don't include retrieved content without trust boundaries | ✅ | Delimiters plus trust labels |
| Don't let retrieved content fill the context | ✅ | Chunk cap |
| Don't treat retrieved content as commands | ✅ | System prompt (`SHIELDED_SYSTEM_PROMPT`) plus delimiters |

## §4 Access control inheritance, deletion and retention

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Access metadata with every chunk | ✅ (by design, differently) | Each chunk carries its document ID and file; roles, station and sensitivity are resolved from the **signed** registry on every request instead of copied into chunks, so they can't go stale or be edited in the index |
| Enforce access at retrieval time | ✅ | `src/policy.py _protected`. Test: `test_restricted_document_is_blocked_by_role_without_its_contents` |
| Isolate tenants | ✅ | Stations act as tenants: search scoped to the asked station, then checked again. Tests: `test_search_is_scoped_to_the_station_before_results_return`, `test_other_station_documents_stay_out_of_home_questions` |
| Log each retrieval with identity and access metadata | ✅ | Audit entry: user, role, home station, every source with status and reason |
| Re-evaluate when source permissions change | ✅ | Registry read per request; an unsigned edit makes the document readable by nobody |
| Don't strip access metadata in chunking | ✅ | See the first row |
| Don't assume document permissions carry to chunks | ✅ | Checked per chunk |
| Don't share a store across tenants without per-chunk checks | ✅ | Per-chunk checks inside and after the search |
| Don't let the model enforce access | ✅ | Restricted text never reaches it; 8-word leak check on answers |
| Remove deleted content from stores, caches and indexes | ✅ | Sync deletes the document's chunks; there is no cache. Test: `test_deleted_source_leaves_no_searchable_chunks` |
| Cascade deletion | ✅ | Chunks and embeddings; no cached responses exist |
| Keep a deletion log | ✅ | `index_change` events (with `removed`) in the sealed log |
| Audit for orphaned chunks | ✅ | `/api/integrity`, shown on the console's Integrity panel |
| Retention periods | N/A | Demo data has no retention rule; production would need one |

## §5 Source attribution

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Return attribution with every response | ✅ | Sources used, excluded and removed, with request ID |
| Sign attribution | ✅ | HMAC-SHA256 seal (`src/rag_controls.py seal_attribution`) |
| Include document hashes | ✅ | SHA-256 of each source file version used, plus the answer hash |
| Verification endpoint | ✅ | `POST /api/verify-attribution`. Test: `test_attribution_is_signed_and_tampering_is_detected` |
| Don't return responses without sources | ✅ | Every protected answer carries them |
| Don't let attribution change after generation | ✅ | Any change breaks the seal (same test) |
| Don't trust upstream attribution unverified | N/A | No upstream system supplies attribution |

## §6 Chunk isolation

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Separate namespaces or collections per tenant or classification | ◐ | One collection; isolation is a document-ID filter inside the search. Separate collections are a production step |
| Enforce boundaries before the search returns results | ✅ | Chroma `where` filter on in-scope documents |
| Regular cross-tenant test queries, zero leaks expected | ✅ | Station tests in CI |
| Per-tenant encryption keys | ✗ | Not built |
| Don't use one flat namespace | ◐ | As the first row |
| Don't rely only on post-retrieval filtering | ✅ | Filter inside and after the search |
| Don't reuse tenant-adapted embedding models | N/A | One off-the-shelf model, no fine-tuning |

## §7 Index integrity

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Verify index integrity with checksums | ✅ | Each retrieved chunk must equal the chunk re-derived from the verified file. Test: `test_chunk_edited_inside_the_vector_database_is_not_used` |
| Only the ingestion pipeline writes the index | ✅ | Only `RAGPipeline.sync` writes; no write endpoint |
| Log inserts, updates, deletes with time and identity | ◐ | `index_change` events are timestamped; the writer is always the service, and uploads record the uploader |
| Snapshots for rollback | ✅ | The index is rebuilt from signed documents (Reset, `--rebuild`); signed copies restore documents |
| Alert on unexpected size changes | ✅ | `index_size_change` |
| Authentication, network isolation, strong credentials | ◐ | Chroma is embedded (no network listener); the portal listens on 127.0.0.1 only. The portal has no login (identity is simulated) |
| Don't give application code or agents index write access | ✅ | |
| Don't deploy with default or no credentials | ◐ | No database credentials exist (embedded); see the portal login gap |
| Don't assume internal databases need no controls | ✅ | Integrity checks above |
| Don't skip monitoring because it's "only embeddings" | ✅ | Integrity panel and alerts |

## §8 Query injection via retrieval

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Normalize and inspect queries; access control independent | ✅ | NFKC, invisible characters stripped and flagged, injection patterns flagged; access rules unchanged. Tests: `test_question_is_normalized_and_flagged`, `test_injection_in_the_question_is_flagged_and_repeats_alert` |
| Rate limit per user | ✅ | 12 questions per minute; HTTP 429. Test: `test_rate_limit_per_user` |
| Monitor reconnaissance | ◐ | `possible_reconnaissance` after 3 restricted or verification hits in 10 minutes. Systematic term variation is not detected beyond that |
| Log query IDs and identity, not content | ✅ | Question hash only. Test: `test_audit_entry_has_model_station_and_attribution` |
| Don't pass raw input to search | ✅ | Normalized first |
| Don't allow unlimited queries | ✅ | Rate limit |
| Don't return similarity scores | ✅ | Not in the technician view. Test: `test_technician_view_has_no_similarity_scores` |

## §9 Output validation

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Validate outputs before release | ✅ | Approved citation, key facts, injection, restricted text, live data |
| Detect and redact PII, secrets, regulated data | ✅ | Private keys, access keys, tokens, passwords, SSNs, card numbers (Luhn); operational numbers kept. Tests: `test_secrets_and_identifiers_are_removed_from_answers`, `test_redaction_keeps_operational_numbers` |
| Validate tool calls against allowlists | N/A | No tools |
| Structured outputs with schema validation in automated workflows | N/A | Answers go to people, not automation |
| Redact by the user's access level | ✅ | Restricted text check and role filter |
| Don't execute model output | ✅ | Inserted as text only, never as HTML or code |
| Don't trust the model for policy | ✅ | All decisions are fixed rules |
| Don't return unvalidated output in high-risk workflows | ✅ | Every protected answer is validated |
| Don't assume safe inputs mean safe outputs | ✅ | The answer is checked separately (step 7) |

## §10 Tool invocation and agent safety

**N/A by design.** The assistant answers questions; it has no tools, cannot call APIs, open
valves or send messages. Not giving the model tools is itself the strongest control here. If
tools were added, the sheet's rules would apply: confirmation for high-risk actions,
authorization independent of the model, per-context allowlists, full tracing, circuit breakers.

## §11 Caching

**N/A.** No responses are cached; every question is answered fresh, so there is nothing to
leak across users or to serve after a permission change. If a cache were added it would need
per-user, per-tenant and per-permission scope, invalidation on source changes, and TTLs.

## §12 Monitoring and incident response

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Trace with correlation IDs, document IDs, authorization decisions, model version | ✅ | Request ID shared by technician view, console and audit log; sources; decision; model |
| Don't log raw queries or content by default | ✅ | |
| Restricted evidence store if content capture is needed | N/A | No content is captured |
| Alert: retrieval from collections a user never accessed | ✅ | `break_glass_access` when another station's documents are used |
| Alert: repeated prompt injection attempts | ✅ | `repeated_injection_attempts` |
| Alert: attempts to retrieve restricted chunks | ✅ | Each block is logged; `possible_reconnaissance` on repeats. Test: `test_repeated_restricted_attempts_raise_a_reconnaissance_alert` |
| Alert: sudden retrieval distribution shift | ◐ | Retrieval-concentration monitor |
| CI test: poisoned document retrieval | ✅ | Scenario B tests |
| CI test: indirect injection overriding the system prompt | ✅ | Scenario C tests |
| CI test: cross-tenant retrieval | ✅ | Station tests |
| CI test: stale permissions | ✅ | Registry edits take effect on the next request |
| CI test: cache leakage | N/A | No cache |
| CI test: unauthorized tool invocation | N/A | No tools |
| CI test: attribution tampering | ✅ | Attribution test |
| CI test: chunks left after deletion | ✅ | Deletion test |
| RAG incident response: quarantine, invalidate caches, find who received tainted answers | ✅ | Automatic quarantine; no cache; `python -m src.incident affected DOC-ID`. Runbook: `docs/incident-response.md`. Test: `test_incident_helper_lists_who_received_a_document` |
| Don't treat RAG as a black box / investigate from model output alone / skip testing | ✅ | |

The audit log is HMAC-chained; the console's Integrity panel shows whether it verifies, and the
presenter's "Tamper with audit log" button demonstrates detection
(`test_rewriting_a_logged_decision_is_detected`).

## §13 Supply chain risk in ingestion

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Vet third-party connectors | N/A | No connectors: local files and portal uploads only |
| Validate external data before ingestion | ◐ | Uploads: text-only, size limit, uploader logged. Injection and hidden-character scans run at query time, before content can reach the model, rather than at upload |
| Pin embedding model and library versions | ◐ | Libraries pinned in `requirements.txt`; the embedding model is pinned by name, not by revision hash |
| Inventory of sources, credentials, schedules, owners | ✅ | Below |
| Don't trust integrations implicitly / auto-sync without staging / over-permission connectors | ◐ | Uploads are indexed immediately but labelled untrusted (the staging state); no connectors exist |

### Inventory

| Item | Where | Owner | Protection |
| --- | --- | --- | --- |
| Approved procedures | `data/kb/approved/` | Owning team per registry entry | Two-person signatures |
| Shared uploads | `data/kb/untrusted/` (portal copy) | Uploader (logged) | Untrusted; excluded from safety answers |
| Live sensor snapshot | `data/kb/live/sensors.json` | Simulated historian | Missing or invalid data warns |
| Signed registry | `config/kb_registry.json` | Document control | Signatures cover hash, version, roles, station, sensitivity |
| Approver keyring | `config/approvers.json` | Root key holder | Root signature, pinned root key |
| Approver and root private keys | `keys/*.pem` (git-ignored) | Each approver (demo: shared) | Encrypted (PBKDF2 + AES-256) |
| Audit-log key | `keys/log_hmac.key` (git-ignored) | Security team | File permissions only |
| Key passphrase, demo PIN | `.env` (git-ignored) | Presenter | Never committed; PIN kept only as a salted scrypt hash in memory |
| Sync schedule | On demand (startup, upload, toggles, quarantine) | Service | Logged as `index_change` |

## §14 Fail-closed design

| Recommendation | Status | How, and the test |
| --- | --- | --- |
| Retrieval fails: don't answer from model memory | ✅ | No verified source means no answer; any error blocks |
| Access check fails: return nothing | ✅ | Corrupt registry blocks; missing roles list or broken signatures means nobody. Tests: `test_corrupt_registry_fails_closed`, `test_registered_document_without_an_access_list_is_denied` |
| Attribution cannot be generated: block | ✅ | Attribution is a named stage; a failure blocks |
| Hash verification fails: exclude and alert | ✅ | |
| Cache lookup fails: answer fresh | N/A | No cache |
| Apply at every stage | ✅ | One catch-all in `Policy.handle` |
| Errors identify the failed stage | ✅ | "A safety check (source inspection) could not finish…", no internals. Test: `test_failure_names_the_stage_and_repeats_alert` |
| Alert on repeated failures | ✅ | `repeated_failures` |
| Don't fall back to model-only answers | ✅ | |
| Don't degrade silently | ✅ | Shield-off is labelled on every answer; step-up unavailable says so |
| Don't treat failures as performance issues | ✅ | Logged as security events |
