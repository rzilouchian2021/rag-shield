# Existing system audit

Date: 2026-11-20. Branch audited: `employee-portal-demo` (= `main` plus the portal and signed-copy recovery).
Scope: everything in the repo, checked against the Monday demo brief (scenarios A to E, shared backend, console).

## 1. Stack

| Layer | What is used |
| --- | --- |
| Language | Python 3.11 (about 5,100 lines across `src/`, `portal/`, `evaluation/`, `demo/`, `config/`, `app.py`); vanilla JavaScript, HTML and CSS for the portal |
| Interface A (technician-facing) | `portal/`: a fictional Williams employee portal. Python standard-library HTTP server (`portal/server.py`) plus static JS. Listens on 127.0.0.1:8600 |
| Interface B (security/admin) | `app.py`: Streamlit 1.66 dashboard (Demo, Evaluation, Watch, Ask, Documents, Quarantine, Review verdicts). Port 8501 |
| LLM | Ollama, `llama3.1:8b`, temperature 0, seed 42 (`src/llm_client.py`). An Anthropic client exists but has only been tested with mocks |
| Embeddings | `sentence-transformers/all-MiniLM-L6-v2` on CPU |
| Vector store | ChromaDB 1.5.9 (persistent, local, `storage/`) |
| Database | None. State is JSON files (`config/document_registry.json`, `config/approvers.json`, quarantine `manifest.json`) and an append-only JSONL audit log (`logs/events.jsonl`) |
| Crypto | `cryptography` 50.0.2 (Ed25519 signatures), `hashlib` SHA-256, `hmac` for the sealed log |
| Tests | pytest, 304 passing (16 test files) |

## 2. What works end to end (verified by tests or live runs in this project)

- **RAG pipeline**: ingestion (TXT, MD, PDF; rejects symlinks, other types, files over 10 MB), chunking, embeddings, Chroma retrieval, generation with `[DOC-xxx]` citations.
- **RAG Shield** (`src/shield.py`, frozen since the evaluation): provenance re-hash at query time; trust labels (`approved`, `hash_mismatch`, `unapproved`, `untrusted`); rule-based injection detection over the whole file; fact-conflict check against `config/authoritative_facts.json`; withhold on high-impact questions without approved evidence; answer check (must cite an approved source, must not contradict a key fact); quarantine.
- **Signed two-person sign-off** (`src/signoff.py`): Ed25519 signatures from two approvers, one from the owning team, against a keyring signed by a root key. Fails closed if the keyring or root is missing or altered. Validated against 8 approval attacks (`docs/phase8_signoff.md`).
- **Tamper-evident audit log** (`src/logging_utils.py`): every entry sealed with a chained HMAC-SHA256 plus a head file; 6 tampering attacks detected in validation. The log stores a hash of the question, not its text.
- **Watch stage** (`src/monitoring.py`): integrity scan, alerts, retrieval-concentration monitor, purge and retest, governance metrics, and optional signed-copy recovery.
- **Evaluation**: Baseline vs Shield on 40 unapproved poison/injection attacks (15/40 vs 0/40 clear successes), approved-poison limits, ablations, FAIR export.
- **Interface A live demo**: fake-bulletin upload and per-question insider edits (notification time, W-217, assembly point, daily rounds); Shield off gives the wrong answer, Shield on gives the right one, with conflicts, quarantine and signed-copy restore shown per question. Rehearsed repeatedly through the API and in Chrome.

## 3. Mocked, hard-coded, or simulated

- **All data is synthetic** ("Station 41", a compressor station). The portal is labeled as a fictional simulation, not affiliated with Williams.
- **Approver keys**: all private keys sit encrypted in one local `keys/` folder with one shared demo passphrase.
- **Signed archive**: the portal uses the project's own `data/` folder as the "protected archive" of signed versions.
- **Attacks are scripted**: fixed text replacements (`portal/server.py`, `SCENARIOS`) and fixed attack files in `data/attack_library/`.
- **The presenter-only "Reveal"** checks answers only against the key-facts list, not general correctness.
- **Users**: the portal hard-codes one user (Jordan Reyes, Field Technician). There is no login and no role.

## 4. Broken, incomplete, or missing against the brief

| Brief requirement | Today | Gap |
| --- | --- | --- |
| Gas-leak knowledge base: emergency procedure, **valve map / isolation valve list**, **evacuation routes**, **sensor readings** (methane ppm, pressure, wind), **work orders** | Six compressor-station procedures. One emergency procedure with an assembly point. No valve map, evacuation routes, sensor data, or work-order records | New KB needed (`data/kb/`) |
| A. Normal | Works (current KB) | Needs the gas-leak KB and questions |
| B. Poisoned document (wrong valve, route into the wind), detected by integrity/provenance | Works for current procedures via hash plus two-person signatures; signals are hash and signatures, not keywords | Needs the new KB signed, plus "unapproved author / unexpected recent edit" surfaced in the explanation |
| C. Prompt injection in a work order, stripped or blocked | Detected (rules) and the document is excluded and quarantined; no partial stripping | **Redact** (strip the injected lines, keep the rest) not implemented |
| D. Conflict with live sensor data (route downwind of the leak) | **Not implemented**: no sensor data and no live-data check | New deterministic check needed |
| E. Unauthorized access by role | **Not implemented**: no users, roles or document ACLs | New deterministic authorization step needed |
| Decision: allow / warn / redact / block, with category and plain-English explanation | Statuses are `answered` / `withheld`; reasons exist per document but there is no single decision or category | New policy layer needed |
| Same request ID in both views | `query_id` is generated and logged; the dashboard shows it; the portal does not | Portal must show it, and the console must read the portal's log |
| **Both interfaces share a backend** | **Same code, not the same running state.** Both call `RAGPipeline`/`Shield`, but the portal runs its own process on a disposable copy (`storage/portal/`) with its own audit log, while the dashboard uses `data/` and `logs/events.jsonl`. A question asked in the portal never appears in the dashboard | Must be fixed for the console requirement |
| Console showing every query (user, role, category, sources excluded and why, decision, explanation, audit entry) | The dashboard has Watch (alerts) and an Ask page log table, but no per-query security console | New console view needed |
| Fail closed | Signature and keyring problems fail closed. A missing registry entry means `untrusted`. Unverified answers to safety questions are withheld | **Not verified**: what happens if the inspection code raises. Error messages can leak internals (for example, a corrupt registry error includes the full file path, and LLM errors are echoed to the user) |
| Secrets | `.env` and `keys/` are git-ignored; `.env.example` exists | `.env.example` lacks `RAG_SHIELD_KEY_PASSPHRASE` and `RAG_SHIELD_LOG_KEY` |
| Latency, benchmark with precision/recall/F1 | Latency is recorded per query; the evaluation reports attack success and detection, not a labeled TP/FP/TN/FN benchmark | For the tester to build and run |

**Constraint to respect.** `src/shield.py` and `config/authoritative_facts.json` are frozen: the reported evaluation numbers (15/40 vs 0/40) depend on them. New behavior should wrap the Shield rather than change those files, and the new KB should live beside the existing `data/` rather than replace it.

## 5. Recommendation per component

| Component | Recommendation | Why |
| --- | --- | --- |
| Ingestion, chunking, embeddings, Chroma, retriever | **Keep** | Work and are tested; parameterized by `Settings`, so a second KB is a configuration change |
| `src/shield.py` (frozen inspection rules) | **Keep unchanged**, wrap it | Preserves the evaluation results |
| `src/signoff.py`, sealed log, Watch, recovery | **Keep** | Provide the integrity and provenance signals scenario B needs; the log is the audit trail |
| Decision layer (allow / warn / redact / block, category, explanation) | **Add** `src/policy.py`, deterministic, wrapping the Shield | Brief requires one explicit decision per request |
| Authorization (roles, document ACLs) | **Add** to the same policy layer, before retrieval results are used | Scenario E; must be deterministic and ignore any metadata inside documents |
| Live-data conflict check | **Add** a deterministic rule over structured sensor readings (wind direction vs route bearing, valve ID vs map) | Scenario D |
| Injection redaction | **Add** line-level stripping for work orders, falling back to block | Scenario C asks for strip or block |
| Synthetic gas-leak KB | **Add** `data/kb/` with its own signed registry and facts file | Existing `data/` stays as the evaluation corpus |
| Interface A, `portal/` | **Refactor** (reuse the server, page shell, presenter panel and scenario toggles) | Already the technician experience; swap to the new KB and scenarios, show the request ID |
| Interface B, the console | **Refactor**: serve a console view from the same portal backend process, reading the same audit log | The only reliable way to get matching request IDs and one shared runtime |
| Streamlit dashboard `app.py` | **Keep** for evaluation results and Watch; no new work | Still the evidence for the 15/40 vs 0/40 results |
| Evaluation harness | **Keep** | Untouched by the new KB |
