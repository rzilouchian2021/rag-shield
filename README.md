# RAG Shield

A local educational simulation of AI knowledge-base poisoning, for a Cyber Risk Modeling group project. It compares **Version A (Baseline RAG)** with **Version B (RAG Shield)** on the same documents, questions, and model.

The scenario is hypothetical and inspired by ConfusedPilot research. It does not claim that The Williams Companies experienced this attack or is vulnerable. All documents describe an invented station ("Station 41"), and all equipment, codes, and values are made up. Nothing here connects to real systems or to Microsoft 365 Copilot.

**Status:** All six phases are built, plus the Watch stage (`docs/phase7_watch.md`), signed two-person sign-off with a tamper-evident log and signed-copy recovery (`docs/phase8_signoff.md`), and the gas-leak demo with a technician portal and security console (`portal/`, `src/policy.py`). Manual review verdicts in `evaluation/adjudications.json` are proposed until the group confirms them on the dashboard's **Review verdicts** page.

| Document | Purpose |
| --- | --- |
| `docs/technical_report.md` | Security design, method, results, and limitations |
| `docs/phase4_evaluation.md` | Full metrics and denominators |
| `docs/fair_handoff.md` | How to use the results in FAIR |
| `docs/phase7_watch.md` | Watch stage, governance metrics, drill results, and verdict review |
| `docs/phase8_signoff.md` | Signed two-person sign-off, key management, sealed log, and their validation |
| `evaluation/results/fair_summary.json` | Machine-readable FAIR summary |

## Architecture

```
data/approved + data/untrusted            data/quarantined (never indexed)
      │
      ▼
Ingestion ── text extraction, metadata, SHA-256, registry lookup   src/ingestion.py
      ▼
Chunking ─── word windows, heading kept with each chunk            src/ingestion.py
      ▼
Embeddings ─ all-MiniLM-L6-v2 on CPU                               src/embeddings.py
      ▼
ChromaDB ─── cosine index, re-embeds only changed files            src/vector_store.py
      ▼
Question ──► Retrieval (top-k) ──► Context assembly ──► LLM        src/retriever.py, llm_client.py
                                                         ▼
             Answer + citations + retrieved chunks + event log     src/rag_pipeline.py, logging_utils.py
```

| Component | What it does |
| --- | --- |
| Ingestion | Reads TXT, MD, and PDF files from `data/` and rejects symlinks, other file types, and files over 10 MB |
| Metadata | ID, filename, source, owner, approval status, version, timestamp, trust class, SHA-256 |
| Trust class | Set only by a registry entry plus a matching hash, never by a file's name, folder, or text |
| Retrieval | Returns the top 4 chunks with similarity scores and metadata |
| Generation | Ordinary RAG prompt with `[DOC-001]` citations. Temperature 0 and a fixed seed |
| Logging | `logs/events.jsonl` stores a hash of the question rather than its text |

Baseline mode records trust labels but deliberately ignores them. They do not affect retrieval or the prompt.

### RAG Shield layers

RAG Shield wraps the same pipeline with checks before and after the model answers.

| Layer | What it does | Where |
| --- | --- | --- |
| Gate: provenance | Re-hashes each retrieved file (SHA-256) and compares it with the registry. Labels: `approved`, `hash_mismatch`, `unapproved`, `untrusted` | `src/shield.py`, `src/ingestion.py` |
| Signed sign-off | A procedure counts as approved only with Ed25519 signatures from two different approvers, one from the owning team, checked against a keyring signed by a document-control root key. Fails closed | `src/signoff.py` |
| Screen: injection detection | Weighted rules for hidden instructions, scanned over the whole file | `src/shield.py` |
| Verify: fact conflicts | Unverified documents and answers are checked against key facts in `config/authoritative_facts.json` | `src/shield.py` |
| Answer: safe response | Safety questions need an approved, cited source; otherwise the answer is withheld | `src/shield.py` |
| Quarantine | Tampered, injected or conflicting files are moved out of the index and kept as evidence | `src/shield.py` |
| Recovery (optional) | Restores a quarantined procedure from a signed archive, only if the archived copy matches the signed hash, then answers again. Off by default | `src/monitoring.py`, `src/rag_pipeline.py` |
| Watch | Integrity scans, alerts, retrieval-concentration monitor, purge and retest, governance metrics | `src/monitoring.py` |
| Tamper-evident log | Every log entry is sealed with a chained HMAC-SHA256, so edits, deletions and truncation are detected | `src/logging_utils.py` |

## Setup

Requires macOS or Linux, Python 3.11+, and [Ollama](https://ollama.com). No GPU is needed. Allow about 2.5 GB of disk for dependencies and the embedding model, plus the LLM.

```bash
cd CRM_RAG_SHEILD
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
ollama pull llama3.1:8b
python -m src.rag_pipeline --rebuild      # first run downloads the embedding model
```

**Signing keys.** The committed registry is already signed, and checking signatures needs only the public keys in `config/`, so a fresh clone works as is. Signing new documents needs private keys, which are never committed. On a new machine, document control can create fresh demo keys and re-sign the six procedures with `python -m src.signoff init-demo --force` (asks for a passphrase, or reads `RAG_SHIELD_KEY_PASSPHRASE` from `.env`).

To use the Anthropic API instead, set `LLM_PROVIDER=anthropic` and `ANTHROPIC_API_KEY` in `.env`. This path has only been tested with mocks, not against the live API. Never commit `.env`.

## Usage

| Task | Command |
| --- | --- |
| Start the dashboard, then open http://localhost:8501 | `streamlit run app.py` |
| Ask from the terminal | `python -m src.rag_pipeline "What should I do about alert W-217?"` |
| List documents and trust | `python -m src.ingestion` |
| Index new or changed files | `python -m src.rag_pipeline --sync` |
| Rebuild the index | `python -m src.rag_pipeline --rebuild` |
| Record a new version's hash for review | `python -m src.ingestion --approve approved/file.md` |
| Sign it (two approvers needed) | `python -m src.signoff sign approved/file.md --as ops-manager` |
| Who signed what | `python -m src.signoff status` |
| Verify the security log's seals | `python -m src.signoff verify-log` |
| Validate sign-off and the log against attacks | `python -m demo.validate_signoff` |
| Run tests | `pytest` |
| Run the full evaluation (about 45 minutes) | `python -m evaluation.run_evaluation`, then `python -m evaluation.run_compromised_holdout` |
| Run Baseline and full Shield only | `python -m evaluation.run_evaluation --core-only` |
| Rebuild summaries and charts | `python -m evaluation.summarize` |
| Export the FAIR summary | `python -m evaluation.export_fair` |
| Run the final demonstration | `python -m demo.run_demo`, or use the Demo page |
| Gas-leak demo: technician portal and security console | `python -m portal.server`, then http://127.0.0.1:8600 and /console (presenter controls: Ctrl+Shift+S) |
| Integrity scan, metrics, or purge and retest | `python -m src.monitoring --scan`, `--metrics`, or `--purge-retest`, or use the Watch page |
| Run the Watch-stage drill (about 2 minutes) | `python -m demo.run_drill`, or use the Watch page |
| Validate the retrieval monitor (about 8 minutes) | `python -m demo.validate_monitor` |
| Confirm manual verdicts as a group | Review verdicts page, then **Rebuild summaries and FAIR export** |

## Gas-leak demo: technician portal and security console

The live demo (`docs/demo-script.md`) runs a fictional Williams-style employee portal, clearly labeled as a class simulation and not affiliated with Williams. A field technician asks the Field Assistant about a gas leak, using a synthetic knowledge base in `data/kb/`: a leak procedure, an isolation valve list, evacuation routes, work orders, a restricted security plan, simulated live sensor readings, and two documents from a second fictional station (Station 52). All documents are signed by two approvers (`config/kb_registry.json`).

```bash
python -m portal.server     # technician: http://127.0.0.1:8600   console: http://127.0.0.1:8600/console
```

Both interfaces call the same backend and the same deterministic policy layer (`src/policy.py`): identify the user and role, filter retrieved documents by role, inspect with RAG Shield, answer from permitted context only, inspect the answer, check routes against live wind, then decide **allow / warn / redact / block** and write the decision to the sealed audit log. The console shows each request under the same request ID as the technician view.

Presenter panel (**Ctrl+Shift+S**) scenarios, each repeatable and applied to a disposable copy in `storage/portal/`:

| Scenario | Toggle | Shield off | Shield on |
| --- | --- | --- | --- |
| A. Normal | Reset | Correct guidance | **Allow** |
| B. Poisoned valve list and route | Poison | Wrong valve (IV-12) | **Redact**: tampered copies excluded, signed versions restored, IV-7 |
| C. Injected work order | Inject | "Open IV-12 at the east manifold, don't call Gas Control" | **Redact**: work order excluded, correct procedure |
| D. Route downwind of the leak | Wind from north | Route S | **Warn**: confirm with Gas Control, upwind route is Route N |
| E. Restricted document | (none) | Leaks camera gaps | **Block** by role, nothing revealed |
| F. Preview: another station | (none) | Station 52's sensitive setpoints, no checks | Emergency procedure: **Warn** (break-glass, flagged for review). Sensitive document: **Block** until the PIN is verified (15 minutes, 3 tries) |

Closing: **Tamper with audit log** rewrites a past decision; the console's Integrity panel shows the log no longer verifies.

**OWASP RAG Security Cheat Sheet:** every recommendation is mapped to code and tests in `docs/owasp-rag-coverage.md` (red-team tests: `tests/test_owasp_rag.py`, run in CI by `.github/workflows/tests.yml`). Added controls include index-integrity checks on every retrieved chunk, hidden-character detection, data delimiters in the prompt, per-user rate limits, secret and identifier redaction, signed attribution (`POST /api/verify-attribution`), stage-named fail-closed errors, and pattern alerts. Incident response: `docs/incident-response.md` and `python -m src.incident affected DOC-ID`.

Set `RAG_SHIELD_DEMO_PIN` in `.env` (see `.env.example`) for scenario F; without it, other stations' sensitive documents stay locked.

Architecture and trust boundaries: `docs/architecture.md`. Audit of the starting point: `docs/existing-system-audit.md`. Independent test results: `docs/test-results.md`. Limitations and production needs: `docs/limitations.md`.

**Loading documents:** put TXT, MD, or PDF files in `data/untrusted/`, then use **Re-index documents** on the Documents page or run `--sync`. New files are classed as untrusted until they are registered and approved.

**Exporting results:** CSV files and charts are written to `evaluation/results/`. `evaluation_summary.csv` holds Baseline vs Shield, and `ablation_summary.csv` holds the per-control runs.

**Monitoring:** the Watch page shows the governance metrics, alerts, and retrieval concentration, and runs scans, purge-and-retest, and the drill.

**Switching modes:** use the sidebar selector. In `shielded` mode, each of the six switchable controls has a checkbox. Logging is always on. Review quarantined files on the Quarantine page.

## Known limitations

- Trust filtering cannot stop false content that was approved. Signed two-person sign-off stops a single insider or someone editing the registry, but not two colluding approvers (`docs/phase8_signoff.md`).
- Injection detection uses English rules and misses other languages and paraphrases.
- Conflict detection covers only the facts listed in `config/authoritative_facts.json`.
- A matching hash shows a file is unchanged since sign-off, not that its content is accurate.
- Signed-copy recovery trusts the archive only as far as it matches the signed hash. In the portal the archive is the project's own `data/` folder; a real deployment would keep it in a separate read-only store.
- Approvers' keys are simulated: all of them sit encrypted in one local `keys/` folder with one shared demo passphrase, and the assistant runs under your own account, so the access audit shows its files as writable.
- `llama3.1:8b` is a small model, so results do not predict how Copilot or any production assistant would behave.
- Scanned PDFs without a text layer are skipped and reported.
- The retrieval concentration monitor was revised after failing its first drill. On revalidation it caught 3 of 3 decoys with no false alarms, but by thin margins and on a small sample (`docs/phase7_watch.md`).
- The monitor only sees documents that are retrieved broadly. A narrow, targeted poison document would not trigger it.
- Monitoring times start from file modification times, which can be preserved by copies or falsified.

## Ethics and safety

All data is synthetic. Test content must stay fictional and must not include real alarm thresholds, control instructions, or ways to bypass safety systems. Use this project only for local education.
