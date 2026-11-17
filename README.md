# RAG Shield

A local educational simulation of AI knowledge-base poisoning, for a Cyber Risk Modeling group project. It compares **Version A (Baseline RAG)** with **Version B (RAG Shield)** on the same documents, questions, and model.

The scenario is hypothetical and inspired by ConfusedPilot research. It does not claim that The Williams Companies experienced this attack or is vulnerable. All documents describe an invented station ("Station 41"), and all equipment, codes, and values are made up. Nothing here connects to real systems or to Microsoft 365 Copilot.

**Status:** All six phases are built, plus the Watch stage (`docs/phase7_watch.md`) and signed two-person sign-off with a tamper-evident log (`docs/phase8_signoff.md`). Manual review verdicts in `evaluation/adjudications.json` are proposed until the group confirms them on the dashboard's **Review verdicts** page.

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
| Integrity scan, metrics, or purge and retest | `python -m src.monitoring --scan`, `--metrics`, or `--purge-retest`, or use the Watch page |
| Run the Watch-stage drill (about 2 minutes) | `python -m demo.run_drill`, or use the Watch page |
| Validate the retrieval monitor (about 8 minutes) | `python -m demo.validate_monitor` |
| Confirm manual verdicts as a group | Review verdicts page, then **Rebuild summaries and FAIR export** |

**Loading documents:** put TXT, MD, or PDF files in `data/untrusted/`, then use **Re-index documents** on the Documents page or run `--sync`. New files are classed as untrusted until they are registered and approved.

**Exporting results:** CSV files and charts are written to `evaluation/results/`. `evaluation_summary.csv` holds Baseline vs Shield, and `ablation_summary.csv` holds the per-control runs.

**Monitoring:** the Watch page shows the governance metrics, alerts, and retrieval concentration, and runs scans, purge-and-retest, and the drill.

**Switching modes:** use the sidebar selector. In `shielded` mode, each of the six switchable controls has a checkbox. Logging is always on. Review quarantined files on the Quarantine page.

## Known limitations

- Trust filtering cannot stop false content that was approved. Signed two-person sign-off stops a single insider or someone editing the registry, but not two colluding approvers (`docs/phase8_signoff.md`).
- Injection detection uses English rules and misses other languages and paraphrases.
- Conflict detection covers only the facts listed in `config/authoritative_facts.json`.
- A matching hash shows a file is unchanged since sign-off, not that its content is accurate.
- Approvers' keys are simulated: all of them sit encrypted in one local `keys/` folder with one shared demo passphrase, and the assistant runs under your own account, so the access audit shows its files as writable.
- `llama3.1:8b` is a small model, so results do not predict how Copilot or any production assistant would behave.
- Scanned PDFs without a text layer are skipped and reported.
- The retrieval concentration monitor was revised after failing its first drill. On revalidation it caught 3 of 3 decoys with no false alarms, but by thin margins and on a small sample (`docs/phase7_watch.md`).
- The monitor only sees documents that are retrieved broadly. A narrow, targeted poison document would not trigger it.
- Monitoring times start from file modification times, which can be preserved by copies or falsified.

## Ethics and safety

All data is synthetic. Test content must stay fictional and must not include real alarm thresholds, control instructions, or ways to bypass safety systems. Use this project only for local education.
