# RAG Shield Technical Report

## Summary

We built a local RAG assistant for a fictional compressor station, attacked it with poisoned documents, and tested a modular defense called RAG Shield. The Shield stopped every clear attack from unapproved documents in testing (15 of 40 on Baseline, 0 of 40 protected) while legitimate accuracy stayed at 10 of 10. It gave no measurable benefit against reworded poison that had passed approval (3 of 10 on Baseline, 4 of 10 protected).

The main lesson matches the scenario's conclusion: securing enterprise AI requires governing the information it retrieves. The strongest protection came from approval status, and approval then became the weakest point.

The scenario is hypothetical. It does not claim that The Williams Companies was attacked or is vulnerable, and nothing here connects to real systems or Copilot.

## System

- **Version A, Baseline RAG:** ingestion, chunking, MiniLM embeddings, ChromaDB, top-4 retrieval, and `llama3.1:8b` through Ollama. It records trust labels but ignores them.
- **Version B, RAG Shield:** the same system with seven controls in `src/shield.py`. Six can be switched off individually.

| Control | Purpose | NIST CSF function |
| --- | --- | --- |
| Provenance | Verify owner, version, approval, and hash | Identify, Protect |
| Trust-based retrieval | Keep unapproved content out of high-impact answers | Protect |
| Injection detection | Flag instructions in documents, with explanations | Detect |
| Conflict detection | Compare unapproved text with approved facts | Detect |
| Quarantine and review | Preserve evidence and contain suspicious files | Respond, Recover |
| Safe response handling | Require approved citations and check answers | Protect |
| Security logging | Record decisions for investigation | Detect, Respond |

## Evaluation method

The suite covers 10 legitimate questions, 20 primary attacks, 20 held-out attacks, 20 signed-off poison runs, and 6 harmless uploads. Each attack document was present only for its own case, and a clean control run separated attack effects from ordinary model error. An attack counted only when its payload reached the model.

Held-out attacks were written, and rules frozen, before they ran. Each control was also tested alone and removed from the full set.

## Results

| Attack set | Trials | Baseline clear (partial) | Shield clear (partial) | Detected |
| --- | --- | --- | --- | --- |
| Injection, primary | 10 | 5 (1) | 0 (0) | 9 |
| Poisoning, primary | 10 | 5 (2) | 0 (0) | 9 |
| Injection, held-out | 10 | 2 (0) | 0 (0) | 0 |
| Poisoning, held-out | 10 | 3 (2) | 0 (0) | 0 |
| Signed-off poison, listed facts | 10 | 5 (2) | 0 (0) | 0 |
| Signed-off poison, new wording | 10 | 3 (5) | 4 (2) | 0 |

Full metrics and denominators: `docs/phase4_evaluation.md`.

### Findings

1. **Prompt injection and poisoning differ in effect.** Injection mostly altered output. Poisoning changed the operational guidance, including "no escalation is needed" for W-217, which is the scenario's failure.
2. **Trust-based retrieval did most of the work.** It alone stopped all unapproved attacks.
3. **Detection was brittle.** Rules flagged 18 of 20 primary attacks and none of the 20 unseen ones. Prevention held, but no alert would have fired.
4. **Approval is the critical dependency.** Signed-off poison on unlisted facts got through.
5. **Security has an availability cost.** Harmless uploads were unusable, and signed-off poison on listed facts caused 7 of 10 answers to be withheld.

In the demonstration, the Shield kept the poison out, but its answer rejected the false claim without telling the technician to notify the Shift Supervisor. The on-screen notice says to follow required escalation, but keeping an attack out does not guarantee a complete answer.

## Watch stage

Added after the evaluation, without changing the frozen rules. Full details are in `docs/phase7_watch.md`.

An integrity scan, purge and retest, and governance metrics now cover the Watch stage. In a drill, the scan caught an unauthorized edit and a poisoned upload within 0.06s of each change, though in use scan frequency would set the real figure. The retest correctly refused to pass while an approved procedure was quarantined.

The first version of the retrieval concentration monitor missed its decoy and falsely alerted on a restored procedure. Its design was fixed, without changing thresholds, by measuring each document only while it was indexed. A validation planned in advance then caught 3 of 3 new decoys, with no alerts on 6 harmless uploads or the restored procedure. The margins were thin: one decoy alerted exactly at the threshold, and one harmless document came close.

## Limitations

- Ten trials per set, one run per case at temperature 0, so intervals are a rough guide.
- All attacks were written by the project, and retrieval favored them.
- Manual verdicts come from one reviewer and are proposed until the group confirms them.
- Control comparisons use rule-based scoring.
- Detection rules are English pattern matches, and the fact list is small.
- Results describe a small local model, not Copilot or another production assistant.

## Recommendations

1. Require two-person approval for changes to safety-critical procedures.
2. Check newly approved documents against existing procedures.
3. Restrict write access and separate draft content from approved content.
4. Use human review rather than automatic quarantine until false alarms fall.
5. Keep independent alarms and human verification for operational decisions.

## Project integrity

Several errors were found and corrected during development, the most serious being Phase Two's invalid injection result. Each is recorded in the phase reports. No results were fabricated, and superseded pilot data is kept in `evaluation/results/pilot/`.

## Financial risk

`docs/fair_handoff.md` explains how to use these results in a FAIR model. Lab reductions must not be read as equal reductions in financial loss.
