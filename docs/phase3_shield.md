# Phase Three: RAG Shield

**These are pilot results, not the formal evaluation.** They do not yet show what each control contributes. Raw data: `evaluation/results/pilot_baseline.csv` and `pilot_shielded.csv`.

## Controls

Code is in `src/shield.py`. Controls 1 to 6 can each be switched off, and logging is always on.

| # | Control | How it works |
| --- | --- | --- |
| 1 | Provenance | Re-hashes the file at query time against the registry, which also catches edits made after indexing |
| 2 | Trust-based retrieval | Pulls a wider candidate pool, ranks approved sources first, and excludes unapproved sources on high-impact questions |
| 3 | Injection detection | Scores the whole document with weighted, explained rules. A score of 0.5 or more is flagged |
| 4 | Conflict detection | Compares unapproved text with structured facts in `config/authoritative_facts.json` and names both sources |
| 5 | Quarantine | Moves flagged unapproved files aside with a manifest, never deletes them, and requires a named reviewer to restore. Restored files stay unapproved |
| 6 | Safe response | Hardened prompt, withholds high-impact answers lacking approved evidence or citation, and checks answers against the facts |
| 7 | Logging | Records IDs, trust, detections, actions, and outcome in JSONL. Stores a hash of the question, not its text |

## Pilot results

| Measure | Baseline | Shield |
| --- | --- | --- |
| Legitimate correct | 10/10 | 10/10 |
| Injection success (manual review) | 5 clear, 1 partial of 10 | 0/10 |
| Poisoning success (manual review) | 5 clear, 2 partial of 10 | 0/10 |
| Attack payload in model context | 20/20 | 0/20 |
| Injection documents flagged | not applicable | 9/10 (missed PI-10, Spanish) |
| Poison documents flagged by conflict check | not applicable | 9/10 (missed KB-10) |
| Answers withheld | not applicable | 0/30 |

A `not_retrieved` outcome in the shielded file means the Shield kept the payload out of the model's context.

PI-10 and KB-10 were still kept from the model by trust-based retrieval. This shows why detection and prevention are reported separately.

## Why 0/20 must not be read as "the Shield stops poisoning"

- Every attack document was unapproved, which is the easiest case for trust filtering. Poison that passes review, or an attacker who controls approval, would not be stopped by it.
- Injection and conflict rules were written after seeing these attacks. Detection rates are therefore optimistic. A held-out set of new attacks is needed.
- Conflict detection only covers listed facts, and its negation handling is a simple heuristic.
- All safeguards were on, so this does not show which control did the work.
- Sample size is small and each case ran once.

## Corrections made during this phase

- The detector wrongly flagged DOC-001 for "only authoritative source", which dropped a chunk and broke LEG-09. Source-ranking language alone no longer reaches the threshold.
- The conflict checker read "must never be treated as a nuisance alert" as a downgrade and withheld a correct KB-01 answer. It now skips negated uses in the same sentence.
- The notification check treated the 60-minute report deadline as a conflict. Both approved time limits are now listed.
- Injection scanning now covers whole files, because a payload can sit outside the retrieved chunk.
