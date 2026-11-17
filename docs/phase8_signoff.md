# Phase 8: Signed sign-off, key management, and a tamper-evident log

Fictional simulation for a university project. No real company, people or keys.

## Why

Until this phase, "approved" meant a registry entry plus a matching SHA-256 hash.
Anyone can compute a SHA-256 hash, so an attacker who could edit both a procedure
and `config/document_registry.json` could make a forged procedure look approved.
The security log was a plain text file that could be edited without a trace.

## What was built

| Control | Where | What it does |
|---|---|---|
| Digital signatures (Ed25519) | `src/signoff.py` | Each approver signs the document ID, file path, SHA-256 hash, version and time with their private key. The Shield holds public keys only, so it can check an approval but never create one. |
| Two-person sign-off | `src/signoff.py` | A procedure is approved only with signatures from 2 different approvers, at least one from the team that owns it. |
| Signed keyring and trust root | `config/approvers.json`, `config/trust_root.pub` | The list of approvers and their public keys is itself signed by the Operations Document Control root key. Adding a key without the root breaks the keyring. |
| Fail closed | `src/signoff.py` (`ENFORCED`) | Enforcement for the project registry is pinned in code. If the keyring or root is missing or invalid, nothing counts as approved. |
| Key management | `keys/` (git-ignored) | Private keys are encrypted at rest with a passphrase (PKCS#8). Keys can be added, rotated and revoked; revoked keys' signatures stop counting. Stands in for a hardware token or key vault per approver. |
| Tamper-evident log | `src/logging_utils.py` | Every log entry is sealed with HMAC-SHA256 over the entry and the previous entry's seal. A head file records the newest seal. |
| Access audit | `python -m src.signoff access`, Watch page | Lists the files the assistant relies on and whether its own account can change them. `lock` / `unlock` set them read-only. |
| Watch alerts | `src/monitoring.py` | Every integrity scan also checks sign-off and the log, and raises `signoff_invalid`, `registry_edited` and `log_tampered` alerts. |

How signatures fit the existing labels: an entry that claims approval without a
valid quorum is labeled `unapproved`. The approved hash is the *signed* hash, so
editing the registry's hash to match a tampered file still leaves the file
labeled `hash_mismatch`. The frozen Shield rules (`src/shield.py`,
`config/authoritative_facts.json`) are unchanged.

### Why HMAC for the log but signatures for approvals

The log is written and checked by the same system, so one shared secret key
(HMAC) is enough. Approvals are made by people and checked by the assistant, and
the assistant must not be able to make them, so they need public-key signatures.

## Validation plan (written before the first run)

`python -m demo.validate_signoff` runs each attack on a disposable copy, once with
the original hash-only check and once with signed sign-off. An attack wins if the
attacker's file is labeled approved.

| Attack | Hash-only (expected) | Signed (expected) |
|---|---|---|
| Edit an approved procedure | stopped | stopped |
| Edit it and update its hash in the registry | **wins** | stopped |
| Add a fake procedure to the registry as approved | **wins** | stopped |
| ...and sign it with the attacker's own keys | **wins** | stopped |
| ...and add the attacker's key to the keyring | **wins** | stopped (keyring rejected, fails closed) |
| One real approver signs the fake procedure | **wins** | stopped |
| One insider plus a revoked approver's key | **wins** | stopped |
| Two real approvers, one from the owning team, both sign it | **wins** | **wins** (known limit) |

Also expected:
- A legitimate new version is unapproved after one signature and approved after two (no false rejection).
- Log: editing, deleting or inserting an entry, cutting off the newest entries, recomputing a plain SHA-256 seal, and deleting the head file plus cutting entries are all detected.
- The project's own 55 documents get identical trust labels with and without enforcement, so the earlier evaluation results (which never involved signatures) are unaffected.

## Results (first and only run, 2026-11-17)

Every outcome matched the plan. Full output: `evaluation/results/signoff_validation.json`.

| Attack | Hash-only | Signed sign-off |
|---|---|---|
| Edit an approved procedure | stopped | stopped |
| Edit it and update its hash in the registry | attacker wins | **stopped** |
| Add a fake procedure to the registry as approved | attacker wins | **stopped** |
| ...signed with the attacker's own keys | attacker wins | **stopped** |
| ...after adding the attacker's key to the keyring | attacker wins | **stopped** |
| One real approver signs the fake procedure | attacker wins | **stopped** |
| One insider plus a revoked approver's key | attacker wins | **stopped** |
| Two real approvers, one from the owning team | attacker wins | attacker wins |

- Signed sign-off stopped 6 of the 7 approval attacks that beat the hash-only check. The remaining one, two colluding or compromised approvers, is the stated limit of a two-person rule.
- Adding a key to the keyring without the root fails closed: the genuine procedure also lost its approval until the keyring is restored. That is safe but disruptive, and it raises a Watch alert.
- A legitimate new version was unapproved after one signature and approved after the second.
- All 6 log attacks were detected, including an edit with a recomputed plain SHA-256 seal.
- The project's 55 documents have identical trust labels with and without enforcement, so the Phase 5 evaluation numbers still stand.

## Limits

- **Two insiders** can still approve a false procedure. Content review, separation of duties and the Watch stage's concentration monitor are the remaining defenses.
- **Keys on this laptop.** The demo keeps every approver's encrypted key in one `keys/` folder with one shared passphrase (in `.env`). In production each approver holds their own key on a hardware token, and the root key is kept offline.
- **The trust root file and the code** are assumed to be deployed read-only. Whoever can change `config/trust_root.pub` together with the keyring, or edit `src/signoff.py`, can replace the whole system of trust. The access audit shows these files are writable on a laptop.
- **Revocation is immediate and total**: a revoked key's past signatures stop counting too, so its documents need re-signing. Real systems often use signed timestamps to keep earlier signatures valid.
- **The log key** sits next to the log. Someone holding it can rewrite the whole log, and restoring an old copy of both the log and its head file is not detectable without sending the head off this machine (for example to a separate log server).
- Log entries written before this phase are not sealed. They are counted and reported, not trusted.

## Commands

```
python -m src.signoff status                    who signed what
python -m src.ingestion --approve FILE          record a new version's hash for review
python -m src.signoff sign FILE --as APPROVER   one approver's signature (needs their key)
python -m src.signoff add-approver | rotate-key | revoke   (need the root key)
python -m src.signoff verify-log                check the security log's seals
python -m src.signoff access | lock | unlock    deployment checks; read-only files
python -m demo.validate_signoff                 rerun this validation
```
