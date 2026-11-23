# Incident response runbook (RAG-specific)

For the fictional gas-leak assistant. Follows OWASP RAG Security Cheat Sheet §12: quarantine
the document, clear anything derived from it, and find everyone who received an answer built
from it. Times are targets for a real operation, not measured.

## 1. A document is found to be poisoned or tampered

| Step | Action | Command or place |
| --- | --- | --- |
| 1 | Confirm the alert on the security console (`document_tampered`, `index_tampered`, `hidden_characters`, `prompt_injection`) | `/console`, Security alerts |
| 2 | Check the audit log still verifies, so the evidence can be trusted | `python -m src.signoff verify-log --log storage/portal/audit.jsonl`, or the Integrity panel |
| 3 | Quarantine. RAG Shield already moved the file to `quarantined/` and restored the signed copy if one exists. For a file it did not catch, move it out of the document folders | File system |
| 4 | Rebuild the search index from signed documents, so no altered chunk stays searchable | Demo: presenter **Reset** (rebuilds from `data/kb`). The portal also re-syncs on every change |
| 5 | Find who received answers from it, and whether any were unchecked (Shield off) | `python -m src.incident affected DOC-102 --log storage/portal/audit.jsonl` |
| 6 | Contact those users with the correct procedure; for safety procedures, through the shift supervisor and Gas Control | Out of band |
| 7 | Review how it got in: uploader (`document_uploaded` alert), signers (the entry in `config/kb_registry.json`), edit time | Console and registry |

There is no response cache, so nothing else needs invalidating.

## 2. An approver key may be compromised

1. Revoke it: `python -m src.signoff revoke <approver> --key <key_id>`. Its signatures stop counting immediately, so documents signed only with it lose approval (fail closed).
2. Issue a new key: `python -m src.signoff rotate-key <approver>`.
3. Have each affected document re-signed by two valid approvers (`src.signoff.sign_document`; the `sign` command-line option targets the evaluation registry).
4. Run `python -m src.incident affected` for each affected document if a false procedure may have been signed.

## 3. The audit log does not verify

The Integrity panel shows the first broken entry. Preserve the log and head file as they are,
compare with any off-machine copy of the head, and treat everything after the break as
untrusted. In the demo, **Reset** starts a fresh log.

## 4. Repeated failures, reconnaissance or injection attempts

Alerts `repeated_failures`, `possible_reconnaissance`, `repeated_injection_attempts`,
`rate_limited`: identify the user from the alert, check their recent requests on the console
(request IDs, categories), and decide whether to suspend access. Repeated failures can mean
someone is trying to force the assistant to answer without its checks; it refuses rather than
degrade, so no unchecked answer was released.

## 5. Break-glass access was used

Every `break_glass_access` alert is reviewed after the event: was there a real emergency at the
other station, and was the person helping there? Break-glass is never blocked, because delaying
safety information is the larger risk.
