# Limitations and what production would need

This is a class demo on synthetic data, built to show the control working, not to run in a
real pipeline company. Everything under "What production would need" is future work, not a
built feature.

## Known limitations of the demo

**Detection**
- Prompt-injection detection is a set of weighted English patterns (`src/shield.py`). Paraphrases, other languages, and instructions split across documents can evade it. It is one layer: an injected document that is also unapproved is excluded on safety questions regardless of the patterns.
- The independent benchmark (`docs/test-results.md`) found the content detectors weak on their own: they raised false alarms on benign documents that quote instructions or mention the valve and leak facts, and missed several malicious documents. What kept every attack out of answers was the combination with provenance: unreviewed uploads are excluded on safety questions whatever their content. A side effect is that RAG Shield often reports **redact** on clean questions, because harmless unreviewed uploads were removed.
- Key-fact conflicts cover only the facts in `config/kb_facts.json` (isolation valve, leak response). Other false claims in an unapproved document are caught only by provenance, not by content.
- The live-data check covers evacuation routes against wind direction only. It reads route names in the answer text, so an answer that describes a direction without naming a route is not checked.
- Signed sign-off cannot stop two colluding or compromised approvers. A false procedure they both sign is trusted.
- Until 2026-11-22 the approvers' signatures covered each document's hash and version but **not** its access list, so editing `allowed_roles` in the registry was not detected. Signatures now also cover `allowed_roles`, `site` and `sensitivity`, and an entry whose signatures fail is readable by nobody (tests: `test_editing_an_access_list_breaks_the_signatures`, `test_editing_a_station_tag_breaks_the_signatures`).
- The answer check blocks 8-word runs of restricted text; a paraphrase of restricted content would not be caught by that check (it is still prevented upstream, because restricted documents never reach the model).

**OWASP RAG Security Cheat Sheet items not fully built** (full map: `docs/owasp-rag-coverage.md`)
- One vector collection with isolation inside the search, not separate collections or per-tenant encryption keys.
- Embeddings are not encrypted at rest (relies on disk encryption); no embedding-drift detection or cross-model validation.
- The embedding model is pinned by name, not by revision hash.
- Reconnaissance detection counts repeated restricted hits only; it does not detect systematic term variation.
- The sensitive-data filter uses fixed patterns (keys, tokens, passwords, SSNs, card numbers) and will miss other formats.

**Model**
- `llama3.1:8b` is small and its wording varies between versions and prompts. Scenario outcomes were rehearsed, but a different model could behave differently, in either direction.
- The model is a single local instance; requests are processed one at a time.

**Identity and access**
- There is no login. The demo user is chosen from a menu, and the server trusts that choice. Roles and document access lists are real checks, but identity is simulated.
- Two roles are exercised (field technician, security officer), and two stations (41 and 52).
- Station-based access (scenario F) is a preview. The step-up factor is one shared demo PIN from `.env`, kept in memory only as a salted scrypt hash; grants and lockouts live in server memory and reset on restart. The question names the station through fixed words ("Station 52", "Regulator Yard"); a question that names no station is about the user's home station.
- Break-glass access is deliberately never blocked for emergency procedures; it relies on after-the-fact review of every `break_glass_access` alert.
- The live-data route check uses Station 41's sensors only; Station 52 answers are not checked against wind.

**Integrity and keys**
- All approver private keys sit encrypted in one local `keys/` folder with one shared demo passphrase.
- The "protected archive" of signed versions is the project's own `data/kb` folder.
- The audit log's HMAC key sits on the same machine as the log. Someone holding it could rewrite the log; restoring an old copy of both the log and its head file is not detectable without an off-machine copy of the head.
- The assistant runs as the same operating-system user that owns the files it protects.

**Data**
- All documents, sensors, people, phone numbers and the company are invented. Sensor readings are a static snapshot that the demo toggles; there is no SCADA connection.

## What production would need

| Area | What it would take |
| --- | --- |
| Identity and SSO | Sign-in through the company identity provider (SAML or OIDC), roles from the directory, short-lived sessions, MFA for approvers |
| Approver keys | Keys on hardware tokens or in a managed key vault, one per approver, never on the assistant host; the root key offline |
| Key rotation | Scheduled rotation of approver keys, the root key, and the audit-log key; signed timestamps so earlier approvals stay valid after rotation; revocation checked at query time |
| Multi-tenancy | Separate indexes, registries, keys and logs per station or business unit, with tenant isolation tests |
| Live data | A read-only integration with the historian, with freshness checks (stale data warns), and rules for more than wind (methane spread, pressure, closed roads) reviewed by safety engineers |
| Separation of duties | The assistant runs as a read-only service account; only document control can write the registry, archive and keyring |
| CI/CD | Tests, the detection benchmark and the signature validation run on every change; the frozen inspection rules are versioned and changes need review; signed builds |
| Monitoring | Central log shipping (the audit-log head sent off-host), alerting on blocks, tamper alerts and failed checks, dashboards for decision rates and latency |
| Scaling and load testing | A served model with capacity planning, concurrent request handling, and load tests with latency targets (this demo measured single-user latency only) |
| Detection quality | A larger labeled benchmark including real-world injection styles, multilingual content, and a regularly re-run red-team exercise |
| Incident response | Runbooks for quarantined documents, approver key compromise, and a model producing unsafe output |
| Human factors | Field testing with technicians: warnings must be quick to read in an emergency, and the assistant must never replace Gas Control's instructions |
