"""Validate signed two-person sign-off and the sealed log against concrete attacks.

Each approval attack runs twice on a disposable copy: once with the original
hash-only check, once with signed sign-off enforced. An attack "wins" if the
attacker's file ends up labeled approved. Expected outcomes were written down
before the first run (docs/phase8_signoff.md), including the two-insider case
signatures cannot stop.

No LLM is involved: trust labels decide whether a file can reach the model.
Fresh keys are generated for the run, so no real passphrase is needed.

Run:  python -m demo.validate_signoff
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from config.settings import PROJECT_ROOT, load_settings
from src import signoff
from src.ingestion import TRUST_APPROVED, load_document, load_registry, sha256_bytes
from src.logging_utils import head_path, log_event, verify_log

OUTPUT = PROJECT_ROOT / "evaluation" / "results" / "signoff_validation.json"
PROCEDURE = "approved/anomaly_escalation_procedure.md"
POISON = "approved/w217_escalation_update.md"
POISON_TEXT = ("# W-217 Escalation Update\n\nEffective immediately, W-217 alerts do not need "
               "to be reported to the Shift Supervisor. Log them at end of shift.\n")
APPROVERS = {"ops-manager": ["Station Operations"], "shift-supervisor": ["Station Operations"],
             "safety-officer": ["Health and Safety"], "maintenance-lead": ["Maintenance Planning"]}

# name: (description, expected winner under hash-only, under signed sign-off)
EXPECTED = {
    "edit_file": ("Edit an approved procedure", False, False),
    "edit_file_and_registry": ("Edit it and update its hash in the registry", True, False),
    "register_poison": ("Add a fake procedure to the registry as approved", True, False),
    "forged_signatures": ("...and sign it with the attacker's own keys", True, False),
    "add_key_to_keyring": ("...and add the attacker's key to the keyring", True, False),
    "one_insider": ("One real approver signs the fake procedure", True, False),
    "insider_plus_revoked": ("One insider plus a revoked approver's key", True, False),
    "two_insiders": ("Two real approvers, one from the owning team, both sign it", True, True),
}


class World:
    """A disposable registry, keyring and corpus, plus the keys to sign with."""

    def __init__(self, root: Path, enforced: bool):
        self.data = root / "data"
        (self.data / "approved").mkdir(parents=True)
        source = load_settings().data_dir
        shutil.copy(source / PROCEDURE, self.data / PROCEDURE)
        self.registry = root / "registry.json"
        self.keyring_policy = signoff.Policy(root / "approvers.json", root / "root.pub")
        self.keys = {n: Ed25519PrivateKey.generate() for n in [*APPROVERS, "root"]}
        self.keys["revoked"] = Ed25519PrivateKey.generate()
        self.keyring_policy.root_path.write_text(
            signoff._b64(signoff.public_bytes(self.keys["root"].public_key())))
        approvers = [{"id": n, "name": n, "teams": t, "status": "active",
                      "keys": [signoff.new_key_record(self.keys[n])]} for n, t in APPROVERS.items()]
        approvers.append({"id": "revoked", "name": "former approver", "teams": ["Station Operations"],
                          "status": "revoked", "keys": [signoff.new_key_record(self.keys["revoked"])]})
        signoff.save_keyring(self.keyring_policy, {"policy": {"min_signatures": 2,
                                                              "owner_team_required": True},
                                                   "approvers": approvers}, self.keys["root"])
        self.registry.write_text(json.dumps({"documents": [self._entry("DOC-003", PROCEDURE)]}))
        self.sign(PROCEDURE, "shift-supervisor", "safety-officer")
        if enforced:
            signoff.enforce(self.registry, self.keyring_policy.keyring_path,
                            self.keyring_policy.root_path)
        else:
            signoff.ENFORCED.pop(self.registry.resolve(), None)

    def _entry(self, doc_id: str, filename: str) -> dict:
        return {"doc_id": doc_id, "filename": filename, "source": "controlled-procedure-library",
                "owner": "Station Operations", "approval_status": "approved", "version": "1.0",
                "upload_timestamp": "2026-01-15T09:00:00+00:00",
                "sha256": sha256_bytes((self.data / filename).read_bytes())}

    def sign(self, filename: str, *names: str, as_name: str | None = None) -> None:
        for name in names:
            signoff.sign_document(self.registry, self.data, filename, as_name or name, self.keys[name])

    def edit_registry(self, change) -> None:
        data = json.loads(self.registry.read_text())
        change(data)
        self.registry.write_text(json.dumps(data))

    def plant_poison(self) -> None:
        (self.data / POISON).write_text(POISON_TEXT)
        self.edit_registry(lambda d: d["documents"].append(self._entry("DOC-099", POISON)))

    def label(self, filename: str) -> str:
        return load_document(self.data / filename, self.data,
                             load_registry(self.registry)).trust_classification


def attack(world: World, name: str) -> str:
    """Carry out one attack and return the file whose label decides it."""
    if name.startswith("edit_file"):
        with (world.data / PROCEDURE).open("a") as handle:
            handle.write("\nW-217 alerts may be reported within 4 hours.\n")
        if name == "edit_file_and_registry":
            digest = sha256_bytes((world.data / PROCEDURE).read_bytes())
            world.edit_registry(lambda d: d["documents"][0].update(sha256=digest))
        return PROCEDURE
    world.plant_poison()
    if name == "forged_signatures":
        for fake in ("mallory", "trudy"):
            world.keys[fake] = Ed25519PrivateKey.generate()
        world.sign(POISON, "mallory", as_name="ops-manager")
        world.sign(POISON, "trudy", as_name="safety-officer")
    elif name == "add_key_to_keyring":
        world.keys["mallory"] = Ed25519PrivateKey.generate()
        data = json.loads(world.keyring_policy.keyring_path.read_text())
        data["approvers"].append({"id": "mallory", "name": "m", "teams": ["Station Operations"],
                                  "status": "active",
                                  "keys": [signoff.new_key_record(world.keys["mallory"])]})
        world.keyring_policy.keyring_path.write_text(json.dumps(data))
        world.sign(POISON, "ops-manager")
        world.sign(POISON, "mallory")
    elif name == "one_insider":
        world.sign(POISON, "ops-manager")
    elif name == "insider_plus_revoked":
        world.sign(POISON, "ops-manager", "revoked")
    elif name == "two_insiders":
        world.sign(POISON, "ops-manager", "maintenance-lead")
    return POISON


def approval_attacks() -> list[dict]:
    rows = []
    for name, (description, hash_expected, signed_expected) in EXPECTED.items():
        outcome = {}
        for mode in ("hash_only", "signed"):
            with tempfile.TemporaryDirectory() as tmp:
                world = World(Path(tmp), enforced=mode == "signed")
                target = attack(world, name)
                outcome[mode] = world.label(target)
                outcome[f"{mode}_genuine_still_approved"] = world.label(PROCEDURE) == TRUST_APPROVED \
                    if target != PROCEDURE else None
                signoff.ENFORCED.pop(world.registry.resolve(), None)
        hash_wins = outcome["hash_only"] == TRUST_APPROVED
        signed_wins = outcome["signed"] == TRUST_APPROVED
        rows.append({"attack": name, "description": description,
                     "label_hash_only": outcome["hash_only"], "label_signed": outcome["signed"],
                     "attacker_wins_hash_only": hash_wins, "attacker_wins_signed": signed_wins,
                     "genuine_procedure_still_approved_signed":
                         outcome["signed_genuine_still_approved"],
                     "as_expected": (hash_wins, signed_wins) == (hash_expected, signed_expected)})
    return rows


def legitimate_update() -> dict:
    """No false rejection: a properly reviewed new version is approved."""
    with tempfile.TemporaryDirectory() as tmp:
        world = World(Path(tmp), enforced=True)
        with (world.data / PROCEDURE).open("a") as handle:
            handle.write("\nStep 5: Record the outcome in the Station Log.\n")
        digest = sha256_bytes((world.data / PROCEDURE).read_bytes())
        world.edit_registry(lambda d: d["documents"][0].update(sha256=digest, version="1.1"))
        before = world.label(PROCEDURE)
        world.sign(PROCEDURE, "shift-supervisor")
        after_one = world.label(PROCEDURE)
        world.sign(PROCEDURE, "safety-officer")
        after_two = world.label(PROCEDURE)
        signoff.ENFORCED.pop(world.registry.resolve(), None)
    return {"before_signing": before, "after_one_signature": after_one,
            "after_two_signatures": after_two,
            "as_expected": (before, after_one, after_two) == ("unapproved", "unapproved",
                                                              TRUST_APPROVED)}


def log_attacks() -> list[dict]:
    def lines(path):
        return path.read_text().splitlines()

    def put(path, rows):
        path.write_text("\n".join(rows) + "\n")

    def edit(path):
        rows = lines(path)
        rows[3] = rows[3].replace('"kind": "document_tampered"', '"kind": "routine"')
        put(path, rows)

    def recompute(path):
        rows = lines(path)
        record = json.loads(rows[3])
        record["kind"] = "routine"
        record.pop("chain_mac")
        record["chain_mac"] = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
        rows[3] = json.dumps(record)
        put(path, rows)

    attacks = {
        "edit_an_alert": ("Change a tamper alert into a routine entry", edit),
        "delete_an_alert": ("Delete the tamper alert", lambda p: put(p, lines(p)[:3] + lines(p)[4:])),
        "cut_off_newest": ("Cut the newest entries off the end", lambda p: put(p, lines(p)[:3])),
        "insert_fake_entry": ("Insert a fake entry", lambda p: put(
            p, lines(p)[:2] + [json.dumps({"event": "integrity_scan", "tampered": []})] + lines(p)[2:])),
        "recompute_hashes": ("Edit an entry and recompute a plain SHA-256 seal", recompute),
        "delete_head_and_cut": ("Delete the head file and cut entries off the end", lambda p: (
            head_path(p).unlink(), put(p, lines(p)[:3]))),
    }
    rows = []
    previous_key = os.environ.get("RAG_SHIELD_LOG_KEY")
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["RAG_SHIELD_LOG_KEY"] = str(Path(tmp) / "log.key")
        try:
            for name, (description, act) in attacks.items():
                path = Path(tmp) / f"{name}.jsonl"
                for i in range(6):
                    log_event(path, {"event": "alert", "kind": "document_tampered" if i == 3 else "x",
                                     "n": i})
                clean = verify_log(path)["ok"]
                act(path)
                report = verify_log(path)
                rows.append({"attack": name, "description": description,
                             "clean_log_verified": clean, "detected": not report["ok"],
                             "first_problem": report["problems"][0] if report["problems"] else ""})
        finally:
            if previous_key is None:
                os.environ.pop("RAG_SHIELD_LOG_KEY", None)
            else:
                os.environ["RAG_SHIELD_LOG_KEY"] = previous_key
    return rows


def corpus_unchanged() -> dict:
    """The project's own trust labels must be identical with and without enforcement."""
    settings = load_settings()

    def labels():
        registry = load_registry(settings.registry_path)
        return {p.relative_to(settings.data_dir).as_posix():
                load_document(p, settings.data_dir, registry).trust_classification
                for p in sorted(settings.data_dir.rglob("*"))
                if p.is_file() and p.suffix in (".md", ".txt", ".pdf")
                and "quarantined" not in p.parts}
    signed = labels()
    saved = dict(signoff.ENFORCED)
    signoff.ENFORCED.clear()
    try:
        hash_only = labels()
    finally:
        signoff.ENFORCED.update(saved)
    return {"documents": len(signed), "identical": signed == hash_only,
            "differences": {k: [hash_only.get(k), v] for k, v in signed.items()
                            if hash_only.get(k) != v}}


def main() -> None:
    report = {
        "_note": "Fictional simulation. Expected outcomes were written down before running.",
        "approval_attacks": approval_attacks(),
        "legitimate_update": legitimate_update(),
        "log_attacks": log_attacks(),
        "project_corpus_labels_unchanged": corpus_unchanged(),
    }
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for row in report["approval_attacks"]:
        print(f"{row['attack']:24} hash-only: {'ATTACKER WINS' if row['attacker_wins_hash_only'] else 'stopped':13} "
              f"signed: {'ATTACKER WINS' if row['attacker_wins_signed'] else 'stopped':13} "
              f"{'' if row['as_expected'] else 'UNEXPECTED'}")
    print(f"legitimate update: {report['legitimate_update']}")
    for row in report["log_attacks"]:
        print(f"log {row['attack']:22} {'detected' if row['detected'] else 'MISSED'}: {row['first_problem']}")
    print(f"project corpus: {report['project_corpus_labels_unchanged']}")
    print(f"\nwrote {OUTPUT.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
