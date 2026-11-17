import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from config.settings import PROJECT_ROOT
from src import signoff
from src.ingestion import (TRUST_APPROVED, TRUST_MODIFIED, TRUST_UNAPPROVED, load_document,
                           load_registry, sha256_bytes)

TEAMS = {"owner-a": ["Station Operations"], "owner-b": ["Station Operations"],
         "reviewer": ["Health and Safety"], "outsider": ["Maintenance Planning"]}


@pytest.fixture
def world(settings, monkeypatch):
    """A signed registry with one approved procedure, under enforcement."""
    monkeypatch.setattr(signoff, "ENFORCED", {})
    keys = {name: Ed25519PrivateKey.generate() for name in [*TEAMS, "root"]}
    keyring_path, root_path = settings.registry_path.with_name("approvers.json"), \
        settings.registry_path.with_name("root.pub")
    root_path.write_text(signoff._b64(signoff.public_bytes(keys["root"].public_key())))
    policy = signoff.Policy(keyring_path, root_path)
    signoff.save_keyring(policy, {"policy": {"min_signatures": 2, "owner_team_required": True},
                                  "approvers": [{"id": n, "name": n, "teams": t, "status": "active",
                                                 "keys": [signoff.new_key_record(keys[n])]}
                                                for n, t in TEAMS.items()]}, keys["root"])
    doc = settings.data_dir / "approved" / "proc.md"
    doc.write_text("# Escalation\n\nNotify the Shift Supervisor within 15 minutes.\n")
    settings.registry_path.write_text(json.dumps({"documents": [{
        "doc_id": "DOC-900", "filename": "approved/proc.md", "source": "s",
        "owner": "Station Operations", "approval_status": "approved", "version": "1.0",
        "upload_timestamp": "t", "sha256": sha256_bytes(doc.read_bytes())}]}))
    signoff.enforce(settings.registry_path, keyring_path, root_path)

    def sign(*names):
        for n in names:
            signoff.sign_document(settings.registry_path, settings.data_dir, "approved/proc.md",
                                  n, keys[n])

    def trust():
        return load_document(doc, settings.data_dir, load_registry(settings.registry_path)).trust_classification

    def edit_registry(change):
        data = json.loads(settings.registry_path.read_text())
        change(data["documents"][0])
        settings.registry_path.write_text(json.dumps(data))

    return {"keys": keys, "policy": policy, "doc": doc, "sign": sign, "trust": trust,
            "edit_registry": edit_registry}


def test_owner_plus_reviewer_is_approved(world):
    world["sign"]("owner-a", "reviewer")
    assert world["trust"]() == TRUST_APPROVED


@pytest.mark.parametrize("signers", [(), ("owner-a",), ("reviewer", "outsider")])
def test_one_signature_or_no_owner_team_is_not_approved(world, signers):
    world["sign"](*signers)
    assert world["trust"]() == TRUST_UNAPPROVED


def test_same_approver_twice_counts_once(world):
    world["sign"]("owner-a", "owner-a")
    assert world["trust"]() == TRUST_UNAPPROVED


def test_editing_file_and_registry_hash_is_still_caught(world):
    world["sign"]("owner-a", "reviewer")
    world["doc"].write_text("# Escalation\n\nNotify the Shift Supervisor within 4 hours.\n")
    new = sha256_bytes(world["doc"].read_bytes())
    world["edit_registry"](lambda e: e.update(sha256=new))
    assert world["trust"]() == TRUST_MODIFIED


def test_signature_from_a_key_outside_the_keyring_does_not_count(world):
    world["sign"]("owner-a")
    forger = Ed25519PrivateKey.generate()
    signoff.sign_document(world["policy"].keyring_path.with_name("registry.json"),
                          world["doc"].parent.parent, "approved/proc.md", "reviewer", forger)
    assert world["trust"]() == TRUST_UNAPPROVED


def test_adding_a_key_to_the_keyring_without_the_root_fails_closed(world):
    world["sign"]("owner-a", "reviewer")
    data = json.loads(world["policy"].keyring_path.read_text())
    data["approvers"].append({"id": "mallory", "name": "m", "teams": ["Station Operations"],
                              "status": "active", "keys": []})
    world["policy"].keyring_path.write_text(json.dumps(data))
    assert world["trust"]() == TRUST_UNAPPROVED  # even the genuinely signed document
    entry = next(iter(load_registry(world["policy"].keyring_path.with_name("registry.json")).values()))
    assert entry["approval_status"] == signoff.STATUS_UNVERIFIABLE


def test_missing_keyring_fails_closed(world):
    world["sign"]("owner-a", "reviewer")
    world["policy"].keyring_path.unlink()
    assert world["trust"]() == TRUST_UNAPPROVED


def test_revoked_approver_no_longer_counts(world):
    world["sign"]("owner-a", "reviewer")
    data = json.loads(world["policy"].keyring_path.read_text())
    next(a for a in data["approvers"] if a["id"] == "reviewer")["status"] = "revoked"
    signoff.save_keyring(world["policy"], data, world["keys"]["root"])
    assert world["trust"]() == TRUST_UNAPPROVED
    world["sign"]("owner-b")  # a second valid signer restores the quorum
    assert world["trust"]() == TRUST_APPROVED


def test_version_bump_needs_fresh_signatures(world):
    world["sign"]("owner-a", "reviewer")
    world["edit_registry"](lambda e: e.update(version="1.1"))
    assert world["trust"]() == TRUST_UNAPPROVED


def test_tampered_signature_bytes_are_rejected(world):
    world["sign"]("owner-a", "reviewer")

    def flip(entry):
        sig = bytearray(base64.b64decode(entry["signatures"][0]["signature"]))
        sig[0] ^= 1
        entry["signatures"][0]["signature"] = base64.b64encode(bytes(sig)).decode()
    world["edit_registry"](flip)
    assert world["trust"]() == TRUST_UNAPPROVED


def test_registry_hash_edit_alone_is_flagged_but_file_stays_approved(world):
    world["sign"]("owner-a", "reviewer")
    world["edit_registry"](lambda e: e.update(sha256="0" * 64))
    entry = next(iter(load_registry(world["policy"].keyring_path.with_name("registry.json")).values()))
    assert world["trust"]() == TRUST_APPROVED and entry["signoff"]["registry_hash_edited"]


def test_signing_refuses_a_file_that_differs_from_the_recorded_hash(world):
    world["doc"].write_text("changed")
    with pytest.raises(ValueError, match="differs"):
        world["sign"]("owner-a")


def test_unenforced_registries_are_unchanged(settings, monkeypatch):
    monkeypatch.setattr(signoff, "ENFORCED", {})
    settings.registry_path.write_text(json.dumps({"documents": [
        {"filename": "approved/x.md", "approval_status": "approved", "sha256": "a"}]}))
    assert load_registry(settings.registry_path)["approved/x.md"] == {
        "filename": "approved/x.md", "approval_status": "approved", "sha256": "a"}


def test_project_registry_is_enforced_and_fully_signed():
    registry = PROJECT_ROOT / "config" / "document_registry.json"
    assert signoff.policy_for(registry) is not None
    rows = signoff.status_rows(registry)
    assert rows and all(r["signed_off"] for r in rows), rows


def test_no_private_key_material_is_committed():
    for path in (PROJECT_ROOT / "config").iterdir():
        if path.is_file():
            assert "PRIVATE KEY" not in path.read_text(encoding="utf-8", errors="ignore"), path
    assert "keys/" in (PROJECT_ROOT / ".gitignore").read_text()


def test_scan_alerts_on_lost_signoff_and_broken_log(world, settings):
    from src.logging_utils import log_event
    from src.monitoring import ScanReport, alerts, check_signoff_and_log
    world["sign"]("owner-a")  # only one approver
    log_event(settings.log_path, {"event": "x"})
    rows = settings.log_path.read_text().replace('"x"', '"y"')
    settings.log_path.write_text(rows)
    report = ScanReport("now", 1)
    check_signoff_and_log(settings, report)
    kinds = {a["kind"] for a in alerts(settings.log_path)}
    assert {"signoff_invalid", "log_tampered"} <= kinds
    assert report.unsigned and not report.log_check["ok"]


def test_procedure_status_explains_missing_signoff(world, settings):
    from src.monitoring import procedure_status
    world["sign"]("owner-a")
    row = procedure_status(settings)[0]
    assert not row["verified"] and "needs 2 approvers" in row["problems"][0]
