"""Signed, two-person sign-off for approved procedures, and the keys behind it.

A registry entry that says "approved" is not enough on its own. For a registry
listed in ENFORCED, a procedure counts as approved only when:

1. at least `min_signatures` different approvers signed the exact file hash and
   version with Ed25519 (the two-person rule),
2. at least one of them belongs to the team that owns the document,
3. every signing key is listed and active in the keyring, and
4. the keyring itself is signed by the document-control trust root.

Anyone can recompute a SHA-256 hash, so a hash alone can't stop someone who can
edit both a file and the registry. A signature can only be made with the
approver's private key, and the Shield holds public keys only, so it can check
approvals but never make one.

Enforcement fails closed: if the keyring or trust root is missing or invalid,
nothing in that registry counts as approved.

Private keys live in keys/ (git-ignored), encrypted with a passphrase. This
stands in for a hardware token or key vault, one per approver. A demo uses one
shared passphrase for convenience; in practice each approver holds their own.

Run:  python -m src.signoff status
      python -m src.signoff sign approved/file.md --as ops-manager
      python -m src.signoff init-demo            set up demo keys and sign the corpus
      python -m src.signoff add-approver ID --name N --role R --teams "Team A,Team B"
      python -m src.signoff rotate-key ID | revoke ID [--key KEY_ID]
      python -m src.signoff verify-log | access | lock | unlock
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)

from config.settings import PROJECT_ROOT

KEYS_DIR = PROJECT_ROOT / "keys"
PASSPHRASE_ENV = "RAG_SHIELD_KEY_PASSPHRASE"
SIGNOFF_PURPOSE = "rag-shield-signoff-v1"
KEYRING_PURPOSE = "rag-shield-keyring-v1"
STATUS_UNSIGNED = "unsigned"              # claims approval, lacks a valid quorum
STATUS_UNVERIFIABLE = "signoff_unverifiable"  # keyring or trust root is missing or invalid


@dataclass(frozen=True)
class Policy:
    keyring_path: Path
    root_path: Path


# Registries whose approvals must be signed. Pinned in code, so deleting the
# keyring or stripping signatures can't switch enforcement off.
ENFORCED: dict[Path, Policy] = {
    (PROJECT_ROOT / "config" / "document_registry.json").resolve(): Policy(
        PROJECT_ROOT / "config" / "approvers.json", PROJECT_ROOT / "config" / "trust_root.pub"),
    # The gas-leak demo knowledge base (data/kb), signed by the same approvers.
    (PROJECT_ROOT / "config" / "kb_registry.json").resolve(): Policy(
        PROJECT_ROOT / "config" / "approvers.json", PROJECT_ROOT / "config" / "trust_root.pub"),
}


def enforce(registry_path: Path, keyring_path: Path, root_path: Path) -> None:
    """Require signatures for another registry (used by validation and tests)."""
    ENFORCED[Path(registry_path).resolve()] = Policy(Path(keyring_path), Path(root_path))


def policy_for(registry_path: Path) -> Policy | None:
    return ENFORCED.get(Path(registry_path).resolve())


# --- Encoding helpers ----------------------------------------------------------

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public_key_b64: str) -> str:
    """Short fingerprint of a public key, used to name it."""
    return hashlib.sha256(base64.b64decode(public_key_b64)).hexdigest()[:16]


def load_public(b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --- Keyring -------------------------------------------------------------------

@dataclass
class Keyring:
    ok: bool
    approvers: dict[str, dict] = field(default_factory=dict)
    min_signatures: int = 2
    owner_team_required: bool = True
    root_key_id: str = ""
    problem: str = ""


def keyring_payload(data: dict) -> bytes:
    return canonical({"purpose": KEYRING_PURPOSE, "policy": data.get("policy", {}),
                      "approvers": data.get("approvers", [])})


def load_keyring(policy: Policy) -> Keyring:
    """Verify the keyring against the trust root. Any failure leaves it unusable."""
    try:
        root_b64 = policy.root_path.read_text(encoding="utf-8").strip()
        root = load_public(root_b64)
    except (OSError, ValueError) as exc:
        return Keyring(False, problem=f"trust root unreadable ({type(exc).__name__})")
    try:
        data = json.loads(policy.keyring_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return Keyring(False, root_key_id=key_id(root_b64),
                       problem=f"keyring unreadable ({type(exc).__name__})")
    try:
        root.verify(base64.b64decode(data.get("root_signature", "")), keyring_payload(data))
    except (InvalidSignature, ValueError):
        return Keyring(False, root_key_id=key_id(root_b64),
                       problem="keyring is not signed by the trust root (edited or replaced)")
    policy_data = data.get("policy", {})
    return Keyring(True, {a["id"]: a for a in data.get("approvers", [])},
                   int(policy_data.get("min_signatures", 2)),
                   bool(policy_data.get("owner_team_required", True)), key_id(root_b64))


def save_keyring(policy: Policy, data: dict, root_key: Ed25519PrivateKey) -> None:
    data["root_signature"] = _b64(root_key.sign(keyring_payload(data)))
    _write_json(policy.keyring_path, data)


# --- Verifying a registry entry ------------------------------------------------

ACCESS_FIELDS = ("allowed_roles", "site", "sensitivity")


def signoff_payload(entry: dict, signature: dict) -> bytes:
    """What an approver signs. Access fields are covered too, so editing who may read a
    document (or which station it belongs to) breaks the signatures. Entries without
    access fields sign exactly what they did before."""
    payload = {"purpose": SIGNOFF_PURPOSE, "doc_id": entry.get("doc_id"),
               "filename": entry.get("filename"), "sha256": signature.get("sha256"),
               "version": signature.get("version"), "approver": signature.get("approver"),
               "key_id": signature.get("key_id"), "signed_at": signature.get("signed_at")}
    access = {k: entry[k] for k in ACCESS_FIELDS if k in entry}
    if access:
        payload["access"] = access
    return canonical(payload)


@dataclass
class SignoffResult:
    ok: bool
    sha256: str = ""
    signers: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    registry_hash_edited: bool = False


def verify_entry(entry: dict, keyring: Keyring) -> SignoffResult:
    if not keyring.ok:
        return SignoffResult(False, problems=[keyring.problem])
    by_hash: dict[str, dict[str, dict]] = {}
    problems = []
    for sig in entry.get("signatures", []):
        who = sig.get("approver", "?")
        approver = keyring.approvers.get(who)
        if approver is None:
            problems.append(f"signature from {who}, who is not in the keyring")
            continue
        key = next((k for k in approver.get("keys", []) if k.get("key_id") == sig.get("key_id")), None)
        if approver.get("status") != "active" or key is None or key.get("status") != "active":
            problems.append(f"{who}'s signing key is revoked or unknown")
            continue
        if sig.get("version") != entry.get("version"):
            problems.append(f"{who} signed version {sig.get('version')}, not {entry.get('version')}")
            continue
        try:
            load_public(key["public_key"]).verify(base64.b64decode(sig.get("signature", "")),
                                                  signoff_payload(entry, sig))
        except (InvalidSignature, ValueError):
            problems.append(f"invalid signature claiming to be from {who}")
            continue
        by_hash.setdefault(sig["sha256"], {})[who] = sig

    owner = entry.get("owner", "")

    def quorum(signers: dict[str, dict]) -> list[str]:
        missing = []
        if len(signers) < keyring.min_signatures:
            missing.append(f"needs {keyring.min_signatures} approvers, has {len(signers)}")
        if keyring.owner_team_required and not any(
                owner in keyring.approvers[w].get("teams", []) for w in signers):
            missing.append(f"no signature from the owning team ({owner})")
        return missing

    complete = [(max(s["signed_at"] for s in signers.values()), digest, signers)
                for digest, signers in by_hash.items() if not quorum(signers)]
    if complete:
        _, digest, signers = max(complete)
        return SignoffResult(True, digest, sorted(signers), problems,
                             registry_hash_edited=entry.get("sha256") != digest)
    best = max(by_hash.values(), key=len, default={})
    return SignoffResult(False, signers=sorted(best), problems=problems + quorum(best))


def apply(registry_path: Path, entries: dict[str, dict]) -> dict[str, dict]:
    """Effective registry: approval only where the signatures hold up.

    The approved hash is the signed one, so editing the registry's hash to match a
    tampered file still leaves the file mismatched.
    """
    policy = policy_for(registry_path)
    if policy is None:
        return entries
    keyring = load_keyring(policy)
    effective = {}
    for filename, entry in entries.items():
        result = verify_entry(entry, keyring)
        out = {**entry, "signoff": asdict(result)}
        if entry.get("approval_status") == "approved":
            if result.ok:
                out["sha256"] = result.sha256
            else:
                out["approval_status"] = STATUS_UNSIGNED if keyring.ok else STATUS_UNVERIFIABLE
        effective[filename] = out
    return effective


# --- Private keys ----------------------------------------------------------------

def passphrase(confirm: bool = False) -> bytes:
    value = os.environ.get(PASSPHRASE_ENV)
    if value is None:
        if not sys.stdin.isatty():
            raise SystemExit(f"Set {PASSPHRASE_ENV} or run this in a terminal to enter the passphrase.")
        value = getpass.getpass("Key passphrase: ")
        if confirm and getpass.getpass("Repeat passphrase: ") != value:
            raise SystemExit("Passphrases did not match.")
    if len(value) < 8:
        raise SystemExit("Use a passphrase of at least 8 characters.")
    return value.encode("utf-8")


def private_key_path(name: str, keys_dir: Path = KEYS_DIR) -> Path:
    return keys_dir / f"{name}.pem"


def save_private_key(key: Ed25519PrivateKey, path: Path, secret: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(secret))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)


def load_private_key(path: Path, secret: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=secret)
    except FileNotFoundError:
        raise SystemExit(f"No private key at {path}. Only its holder can sign.") from None
    except (ValueError, TypeError):
        raise SystemExit(f"Could not unlock {path.name}: wrong passphrase or damaged key.") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path.name} is not an Ed25519 key.")
    return key


def new_key_record(key: Ed25519PrivateKey) -> dict:
    pub = _b64(public_bytes(key.public_key()))
    return {"key_id": key_id(pub), "public_key": pub, "status": "active", "created": _now()}


# --- Signing ---------------------------------------------------------------------

def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    try:
        os.replace(tmp, path)
    except PermissionError:
        tmp.unlink(missing_ok=True)
        raise


def sign_document(registry_path: Path, data_dir: Path, filename: str, approver_id: str,
                  key: Ed25519PrivateKey) -> dict:
    """Add one approver's signature over the file's current hash and the entry's version."""
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    entry = next((e for e in data["documents"] if e["filename"] == filename), None)
    if entry is None:
        raise ValueError(f"{filename} is not in the registry")
    digest = hashlib.sha256((data_dir / filename).read_bytes()).hexdigest()
    if entry.get("sha256") != digest:
        raise ValueError(f"{filename} differs from the hash recorded for review. Record it "
                         f"first: python -m src.ingestion --approve {filename}")
    pub = _b64(public_bytes(key.public_key()))
    record = {"approver": approver_id, "key_id": key_id(pub), "sha256": digest,
              "version": entry["version"], "signed_at": _now()}
    record["signature"] = _b64(key.sign(signoff_payload(entry, record)))
    entry["signatures"] = [s for s in entry.get("signatures", [])
                           if not (s.get("approver") == approver_id
                                   and s.get("version") == entry["version"])] + [record]
    _write_json(registry_path, data)
    return record


# --- Status, access checks ------------------------------------------------------

def status_rows(registry_path: Path) -> list[dict]:
    from src.ingestion import load_registry  # avoid a cycle at import time
    policy = policy_for(registry_path)
    keyring = load_keyring(policy) if policy else None
    names = {i: a.get("name", i) for i, a in (keyring.approvers.items()
                                                                     if keyring else [])}
    rows = []
    for filename, entry in load_registry(registry_path).items():
        result = entry.get("signoff") or {}
        rows.append({"doc_id": entry.get("doc_id"), "owner": entry.get("owner"),
                     "signed_off": bool(result.get("ok")),
                     "signers": ", ".join(names.get(s, s) for s in result.get("signers", [])),
                     "problems": "; ".join(result.get("problems", [])), "filename": filename})
    return rows


def keyring_summary(registry_path: Path) -> dict:
    policy = policy_for(registry_path)
    if policy is None:
        return {"enforced": False}
    keyring = load_keyring(policy)
    return {"enforced": True, "ok": keyring.ok, "problem": keyring.problem,
            "root_key_id": keyring.root_key_id, "min_signatures": keyring.min_signatures,
            "owner_team_required": keyring.owner_team_required,
            "approvers": [{"id": a["id"], "name": a.get("name"), "role": a.get("role"),
                           "teams": ", ".join(a.get("teams", [])), "status": a.get("status"),
                           "active_keys": sum(k.get("status") == "active" for k in a.get("keys", []))}
                          for a in keyring.approvers.values()]}


def protected_paths(settings) -> list[tuple[str, Path]]:
    policy = policy_for(settings.registry_path)
    paths = [("Registry", settings.registry_path), ("Authoritative facts", settings.facts_path)]
    if policy:
        paths += [("Keyring", policy.keyring_path), ("Trust root", policy.root_path)]
    approved = settings.data_dir / "approved"
    if approved.is_dir():
        paths += [("Approved procedure", p) for p in sorted(approved.iterdir()) if p.is_file()]
    return paths


def access_audit(settings) -> list[dict]:
    """What the assistant's own account can change. It should be able to change none of it."""
    def shown(p: Path) -> str:
        return str(p.relative_to(PROJECT_ROOT)) if p.is_relative_to(PROJECT_ROOT) else str(p)

    rows = []
    for label, p in protected_paths(settings):
        issue = ("missing" if not p.exists() else
                 "the assistant's account can modify it" if os.access(p, os.W_OK) else "")
        rows.append({"item": label, "path": shown(p), "ok": not issue, "issue": issue})
    if KEYS_DIR.exists():
        mode = stat.S_IMODE(KEYS_DIR.stat().st_mode)
        rows.append({"item": "Private keys", "path": "keys/", "ok": False,
                     "issue": f"stored on the assistant's machine (permissions {oct(mode)}); "
                              "in production they live on each approver's token"})
    return rows


def set_locked(settings, locked: bool) -> int:
    count = 0
    for _, path in protected_paths(settings):
        if path.exists():
            mode = stat.S_IMODE(path.stat().st_mode)
            os.chmod(path, mode & ~0o222 if locked else mode | stat.S_IWUSR)
            count += 1
    return count


# --- Demo setup ------------------------------------------------------------------

DEMO_APPROVERS = [
    ("ops-manager", "Operations Manager", "Approver",
     ["Station Operations", "Operations Document Control"]),
    ("shift-supervisor", "Senior Shift Supervisor", "Approver", ["Station Operations"]),
    ("reliability-lead", "Reliability Engineering Lead", "Approver", ["Reliability Engineering"]),
    ("maintenance-lead", "Maintenance Planning Lead", "Approver", ["Maintenance Planning"]),
    ("safety-officer", "Health and Safety Officer", "Approver", ["Health and Safety"]),
]
# Owner-team approver first, then a second, independent reviewer.
DEMO_SIGNERS = {
    "DOC-001": ("ops-manager", "reliability-lead"),
    "DOC-002": ("reliability-lead", "ops-manager"),
    "DOC-003": ("shift-supervisor", "safety-officer"),
    "DOC-004": ("maintenance-lead", "ops-manager"),
    "DOC-005": ("safety-officer", "ops-manager"),
    "DOC-006": ("reliability-lead", "maintenance-lead"),
}


def init_demo(registry_path: Path, data_dir: Path, force: bool = False) -> dict:
    policy = policy_for(registry_path)
    if policy is None:
        raise SystemExit("This registry is not under sign-off enforcement.")
    if policy.root_path.exists() and not force:
        raise SystemExit("A trust root already exists. Use --force to replace every demo key.")
    secret = passphrase(confirm=True)
    root = Ed25519PrivateKey.generate()
    save_private_key(root, private_key_path("root"), secret)
    approvers, keys = [], {}
    for approver_id, name, role, teams in DEMO_APPROVERS:
        key = Ed25519PrivateKey.generate()
        save_private_key(key, private_key_path(approver_id), secret)
        keys[approver_id] = key
        approvers.append({"id": approver_id, "name": name, "role": role, "teams": teams,
                          "status": "active", "keys": [new_key_record(key)]})
    policy.root_path.write_text(_b64(public_bytes(root.public_key())) + "\n", encoding="utf-8")
    save_keyring(policy, {"_note": "Fictional approvers for a university simulation. Signed by "
                                   "the Operations Document Control trust root.",
                          "policy": {"min_signatures": 2, "owner_team_required": True},
                          "approvers": approvers}, root)
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    for entry in data["documents"]:
        entry.pop("signatures", None)
    _write_json(registry_path, data)
    signed = {}
    for entry in data["documents"]:
        for approver_id in DEMO_SIGNERS.get(entry["doc_id"], ()):
            sign_document(registry_path, data_dir, entry["filename"], approver_id, keys[approver_id])
        signed[entry["doc_id"]] = DEMO_SIGNERS.get(entry["doc_id"], ())
    return signed


def _root_edit(policy: Policy, change) -> None:
    root = load_private_key(private_key_path("root"), passphrase())
    if _b64(public_bytes(root.public_key())) != policy.root_path.read_text(encoding="utf-8").strip():
        raise SystemExit("keys/root.pem does not match the trust root.")
    data = json.loads(policy.keyring_path.read_text(encoding="utf-8"))
    change(data)
    save_keyring(policy, data, root)


def main() -> None:
    from config.settings import load_settings
    from src.logging_utils import verify_log

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    p = sub.add_parser("sign"); p.add_argument("filename"); p.add_argument("--as", dest="approver", required=True)
    p = sub.add_parser("init-demo"); p.add_argument("--force", action="store_true")
    p = sub.add_parser("add-approver"); p.add_argument("id"); p.add_argument("--name", required=True)
    p.add_argument("--role", default="Approver"); p.add_argument("--teams", required=True)
    p = sub.add_parser("rotate-key"); p.add_argument("id")
    p = sub.add_parser("revoke"); p.add_argument("id"); p.add_argument("--key", dest="key_id")
    p = sub.add_parser("verify-log"); p.add_argument("--log", type=Path)
    sub.add_parser("access"); sub.add_parser("lock"); sub.add_parser("unlock")
    args = parser.parse_args()
    settings = load_settings()
    policy = policy_for(settings.registry_path)

    try:
        if args.command == "status":
            print(json.dumps({k: v for k, v in keyring_summary(settings.registry_path).items()
                              if k != "approvers"}, indent=2))
            for row in status_rows(settings.registry_path):
                mark = "SIGNED  " if row["signed_off"] else "UNSIGNED"
                print(f"{mark} {row['doc_id']:8} {row['signers'] or '-'}"
                      + (f"\n         {row['problems']}" if row["problems"] else ""))
        elif args.command == "sign":
            key = load_private_key(private_key_path(args.approver), passphrase())
            record = sign_document(settings.registry_path, settings.data_dir, args.filename,
                                   args.approver, key)
            print(f"{args.approver} signed {args.filename} at {record['sha256'][:12]}")
        elif args.command == "init-demo":
            for doc_id, signers in init_demo(settings.registry_path, settings.data_dir,
                                             args.force).items():
                print(f"{doc_id}: signed by {', '.join(signers) or 'nobody'}")
        elif args.command == "add-approver":
            if private_key_path(args.id).exists():
                raise SystemExit(f"{args.id} already has a key. Use rotate-key.")
            secret = passphrase(confirm=True)
            key = Ed25519PrivateKey.generate()

            def add(data):
                if any(a["id"] == args.id for a in data["approvers"]):
                    raise SystemExit(f"{args.id} is already in the keyring.")
                data["approvers"].append({"id": args.id, "name": args.name, "role": args.role,
                                          "teams": [t.strip() for t in args.teams.split(",")],
                                          "status": "active", "keys": [new_key_record(key)]})
            _root_edit(policy, add)
            save_private_key(key, private_key_path(args.id), secret)
            print(f"added {args.id}")
        elif args.command == "rotate-key":
            secret = passphrase(confirm=True)
            key = Ed25519PrivateKey.generate()
            record = new_key_record(key)

            def rotate(data):
                approver = next(a for a in data["approvers"] if a["id"] == args.id)
                approver["keys"].append(record)
            _root_edit(policy, rotate)
            old = private_key_path(args.id)
            if old.exists():
                old.rename(old.with_name(f"{args.id}.{_now()[:10]}.retired.pem"))
            save_private_key(key, old, secret)
            print(f"new key {record['key_id']} for {args.id}. Re-sign its documents, then "
                  f"revoke the old key with: revoke {args.id} --key OLD_KEY_ID")
        elif args.command == "revoke":
            def revoke(data):
                approver = next(a for a in data["approvers"] if a["id"] == args.id)
                if args.key_id:
                    for k in approver["keys"]:
                        if k["key_id"] == args.key_id:
                            k["status"] = "revoked"
                else:
                    approver["status"] = "revoked"
            _root_edit(policy, revoke)
            print(f"revoked {args.key_id or args.id}. Its signatures no longer count.")
        elif args.command == "verify-log":
            print(json.dumps(verify_log(args.log or settings.log_path), indent=2))
        elif args.command == "access":
            for row in access_audit(settings):
                print(f"{'ok  ' if row['ok'] else 'OPEN'} {row['item']:20} {row['path']}"
                      + (f"  ({row['issue']})" if row["issue"] else ""))
        else:
            count = set_locked(settings, args.command == "lock")
            print(f"{args.command}ed {count} files")
    except PermissionError as exc:
        raise SystemExit(f"{exc.filename} is read-only. Document control must run "
                         "`python -m src.signoff unlock` first.") from None
    except (ValueError, StopIteration) as exc:
        raise SystemExit(str(exc) or "Approver not found.") from None


if __name__ == "__main__":
    main()
