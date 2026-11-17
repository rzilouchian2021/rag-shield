import json

from src.logging_utils import head_path, log_event, verify_log


def write(path, n=5):
    for i in range(n):
        log_event(path, {"event": "test", "n": i})


def lines(path):
    return path.read_text().splitlines()


def test_untouched_log_verifies(tmp_path):
    path = tmp_path / "events.jsonl"
    write(path)
    report = verify_log(path)
    assert report["ok"] and report["sealed"] == 5


def test_edited_entry_is_caught(tmp_path):
    path = tmp_path / "events.jsonl"
    write(path)
    rows = lines(path)
    rows[2] = rows[2].replace('"n": 2', '"n": 99')
    path.write_text("\n".join(rows) + "\n")
    report = verify_log(path)
    assert not report["ok"] and "line 3" in report["problems"][0]


def test_deleted_entry_is_caught(tmp_path):
    path = tmp_path / "events.jsonl"
    write(path)
    rows = lines(path)
    del rows[1]
    path.write_text("\n".join(rows) + "\n")
    assert any("does not follow" in p for p in verify_log(path)["problems"])


def test_truncated_tail_is_caught(tmp_path):
    path = tmp_path / "events.jsonl"
    write(path)
    path.write_text("\n".join(lines(path)[:3]) + "\n")
    assert any("newest entries removed" in p for p in verify_log(path)["problems"])


def test_removed_start_is_caught(tmp_path):
    path = tmp_path / "events.jsonl"
    write(path)
    path.write_text("\n".join(lines(path)[2:]) + "\n")
    assert any("start of the log removed" in p for p in verify_log(path)["problems"])


def test_inserted_unsealed_entry_is_caught(tmp_path):
    path = tmp_path / "events.jsonl"
    write(path)
    rows = lines(path)
    rows.insert(2, json.dumps({"event": "alert", "kind": "fake"}))
    path.write_text("\n".join(rows) + "\n")
    assert any("unsealed entry added" in p for p in verify_log(path)["problems"])


def test_recomputed_plain_hashes_do_not_help_without_the_key(tmp_path):
    """An attacker who rewrites an entry and forges a seal without the key is caught."""
    import hashlib
    path = tmp_path / "events.jsonl"
    write(path)
    rows = lines(path)
    record = json.loads(rows[-1])
    record["n"] = 42
    record.pop("chain_mac")
    record["chain_mac"] = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
    rows[-1] = json.dumps(record)
    path.write_text("\n".join(rows) + "\n")
    assert not verify_log(path)["ok"]


def test_deleted_head_is_caught_and_writing_continues_with_a_restart(tmp_path):
    path = tmp_path / "events.jsonl"
    write(path)
    head_path(path).unlink()
    assert not verify_log(path)["ok"]
    write(path, 1)
    assert any("chain restarted" in p for p in verify_log(path)["problems"])


def test_legacy_unsealed_entries_before_sealing_are_counted_not_flagged(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"event": "old"}) + "\n")
    write(path, 2)
    report = verify_log(path)
    assert report["ok"] and report["unsealed_before_sealing"] == 1


def test_seal_fields_in_an_event_cannot_override_the_chain(tmp_path):
    path = tmp_path / "events.jsonl"
    log_event(path, {"event": "x", "chain_prev": "spoof", "chain_mac": "spoof"})
    assert verify_log(path)["ok"]
