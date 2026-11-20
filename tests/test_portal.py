import pytest

from portal import server
from tests.conftest import FakeLLM


@pytest.fixture
def portal(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "WORK_DIR", tmp_path / "portal")
    p = server.Portal()
    p.pipeline.llm = FakeLLM("Notify within 15 minutes [DOC-003].")
    return p


def test_attacks_and_reset_stay_in_the_disposable_copy(portal):
    original = (portal.source / server.PROCEDURE).read_text()
    portal.upload_bulletin()
    portal.tamper_procedure()
    state = portal.state()
    assert (state["bulletin"], state["procedure"]) == ("live", "tampered")
    assert (portal.source / server.PROCEDURE).read_text() == original
    assert not (portal.source / server.BULLETIN).exists()
    portal.reset()
    state = portal.state()
    assert (state["bulletin"], state["procedure"], state["alerts"]) == ("absent", "original", [])


def test_shield_blocks_and_quarantines_the_fake_bulletin(portal):
    portal.upload_bulletin()
    data = portal.ask("How quickly must I notify the Shift Supervisor after a Band Amber alert?", True)
    assert data["shield"] and any("conflicts with" in r for b in data["blocked"] for r in b["reasons"])
    assert portal.state()["bulletin"] == "quarantined"


def test_tampering_is_refused_while_the_procedure_is_missing(portal):
    (portal.settings.data_dir / server.PROCEDURE).unlink()  # quarantined, nothing restored
    with pytest.raises(ValueError, match="Reset"):
        portal.tamper_procedure()


def test_restored_procedure_can_be_attacked_again(portal):
    portal.tamper_procedure()
    portal.ask("How quickly must I notify the Shift Supervisor after a Band Amber alert?", True)
    portal.tamper_procedure()
    assert portal.state()["procedure"] == "tampered"


def test_uploaded_documents_are_untrusted_and_names_are_sanitized(portal):
    saved = portal.upload("../../etc/CX-7 notes!", "# Notes\n\nAll normal.")
    assert saved == "untrusted/cx_7_notes.md"  # any directory part is dropped
    shared = [d for d in portal.state()["documents"] if d["shared"]]
    assert shared and shared[0]["trust"] == "untrusted"
    assert portal.document(shared[0]["doc_id"])["text"].startswith("# Notes")


@pytest.mark.parametrize("name,text", [("", "x"), ("a", "  "), ("a", "x" * 20_001)])
def test_bad_uploads_are_refused(portal, name, text):
    with pytest.raises(ValueError):
        portal.upload(name, text)


def test_fact_check_flags_the_false_rule(portal):
    portal.pipeline.llm = FakeLLM("Notify the Shift Supervisor within 4 hours [DOC-003].")
    data = portal.ask("How quickly must I notify the Shift Supervisor after a Band Amber alert?", False)
    assert data["fact_check"] and data["fact_check"][0]["claim"] == "4 hours"


def test_after_restore_the_document_shows_the_signed_text(portal):
    portal.tamper_procedure()
    portal.ask("How quickly must I notify the Shift Supervisor after a Band Amber alert?", True)
    assert server.REAL_RULE in portal.document("DOC-003")["text"]


def test_quarantined_document_is_not_readable(portal):
    portal.upload_bulletin()
    portal.ask("How quickly must I notify the Shift Supervisor after a Band Amber alert?", True)
    shared = [d["doc_id"] for d in portal.state()["documents"] if d["shared"]]
    assert not shared
    with pytest.raises(LookupError):
        portal.document("UNREG-048dd00f")


def test_shield_restores_the_signed_procedure_and_answers(portal):
    portal.tamper_procedure()
    data = portal.ask("How quickly must I notify the Shift Supervisor after a Band Amber alert?", True)
    assert data["status"] == "answered" and "DOC-003" in [r["doc_id"] for r in data["restored"]]
    assert any(w.startswith('Conflict: DOC-003 says "4 hours"') for w in data["warnings"])
    assert portal.state()["procedure"] == "restored"
    assert server.REAL_RULE in (portal.settings.data_dir / server.PROCEDURE).read_text()


def test_insider_attack_edits_every_procedure_behind_the_suggested_questions(portal):
    portal.tamper_procedure()
    state = portal.state()
    assert state["procedure"] == "tampered"
    assert state["procedures_edited"] == state["procedures_total"] == len(server.TAMPERS) == 5
    for name, pairs in server.TAMPERS.items():
        text = (portal.settings.data_dir / name).read_text()
        assert all(fake in text and real not in text for real, fake in pairs), name


def test_shield_restores_every_edited_procedure(portal):
    portal.tamper_procedure()
    data = portal.ask("How quickly must I notify the Shift Supervisor after a Band Amber alert?", True)
    restored = {r["doc_id"] for r in data["restored"]}
    assert "DOC-003" in restored and data["status"] == "answered"
    assert any('Conflict: DOC-003 says "4 hours"' in c for c in data["conflicts"])


def test_conflict_lines_read_naturally():
    lines = server.conflict_lines([
        {"doc_id": "DOC-005", "fact_id": "F-ASSEMBLY", "claim": "d", "approved_source": "DOC-005",
         "approved_statement": "Personnel go to Assembly Point B."}] * 2)
    assert lines == ['Conflict: DOC-005 says "Assembly Point D", but approved DOC-005 states: '
                     'Personnel go to Assembly Point B.']


def test_each_scenario_edits_only_its_own_procedures(portal):
    portal.tamper_procedure("assembly")
    statuses = {s["key"]: s["status"] for s in portal.state()["scenarios"]}
    assert statuses == {"notify": "original", "w217": "original", "assembly": "tampered",
                        "rounds": "original"}
    with pytest.raises(ValueError):
        portal.tamper_procedure("nope")


def test_answer_shows_only_what_pertains_to_the_question(portal):
    portal.tamper_procedure("all")
    q1 = server.SCENARIOS["notify"]["question"]
    data = portal.ask(q1, True)
    assert data["conflicts"] and all("4 hours" in c for c in data["conflicts"])
    assert {r["doc_id"] for r in data["restored"]} <= {"DOC-003"}
    assert {b["doc_id"] for b in data["blocked"]} <= {"DOC-003"}
    later = portal.ask(server.SCENARIOS["assembly"]["question"], True)
    assert all("Assembly Point" in c for c in later["earlier_conflicts"] + later["conflicts"])
    assert not any("4 hours" in c for c in later["earlier_conflicts"] + later["conflicts"])


def test_typed_questions_keep_conflicts_whose_topic_they_mention(portal):
    facts, docs = portal._relevance("Do I radio the Shift Supervisor and notify them?")
    assert "F-NOTIFY-TIME" in facts and docs is None
