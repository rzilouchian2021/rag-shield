"""Uses the real embedding model and a real temporary ChromaDB index."""
from dataclasses import replace

import pytest

from config.settings import PROJECT_ROOT, Settings
from src.ingestion import load_corpus
from src.llm_client import AnthropicClient, LLMError, OllamaClient
from src.logging_utils import read_events
from src.rag_pipeline import RAGPipeline, extract_citations
from src.retriever import RetrievedChunk
from tests.conftest import FakeLLM


@pytest.fixture
def pipeline(settings):
    (settings.data_dir / "untrusted" / "fruit.md").write_text(
        "# Fruit\n\nApples are harvested in autumn from orchards.")
    (settings.data_dir / "untrusted" / "alert.md").write_text(
        "# Alerts\n\nAlert W-217 means vibration drift and needs escalation.")
    p = RAGPipeline(settings, llm=FakeLLM())
    p.sync()
    return p


def test_most_relevant_document_ranks_first(pipeline):
    chunks = pipeline.retriever.retrieve("What does alert W-217 mean?", top_k=2)
    assert chunks[0].metadata["filename"] == "untrusted/alert.md"
    assert chunks[0].similarity > chunks[1].similarity


def test_empty_index_returns_nothing(settings):
    assert RAGPipeline(settings, llm=FakeLLM()).retriever.retrieve("anything") == []


def test_sync_handles_unchanged_changed_new_and_deleted(pipeline, settings):
    untrusted = settings.data_dir / "untrusted"
    assert pipeline.sync()[0].unchanged == 2
    (untrusted / "fruit.md").write_text("# Fruit\n\nPears ripen indoors after picking.")
    (untrusted / "new.md").write_text("# New\n\nA new document.")
    (untrusted / "alert.md").unlink()
    report = pipeline.sync()[0]
    # An unregistered file's ID derives from its hash, so an edit is remove + add.
    assert (report.added, report.removed) == (2, 2)
    texts = pipeline.store.collection.get()["documents"]
    assert any("Pears" in t for t in texts)
    assert not any("Apples" in t or "W-217" in t for t in texts)


def test_quarantined_files_are_never_indexed(pipeline, settings):
    (settings.data_dir / "quarantined" / "bad.md").write_text("# Bad\n\nQuarantined zebra text.")
    pipeline.sync()
    assert not any("zebra" in t for t in pipeline.store.collection.get()["documents"])


def test_answer_uses_retrieved_context_and_logs_without_question_text(pipeline, settings):
    result = pipeline.answer("Explain confidential W-217 alert")
    assert "Alert W-217 means vibration drift" in pipeline.llm.user_prompt
    assert result.chunks
    event = read_events(settings.log_path)[0]
    assert event["query_id"] == result.query_id and event["shield_mode"] == "baseline"
    assert "confidential" not in settings.log_path.read_text()


def test_baseline_prompt_gives_no_trust_signals(pipeline):
    pipeline.answer("Explain alert W-217")
    assert "untrusted" not in pipeline.llm.user_prompt.lower()


@pytest.mark.parametrize("question", ["", "   ", "x" * 2001])
def test_invalid_questions_rejected(pipeline, question):
    with pytest.raises(ValueError):
        pipeline.answer(question)


def test_citations_are_checked_against_retrieved_sources():
    chunk = RetrievedChunk(1, "c", "t", 0.5, {"doc_id": "DOC-001", "trust_classification": "approved"})
    assert extract_citations("[DOC-001] and [DOC-099], [DOC-001]", [chunk]) == (["DOC-001"], ["DOC-099"])


def test_synthetic_corpus_is_fully_approved():
    project = Settings(data_dir=PROJECT_ROOT / "data",
                       registry_path=PROJECT_ROOT / "config" / "document_registry.json")
    documents, errors = load_corpus(project)
    approved = [d for d in documents if d.filename.startswith("approved/")]
    assert not errors and len(approved) == 6
    assert all(d.trust_classification == "approved" for d in approved)


def test_ollama_connection_failure_is_a_clear_error():
    settings = replace(Settings(), ollama_url="http://127.0.0.1:9")
    with pytest.raises(LLMError, match="Cannot reach Ollama"):
        OllamaClient(settings).generate("s", "u")


def test_anthropic_requires_key_and_never_shows_it(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMError, match="not set"):
        AnthropicClient(Settings())

    class Rejected:
        ok, status_code = False, 401
    monkeypatch.setenv("ANTHROPIC_API_KEY", "secret-value")
    monkeypatch.setattr("src.llm_client.requests.post", lambda *a, **k: Rejected())
    with pytest.raises(LLMError) as caught:
        AnthropicClient(Settings()).generate("s", "u")
    assert "secret-value" not in str(caught.value)


def test_extraction_change_reindexes_even_when_file_hash_is_unchanged(pipeline):
    documents, _ = load_corpus(pipeline.settings)
    documents[0].text += " extra"
    report = pipeline.store.sync(documents)
    assert report.updated == 1 and report.unchanged == 1


def test_malformed_citation_is_reported_as_invalid():
    chunk = RetrievedChunk(1, "c", "t", 0.5, {"doc_id": "UNREG-d58f6fe0", "trust_classification": "untrusted"})
    assert extract_citations("[UNREG-d58f6e0]", [chunk]) == ([], ["UNREG-d58f6e0"])
