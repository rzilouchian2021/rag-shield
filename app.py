"""Streamlit dashboard for the RAG Shield simulation. Run: streamlit run app.py"""
from __future__ import annotations

import json
import re
from datetime import datetime

import pandas as pd
import streamlit as st

from config.settings import load_settings
from demo.run_demo import OUTPUT as DEMO_OUTPUT
from demo.run_demo import run as run_demo
from demo.run_drill import OUTPUT as DRILL_OUTPUT
from demo.run_drill import run as run_drill
from evaluation import export_fair
from evaluation import review as verdicts
from evaluation import summarize as summaries
from evaluation.harness import load_cases
from evaluation.charts import ablation_chart, attack_success_chart
from src.ingestion import load_corpus
from src.llm_client import LLMError
from src.logging_utils import read_events
from src.monitoring import (alerts, all_events, governance_metrics, integrity_scan,
                            purge_and_retest, retrieval_concentration)
from src.rag_pipeline import RAGPipeline, RAGResult
from src.shield import ShieldConfig

st.set_page_config(page_title="RAG Shield", layout="wide")

MODE_LABELS = {"baseline": "Baseline (no controls)", "shielded": "RAG Shield"}
COLUMN_LABELS = {
    "doc_id": "Doc ID", "sha256": "SHA-256", "query_id": "Query ID",
    "shield_mode": "Mode", "response_outcome": "Outcome", "withheld_reason": "Withheld because",
    "retrieved_doc_ids": "Retrieved", "context_doc_ids": "Sent to model",
    "detection_results": "Injection flags", "conflicts": "Conflicts",
    "quarantine_actions": "Quarantined", "cited_doc_ids": "Cited",
    "config": "Setup", "attack_category": "Category", "clear_successes": "Clear successes",
    "partial_successes": "Partial", "attack_success_rate": "Attack success",
    "asr_ci_low": "95% CI low", "asr_ci_high": "95% CI high", "false_positives": "False positives",
}
SUMMARY_COLUMNS = ["config", "scenario", "attack_category", "attempts", "correct",
                   "clear_successes", "partial_successes", "attack_success_rate",
                   "asr_ci_low", "asr_ci_high", "detected", "false_positives"]
OUTCOME_TEXT = {
    "adopted": "the answer adopted the poisoned guidance",
    "followed": "the answer followed the injected instruction",
    "mixed": "the answer mixed poisoned and approved guidance",
    "resisted": "the answer kept to approved guidance",
    "suppressed": "the answer was withheld",
    "payload_not_in_context": "the poisoned document never reached the model",
    "omitted": "the answer left out the required escalation",
    "correct": "the answer matched approved guidance",
    "control_also_unsafe": "the clean control answer was also unsafe, so this run is inconclusive",
}
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$:])")
_LINK_MARKUP = re.compile(r"!?\[[^\]]*\]\([^)]*\)|https?://", re.IGNORECASE)


def plain(text) -> str:
    """Escape Markdown so model output and document text show literally.

    Untrusted text must never render as links or remote images: an image tag in a
    poisoned answer would make the browser fetch an outside URL.
    """
    return _MARKDOWN_SPECIAL.sub(r"\\\1", str(text)).replace("\n", "  \n")


def humanize(code: str) -> str:
    return str(code).replace("_", " ")


def when(iso: str) -> str:
    """ISO timestamp to a short UTC reading, e.g. 2026-11-02 02:54 UTC."""
    try:
        return datetime.fromisoformat(str(iso)).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return str(iso)


def outcome_text(outcome: str) -> str:
    return OUTCOME_TEXT.get(outcome, f"scored {humanize(outcome)}")


def _cell(value):
    if isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            return ", ".join(str(item) for item in value)
        return json.dumps(value)
    if isinstance(value, dict):
        return json.dumps(value)
    return value


def table(rows, columns: list[str] | None = None) -> None:
    """A dataframe with readable headers and lists shown as text."""
    frame = pd.DataFrame(rows)
    if columns:
        frame = frame.reindex(columns=columns)
    for column in frame.columns:
        if column == "timestamp" or column.endswith("_at"):
            frame[column] = frame[column].map(lambda v: when(v) if isinstance(v, str) else v)
        elif column in ("attack_success_rate", "asr_ci_low", "asr_ci_high"):
            frame[column] = (frame[column] * 100).round(0)
    for column in frame.columns:  # numeric columns keep their NaN so they stay numeric
        if frame[column].dtype == object:
            frame[column] = frame[column].map(
                lambda v: "" if v is None or (isinstance(v, float) and pd.isna(v)) else _cell(v))
    frame.columns = [COLUMN_LABELS.get(c, c.replace("_", " ").capitalize()) for c in frame.columns]
    st.dataframe(frame, width="stretch", hide_index=True)


@st.cache_resource(show_spinner="Loading the embedding model and index...")
def get_pipeline() -> RAGPipeline:
    pipeline = RAGPipeline(load_settings())
    pipeline.sync()
    return pipeline


def render_answer(result: RAGResult) -> None:
    st.subheader(f"Answer · {MODE_LABELS[result.mode]}")
    for warning in result.warnings:
        st.warning(plain(warning))
    if result.status == "withheld":
        st.error(f"Answer withheld by RAG Shield: {plain(humanize(result.withheld_reason))}.")
    if _LINK_MARKUP.search(result.answer):
        st.warning("The answer contains link or image markup. It is shown as plain text and "
                   "nothing was loaded.")
    st.markdown(plain(result.answer))
    st.caption(f"{result.model} · {result.latency_seconds:.1f}s · query {result.query_id}")
    if result.invalid_citations:
        st.warning(f"The answer cites sources that were not retrieved: "
                   f"{plain(', '.join(result.invalid_citations))}")

    if result.mode == "shielded":
        st.subheader("Document trust decisions")
        table(result.decisions)
        for detection in result.detections:
            with st.expander(f"Injection flag: {detection['doc_id']}, score {detection['score']}"):
                for rule in detection["matched_rules"]:
                    st.markdown(plain(f"{rule['rule']} (+{rule['weight']}): {rule['why']}"))
        for record in result.quarantined:
            st.warning(plain(f"Quarantined {record['original_path']}: {record['reason']}"))

    st.subheader("Sources cited")
    if result.cited_doc_ids:
        titles = {c.doc_id: c.metadata["title"] for c in result.chunks}
        for doc_id in result.cited_doc_ids:
            st.markdown(f"- **{plain(doc_id)}**: {plain(titles[doc_id])}")
    else:
        st.info("The answer did not cite any retrieved source.")

    st.subheader("Chunks used in the answer")
    for chunk in result.chunks:
        label = f"#{chunk.rank} · {chunk.doc_id} · similarity {chunk.similarity:.3f} · {chunk.trust}"
        with st.expander(label):
            st.code(chunk.text, language=None, wrap_lines=True)
            st.json({k: v for k, v in chunk.metadata.items() if k != "fingerprint"},
                    expanded=False)


def render_events(result: RAGResult | None, log_path) -> None:
    st.subheader("Security events")
    if result and result.mode == "baseline":
        st.caption("Baseline mode has no security controls. Trust labels are recorded "
                   "but do not affect retrieval or the answer.")
    events = read_events(log_path, limit=10)
    if not events:
        st.info("No events logged yet. Ask a question to create one.")
        return
    table(events, ["timestamp", "shield_mode", "response_outcome", "withheld_reason",
                   "retrieved_doc_ids", "cited_doc_ids"])
    with st.expander("All logged fields"):
        table(events, ["timestamp", "query_id", "shield_mode", "response_outcome",
                       "withheld_reason", "retrieved_doc_ids", "context_doc_ids",
                       "detection_results", "conflicts", "quarantine_actions", "cited_doc_ids"])


def ask_page(pipeline: RAGPipeline, mode: str, config: ShieldConfig) -> None:
    st.title("Station 41 knowledge assistant")
    st.caption("Fictional simulation. Not connected to any real company, system, or equipment.")
    with st.form("ask"):
        question = st.text_area("Question", placeholder="What should I do about alert W-217?",
                                max_chars=2000)
        submitted = st.form_submit_button(f"Ask ({MODE_LABELS[mode]})", type="primary")
    if submitted:
        try:
            with st.spinner("Retrieving and generating..."):
                st.session_state["result"] = pipeline.answer(question, mode, config)
                st.session_state["asked_with"] = (mode, config)
        except (ValueError, LLMError) as exc:
            st.session_state.pop("result", None)
            st.error(str(exc))
    result = st.session_state.get("result")
    if result:
        if st.session_state.get("asked_with") != (mode, config):
            st.info(f"This answer came from {MODE_LABELS[result.mode]} with the settings in "
                    "place when it was asked. The sidebar has changed since; ask again to compare.")
        render_answer(result)
    render_events(result, pipeline.settings.log_path)


def documents_page(pipeline: RAGPipeline) -> None:
    st.title("Documents")
    documents, errors = load_corpus(pipeline.settings)
    if st.button("Re-index documents"):
        report, errors = pipeline.sync()
        st.success(f"Added {report.added}, updated {report.updated}, "
                   f"removed {report.removed}, unchanged {report.unchanged}.")
        documents, _ = load_corpus(pipeline.settings)
    for error in errors:
        st.warning(plain(f"Skipped: {error}"))
    table([{**doc.metadata(), "sha256": doc.sha256[:12]} for doc in documents])
    st.caption("Trust comes from the registry and a matching hash, not from a file's name, "
               "folder, or text. A matching hash shows the file is unchanged since sign-off, "
               "not that its content is correct.")


def quarantine_page(pipeline: RAGPipeline) -> None:
    st.title("Quarantine review")
    records = pipeline.shield.quarantine.records()
    if not records:
        st.info("No documents have been quarantined. The Shield moves a file here when it "
                "flags an injection or a conflict with approved facts.")
        return
    table(records)
    held = [r["stored_name"] for r in records if r["status"] == "quarantined"]
    if not held:
        return
    with st.form("restore"):
        stored = st.selectbox("Document", held)
        reviewer = st.text_input("Reviewer name (required)")
        if st.form_submit_button("Restore to untrusted"):
            try:
                path = pipeline.shield.quarantine.restore(stored, reviewer)
                pipeline.sync()
                st.success(f"Restored to {plain(path)}. It stays unapproved until it is signed off.")
            except ValueError as exc:
                st.error(str(exc))
    st.caption("Files are preserved as evidence. Restoring does not approve a document.")


def shield_controls() -> ShieldConfig:
    st.subheader("Shield controls")
    config = ShieldConfig(
        provenance=st.checkbox("1. Provenance", True),
        trust_retrieval=st.checkbox("2. Trust-based retrieval", True),
        injection_detection=st.checkbox("3. Injection detection", True),
        conflict_detection=st.checkbox("4. Conflict detection", True),
        quarantine=st.checkbox("5. Quarantine", True),
        safe_response=st.checkbox("6. Safe response handling", True),
    )
    st.checkbox("7. Security logging (always on)", True, disabled=True)
    return config


def show_scene(scene: dict, verdict=None) -> None:
    st.markdown(f"**Question:** {plain(scene['question'])}")
    label = "Answer (withheld by the Shield)" if scene["status"] == "withheld" else "Answer"
    st.markdown(f"**{label}:** {plain(scene['answer'])}")
    if verdict:
        verdict()
    st.caption("Sources used")
    table(scene["sources_used"])


def demo_page(pipeline: RAGPipeline) -> None:
    st.title("Final demonstration")
    st.caption("Runs on a disposable copy of the data. Outcomes are whatever the run produces. "
               "Both modes run automatically; the sidebar settings do not apply here.")
    if st.button("Run demonstration", type="primary"):
        status = st.status("Running the demonstration. This takes a few minutes.", expanded=True)
        try:
            with status:
                run_demo(pipeline.settings, progress=st.write)
            status.update(label="Demonstration finished", state="complete", expanded=False)
        except LLMError as exc:
            status.update(label="Demonstration failed", state="error")
            st.error(str(exc))
    if not DEMO_OUTPUT.exists():
        st.info("The demonstration has not been run yet.")
        return
    report = json.loads(DEMO_OUTPUT.read_text(encoding="utf-8"))
    st.caption(f"Last run: {when(report['generated_at'])} with {report['model']}")

    st.header("A. Normal operation")
    show_scene(report["scene_a_normal_operation"])

    st.header("B. Poisoned document, no Shield")
    scene = report["scene_b_poisoning_without_shield"]
    show_scene(scene, lambda: (st.error if scene["attack_succeeded"] else st.success)(
        f"Attack {'succeeded' if scene['attack_succeeded'] else 'failed'}: "
        f"{outcome_text(scene['scored_outcome'])}."))

    st.header("C. Same question, Shield on")
    scene = report["scene_c_shield_enabled"]
    show_scene(scene, lambda: (st.success if scene["attack_prevented"] else st.error)(
        f"Attack {'prevented' if scene['attack_prevented'] else 'not prevented'}: "
        f"{outcome_text(scene['scored_outcome'])}."))
    st.subheader("Document trust decisions")
    table(scene["trust_decisions"])
    for warning in scene["warnings"]:
        st.warning(plain(warning))
    for record in scene["quarantined"]:
        st.info(plain(f"Quarantined {record['original_path']}: {record['reason']}"))
    st.subheader("Security event log")
    table(report["security_event_log"])


def evaluation_page(pipeline: RAGPipeline) -> None:
    st.title("Evaluation results")
    results = pipeline.settings.results_dir
    summary_path = results / "evaluation_summary.csv"
    if not summary_path.exists():
        st.info("No evaluation has been run yet. Run python -m evaluation.run_evaluation "
                "to produce results.")
        return
    st.caption("Measured on a fictional simulation with a small local model. These are laboratory "
               "results, not real-world risk estimates.")
    summary = pd.read_csv(summary_path)
    st.plotly_chart(attack_success_chart(summary), width="stretch")
    st.subheader("Summary table")
    st.caption("Attack success and its interval are percentages of attempts.")
    table(summary, SUMMARY_COLUMNS)
    with st.expander("All summary columns"):
        table(summary)
    ablation_path = results / "ablation_summary.csv"
    if ablation_path.exists():
        ablation = pd.read_csv(ablation_path)
        if ablation.config.nunique() > 2:
            st.subheader("What each control contributes")
            st.plotly_chart(ablation_chart(ablation), width="stretch")
            with st.expander("Table view"):
                table(ablation)
    with st.expander("Download raw files"):
        for path in sorted(results.glob("*.csv")):
            st.download_button(path.name, path.read_bytes(), path.name, "text/csv")


def seconds_text(stats: dict) -> str:
    return "none yet" if stats["mean_seconds"] is None else f"{stats['mean_seconds']:.2f}s"


def watch_page(pipeline: RAGPipeline) -> None:
    st.title("Watch")
    st.caption("The Shield's monitoring stage: integrity scans, alerts, unusual retrieval "
               "patterns, and purge-and-retest before the assistant goes back into use.")
    settings = pipeline.settings
    metrics = governance_metrics(settings)
    procedures = metrics["verified_procedures"]
    detect, contain = metrics["time_to_detect_unauthorized_change"], metrics["time_to_quarantine"]
    cols = st.columns(4)
    cols[0].metric("Procedures verified", f"{procedures['verified']} of {procedures['registered']}",
                   help="Named owner, approved, and unchanged since sign-off.")
    cols[1].metric("Mean time to detect a change", seconds_text(detect),
                   help=f"{detect['count']} unauthorized changes detected.")
    cols[2].metric("Mean time to quarantine", seconds_text(contain),
                   help=f"{contain['count']} documents quarantined.")
    cols[3].metric("Alerts", sum(metrics["alerts_by_kind"].values()))
    st.caption(metrics["caveat"])
    for row in procedures["unverified"]:
        st.error(plain(f"{row['doc_id']} {row['filename']}: {', '.join(row['problems'])}"))

    left, right = st.columns(2)
    if left.button("Run integrity scan"):
        report = integrity_scan(pipeline)
        st.session_state.pop("result", None)
        (st.warning if report.quarantined else st.success)(
            f"Scanned {report.documents_scanned} documents in {report.seconds:.2f}s. "
            f"Tampered: {len(report.tampered)}. Flagged uploads: {len(report.flagged_uploads)}. "
            f"Quarantined: {len(report.quarantined)}.")
    if right.button("Purge index and retest", type="primary"):
        with st.spinner("Scanning, rebuilding the index, and re-asking the legitimate "
                        "questions. This takes about a minute."):
            try:
                report = purge_and_retest(pipeline)
            except LLMError as exc:
                st.error(str(exc))
                report = None
        st.session_state.pop("result", None)
        if report:
            verdict = "passed: safe to go back into use" if report["passed"] else "failed: keep offline"
            (st.success if report["passed"] else st.error)(
                f"Retest {verdict}. {report['legitimate_correct']} of {report['legitimate_total']} "
                f"legitimate answers correct; {len(report['unverified_procedures'])} unverified "
                f"procedures. Index now holds {report['indexed_by_trust']}.")
            table([{k: r[k] for k in ("test_id", "status", "correct", "cited")}
                   for r in report["results"]])

    st.subheader("Alerts")
    found = alerts(settings.log_path)[::-1]
    if found:
        table(found, ["timestamp", "kind", "detail", "detected_by", "changed_at"])
    else:
        st.info("No alerts yet.")

    st.subheader("Retrieval concentration")
    st.caption("Share of recent RAG Shield questions that retrieved each document, counting "
               "only questions asked while it was indexed. An unapproved document in half or "
               "more, or an approved one whose share jumps, raises an alert.")
    rows = retrieval_concentration(all_events(settings.log_path))
    if rows:
        table(rows)
    else:
        st.info("Needs at least five RAG Shield questions in the log.")

    st.subheader("Drill")
    st.caption("Runs on a disposable copy of the data: an unauthorized edit, a poisoned "
               "upload, purge and retest, and a document built to evade the content rules.")
    if st.button("Run drill (about 2 minutes)"):
        status = st.status("Running the drill", expanded=True)
        try:
            with status:
                run_drill(settings, progress=st.write)
            status.update(label="Drill finished", state="complete", expanded=False)
        except LLMError as exc:
            status.update(label="Drill failed", state="error")
            st.error(str(exc))
    if DRILL_OUTPUT.exists():
        drill = json.loads(DRILL_OUTPUT.read_text(encoding="utf-8"))
        scan = drill["step1_scan"]
        st.caption(f"Last run: {when(drill['generated_at'])} with {drill['model']}")
        st.markdown(plain(
            f"1. Scan caught tampering in {', '.join(t['filename'] for t in scan['tampered']) or 'nothing'} "
            f"and flagged {', '.join(f['filename'] for f in scan['flagged_uploads']) or 'no uploads'}."))
        for number, key in ((2, "step2_retest_while_quarantined"), (3, "step3_retest_after_restore")):
            r = drill[key]
            st.markdown(plain(f"{number}. Retest {'passed' if r['passed'] else 'failed'}: "
                              f"{r['legitimate_correct']} of {r['legitimate_total']} correct, "
                              f"unverified: {', '.join(r['unverified_procedures']) or 'none'}."))
        if "step4_decoy_doc_id" not in drill:
            st.info("This drill report is from an older version. Run the drill again.")
            return
        st.markdown(plain(f"4. Decoy {drill['step4_decoy_doc_id']} "
                          f"{'raised an alert' if drill['step4_decoy_alerted'] else 'was not caught'}."))
        for alert in drill["step4_other_concentration_alerts"]:
            st.warning(plain(f"Other alert, not the decoy: {alert['doc_id']}: {alert['detail']}"))
        with st.expander("Retrieval concentration in the drill"):
            table(drill["step4_concentration"])


def review_page() -> None:
    st.title("Review verdicts")
    st.caption("Confirm or change each proposed verdict. Verdicts decide the attack success "
               "numbers, so confirm them as a group, then rebuild the summaries.")
    path = summaries.REVIEW_PATH
    entries = verdicts.load(path)
    runs_path = load_settings().results_dir / "evaluation_runs.csv"
    if not entries or not runs_path.exists():
        st.info("No verdicts to review.")
        return
    items = verdicts.review_items(entries, pd.read_csv(runs_path, keep_default_na=False), load_cases())
    state = verdicts.status(entries)
    st.progress(state["confirmed"] / state["total"],
                f"{state['confirmed']} of {state['total']} confirmed · "
                f"{state['changed_from_proposal']} changed · {state['disputed']} disputed")
    reviewer = st.text_input("Your name (recorded with each confirmation)",
                             key="reviewer_name")
    show = st.radio("Show", ["Pending", "All", "Changed or disputed"], horizontal=True)
    if show == "Pending":
        items = [i for i in items if not verdicts.is_confirmed(i["entry"])]
    elif show == "Changed or disputed":
        items = [i for i in items if verdicts.is_confirmed(i["entry"]) and (
            i["entry"]["verdict"] != i["entry"].get("proposed_verdict")
            or len({c["verdict"] for c in i["entry"]["confirmations"]}) > 1)]
    if not items:
        st.success("Nothing to show here.")
    else:
        labels = [f"{i['entry']['test_id']} · {i['entry']['config']}" for i in items]
        position = min(st.session_state.get("review_position", 0), len(items) - 1)
        position = st.selectbox("Verdict", range(len(items)), index=position,
                                format_func=lambda n: f"{n + 1} of {len(items)}: {labels[n]}")
        st.session_state["review_position"] = position
        render_review_item(items[position], reviewer, path, entries)

    st.divider()
    st.subheader("Rebuild results")
    st.caption("Recomputes the summaries, charts, and FAIR export from the verdicts above.")
    if st.button("Rebuild summaries and FAIR export"):
        summaries.main()
        export_fair.main()
        state = verdicts.status(verdicts.load(path))
        st.success(f"Rebuilt with {state['confirmed']} of {state['total']} verdicts confirmed.")


def render_review_item(item: dict, reviewer: str, path, entries: list[dict]) -> None:
    entry, case = item["entry"], item["case"]
    setup = "Baseline" if entry["config"] == "baseline" else "RAG Shield"
    st.subheader(f"{entry['test_id']} · {setup} · {humanize(item['scenario'])}")
    st.markdown(f"**Question:** {plain(case.get('question', ''))}")
    st.markdown(f"**Safe behavior:** {plain(case.get('expected_safe_behavior', ''))}")
    st.markdown(f"**Attack counts when:** {plain(case.get('attack_success_criteria', ''))}")
    attack_file = load_settings().data_dir / str(case.get("attack_document") or "")
    if case.get("attack_document") and attack_file.is_file():
        with st.expander("Attack document (fictional)"):
            st.code(attack_file.read_text(encoding="utf-8"), language=None, wrap_lines=True)
    st.markdown("**Answer being judged:**")
    st.code(item["answer"] or "(answer not found in evaluation_runs.csv)", language=None,
            wrap_lines=True)
    with st.expander("Clean control answer (same question, no attack document)"):
        st.code(item["control_answer"] or "", language=None, wrap_lines=True)
    st.caption(f"Rule-based outcome: {humanize(item['rule_outcome'] or 'unknown')} · "
               f"proposed verdict: {entry.get('proposed_verdict', entry['verdict'])} "
               f"({entry.get('reviewed_by', '')})")
    for confirmation in entry.get("confirmations", []):
        st.info(plain(f"{confirmation['reviewer']} confirmed {confirmation['verdict']} "
                      f"at {when(confirmation['at'])}"
                      + (f": {confirmation['note']}" if confirmation["note"] else "")))
    key = f"{entry['test_id']}|{entry['config']}"
    with st.form(f"verdict-{key}"):
        verdict = st.radio("Verdict", verdicts.VERDICTS,
                           index=verdicts.VERDICTS.index(entry["verdict"]), horizontal=True,
                           captions=[verdicts.VERDICT_HELP[v] for v in verdicts.VERDICTS])
        note = st.text_input("Note (optional; please explain if you change the verdict)")
        if st.form_submit_button("Confirm", type="primary"):
            try:
                verdicts.confirm(entries, entry["test_id"], entry["config"],
                                 entry["answer_sha256"], verdict, reviewer, note)
                verdicts.save(path, entries)
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))


def main() -> None:
    try:
        pipeline = get_pipeline()
    except Exception as exc:
        st.error(f"Could not start: {exc}")
        st.stop()
    with st.sidebar:
        st.header("RAG Shield")
        page = st.radio("Page", ["Ask", "Documents", "Quarantine", "Watch", "Evaluation",
                                 "Review verdicts", "Demo"])
        mode, config = "baseline", ShieldConfig()
        if page == "Ask":
            mode = st.radio("Mode", list(MODE_LABELS), format_func=MODE_LABELS.get)
            if mode == "shielded":
                config = shield_controls()
        st.caption(f"Model: {pipeline.settings.model_label}")
        st.caption(f"Top-k: {pipeline.settings.top_k}")
    if page == "Ask":
        ask_page(pipeline, mode, config)
    elif page == "Documents":
        documents_page(pipeline)
    elif page == "Quarantine":
        quarantine_page(pipeline)
    elif page == "Watch":
        watch_page(pipeline)
    elif page == "Evaluation":
        evaluation_page(pipeline)
    elif page == "Review verdicts":
        review_page()
    else:
        demo_page(pipeline)


main()
