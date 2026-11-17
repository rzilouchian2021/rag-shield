"""Streamlit dashboard for the RAG Shield simulation. Run: streamlit run app.py"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime

from pathlib import Path

import pandas as pd
import streamlit as st

from config import palette
from config.settings import load_settings
from demo.run_demo import OUTPUT as DEMO_OUTPUT
from demo.run_demo import run as run_demo
from demo.run_drill import OUTPUT as DRILL_OUTPUT
from demo.run_drill import run as run_drill
from evaluation import export_fair
from evaluation import review as verdicts
from evaluation import summarize as summaries
from evaluation.harness import load_cases
from evaluation.headline import headline
from evaluation.charts import ablation_chart, attack_success_chart
from src.ingestion import load_corpus
from src.llm_client import LLMError
from src import signoff
from src.logging_utils import read_events, verify_log
from src.monitoring import (alerts, all_events, governance_metrics, integrity_scan,
                            purge_and_retest, retrieval_concentration)
from src.rag_pipeline import RAGPipeline, RAGResult
from src.shield import ShieldConfig

st.set_page_config(page_title="RAG Shield", page_icon=":material/shield:", layout="wide")

# Static styles for the few elements Streamlit has no theme token for. Values
# come from config/palette.py; see DESIGN.md.
STYLE = f"""<style>
.rs-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
            gap: 0.75rem 2rem; margin: 0.25rem 0 1rem; }}
.rs-label {{ font-size: 0.875rem; font-weight: 600; color: {palette.INK_MUTED}; }}
.rs-value {{ font-size: 2rem; font-weight: 700; color: {palette.INK}; line-height: 1.2;
            font-variant-numeric: tabular-nums; }}
.rs-empty {{ font-size: 1rem; color: {palette.INK_MUTED}; padding-top: 0.5rem; }}
.rs-note {{ font-size: 0.875rem; color: {palette.INK_MUTED}; }}
/* Streamlit fades blockquotes and captions to 60% (about 4.1 to 4.3:1). Full-strength
   Slate Note keeps them at 7.3:1. */
[data-testid="stMarkdownContainer"] blockquote {{ opacity: 1; color: {palette.INK}; }}
[data-testid="stCaptionContainer"], [data-testid="stWidgetLabel"] + div [data-testid="stMarkdownContainer"] p,
[data-testid="stRadio"] [data-testid="stCaptionContainer"] {{ opacity: 1 !important; color: {palette.INK_MUTED}; }}
/* Keyboard focus in the sidebar: a clear outline, distinct from the current-page tint. */
[data-testid="stSidebarNav"] a:focus-visible {{ outline: 2px solid {palette.SHIELD};
                                                 outline-offset: 2px; }}
/* Headings: tighter tracking at display sizes. */
h1 {{ letter-spacing: -0.02em; }}
h2, h3 {{ letter-spacing: -0.01em; }}
.rs-eyebrow {{ font-size: 0.875rem; font-weight: 700; letter-spacing: 0.08em;
              text-transform: uppercase; color: {palette.SHIELD}; margin-bottom: -0.75rem; }}
/* Measured-results strip: proportion bars, lower is better. */
.rs-results {{ display: grid; gap: 1.1rem; margin: 0.25rem 0 0.5rem; }}
.rs-row-title {{ font-weight: 700; color: {palette.INK}; }}
.rs-row-title span {{ font-weight: 600; color: {palette.DANGER_TEXT}; margin-left: 0.5rem; }}
.rs-bar {{ display: grid; grid-template-columns: 7.5rem 1fr 6.5rem; align-items: center;
          gap: 0.75rem; margin-top: 0.35rem; }}
.rs-bar-name {{ font-weight: 600; }}
.rs-bar-track {{ height: 0.9rem; background: {palette.PANEL}; border-radius: 4px;
                 border: 1px solid {palette.RULE}; overflow: hidden; }}
.rs-bar-fill {{ height: 100%; border-radius: 3px 0 0 3px; }}
.rs-bar-count {{ font-variant-numeric: tabular-nums; font-weight: 700; text-align: right; }}
@media (prefers-reduced-motion: reduce) {{
  * {{ animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }}
}}
</style>"""

MODE_LABELS = {"baseline": "Baseline (no controls)", "shielded": "RAG Shield"}
SHORT_MODE = {"baseline": "Baseline", "shielded": "RAG Shield"}
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
LOGO = Path(__file__).parent / "assets" / "logo.svg"
PERCENT_COLUMNS = {"share", "previous_share"}
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


def sentence(text: str) -> str:
    return plain(text[:1].upper() + text[1:] + ".")


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
        elif column in PERCENT_COLUMNS:
            frame[column] = frame[column].map(
                lambda v: "" if v is None or pd.isna(v) else f"{float(v):.0%}")
        if frame[column].dtype == bool:  # checkboxes look editable; words don't
            frame[column] = frame[column].map({True: "Yes", False: "No"})
    for column in frame.columns:  # numeric columns keep their NaN so they stay numeric
        if frame[column].dtype == object:
            frame[column] = frame[column].map(
                lambda v: "" if v is None or (isinstance(v, float) and pd.isna(v)) else _cell(v))
    frame.columns = [COLUMN_LABELS.get(c, c.replace("_", " ").capitalize()) for c in frame.columns]
    st.dataframe(frame, width="stretch", hide_index=True)


def stats(items: list[tuple[str, str | None, str]]) -> None:
    """A row of measured figures. Missing data shows as a quiet note, never a big placeholder."""
    cells = []
    for label, value, note in items:
        if value is None:
            body = f'<div class="rs-empty">{html.escape(note)}</div>'
        else:
            body = f'<div class="rs-value">{html.escape(value)}</div>'
            if note:
                body += f'<div class="rs-note">{html.escape(note)}</div>'
        cells.append(f'<div><div class="rs-label">{html.escape(label)}</div>{body}</div>')
    st.markdown(f'<div class="rs-stats">{"".join(cells)}</div>', unsafe_allow_html=True)


@st.cache_resource(show_spinner="Loading the embedding model and index...")
def get_pipeline() -> RAGPipeline:
    pipeline = RAGPipeline(load_settings())
    pipeline.sync()
    return pipeline


def render_answer(result: RAGResult) -> None:
    st.header(f"Answer · {MODE_LABELS[result.mode]}", anchor=False)
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
        st.header("Document trust decisions", anchor=False)
        table(result.decisions)
        for detection in result.detections:
            with st.expander(f"Injection flag: {detection['doc_id']}, score {detection['score']}"):
                for rule in detection["matched_rules"]:
                    st.markdown(plain(f"{rule['rule']} (+{rule['weight']}): {rule['why']}"))
        for record in result.quarantined:
            st.warning(plain(f"Quarantined {record['original_path']}: {record['reason']}"))

    st.header("Sources cited", anchor=False)
    if result.cited_doc_ids:
        titles = {c.doc_id: c.metadata["title"] for c in result.chunks}
        for doc_id in result.cited_doc_ids:
            st.markdown(f"- **{plain(doc_id)}**: {plain(titles[doc_id])}")
    else:
        st.info("The answer did not cite any retrieved source.")

    st.header("Chunks used in the answer", anchor=False)
    for chunk in result.chunks:
        label = f"#{chunk.rank} · {chunk.doc_id} · similarity {chunk.similarity:.3f} · {chunk.trust}"
        with st.expander(label):
            st.code(chunk.text, language=None, wrap_lines=True)
            st.json({k: v for k, v in chunk.metadata.items() if k != "fingerprint"},
                    expanded=False)


def render_events(result: RAGResult, log_path) -> None:
    if result.mode == "baseline":
        st.caption("Baseline mode has no security controls. Trust labels are recorded "
                   "but do not affect retrieval or the answer.")
    events = [e for e in read_events(log_path, limit=50) if "query_id" in e][:10]
    table(events, ["timestamp", "shield_mode", "response_outcome", "withheld_reason",
                   "retrieved_doc_ids", "cited_doc_ids"])
    if st.toggle("Show every logged field"):  # a toggle: this already sits in an expander
        table(events, ["timestamp", "query_id", "shield_mode", "response_outcome",
                       "withheld_reason", "retrieved_doc_ids", "context_doc_ids",
                       "detection_results", "conflicts", "quarantine_actions", "cited_doc_ids"])


def ask_page(pipeline: RAGPipeline) -> None:
    with st.sidebar:
        mode = st.radio("Mode", list(MODE_LABELS), format_func=MODE_LABELS.get)
        config = shield_controls() if mode == "shielded" else ShieldConfig()
    page_title("Assistant", "Station 41 knowledge assistant")
    with st.form("ask"):
        question = st.text_area("Question", placeholder="What should I do about alert W-217?",
                                max_chars=2000)
        submitted = st.form_submit_button(f"Ask with {SHORT_MODE[mode]}", type="primary")
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
        with st.expander("Security log for recent questions"):
            render_events(result, pipeline.settings.log_path)


def documents_page(pipeline: RAGPipeline) -> None:
    page_title("Assistant", "Documents")
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
    page_title("Assistant", "Quarantine review")
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
    st.subheader("Shield controls", anchor=False)
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


def page_title(eyebrow: str, title: str) -> None:
    st.markdown(f'<div class="rs-eyebrow">{html.escape(eyebrow)}</div>', unsafe_allow_html=True)
    st.title(title, anchor=False)


def results_strip(summary: pd.DataFrame) -> None:
    """Measured clear attack successes as proportion bars. Lower is better."""
    rows = []
    for row in headline(summary):
        flag = f'<span>{html.escape(row["flag"])}</span>' if row["flag"] else ""
        bars = ""
        for name, key, color in (("Baseline", "baseline", palette.BASELINE),
                                 ("RAG Shield", "shield", palette.SHIELD)):
            hits, trials = row[key]
            share = 100 * hits / trials if trials else 0
            bars += (f'<div class="rs-bar"><div class="rs-bar-name">{name}</div>'
                     f'<div class="rs-bar-track" role="img" aria-label="{name}: {hits} of {trials}">'
                     f'<div class="rs-bar-fill" style="width:{share:.1f}%;background:{color}"></div></div>'
                     f'<div class="rs-bar-count">{hits} of {trials}</div></div>')
        rows.append(f'<div><div class="rs-row-title">{html.escape(row["title"])}{flag}</div>{bars}</div>')
    st.markdown(f'<div class="rs-results">{"".join(rows)}</div>', unsafe_allow_html=True)


def answer_block(scene: dict, nested: bool = False) -> None:
    """nested=True when already inside an expander, which Streamlit cannot nest."""
    if scene["status"] == "withheld":
        st.caption("Withheld by RAG Shield")
    # Untrusted model output: escaped Markdown only, never inside raw HTML.
    st.markdown(plain(scene["answer"]))
    if nested:
        st.caption("Sources used")
        table(scene["sources_used"])
    else:
        with st.expander("Sources used"):
            table(scene["sources_used"])


def verdict(succeeded: bool, text: str) -> None:
    """Outcome callout. Icon and wording carry the meaning, not color alone."""
    if succeeded:
        st.error(f"**Attack succeeded.** {text}", icon=":material/gpp_bad:")
    else:
        st.success(f"**Attack stopped.** {text}", icon=":material/verified_user:")


def demo_page(pipeline: RAGPipeline) -> None:
    page_title("Live comparison · fictional Station 41", "Final demonstration")
    intro, action = st.columns([4, 1], vertical_alignment="center")
    intro.caption("Same question, same documents, same model. Runs on a disposable copy of the "
                  "data and shows whatever the run produces.")
    if action.button("Run again", icon=":material/replay:", help="About 1 minute. Needs Ollama.",
                     width="stretch"):
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

    unprotected = report["scene_b_poisoning_without_shield"]
    shielded = report["scene_c_shield_enabled"]
    st.header("A poisoned bulletin is uploaded. A technician asks:", anchor=False)
    st.markdown(f"> {plain(unprotected['question'])}")
    st.caption(f"Run {when(report['generated_at'])} with {report['model']}")
    left, right = st.columns(2, gap="medium")
    with left.container(border=True):
        st.badge("Unprotected", color="orange", icon=":material/warning:")
        st.subheader("Baseline RAG", anchor=False)
        verdict(unprotected["attack_succeeded"], sentence(outcome_text(unprotected["scored_outcome"])))
        answer_block(unprotected)
    with right.container(border=True):
        st.badge("Protected", color="blue", icon=":material/shield:")
        st.subheader("RAG Shield", anchor=False)
        verdict(not shielded["attack_prevented"], sentence(outcome_text(shielded["scored_outcome"])))
        answer_block(shielded)
        for record in shielded["quarantined"]:
            st.info(plain(f"Quarantined {record['original_path']}: {record['reason']}"),
                    icon=":material/inventory_2:")

    summary_path = pipeline.settings.results_dir / "evaluation_summary.csv"
    if summary_path.exists():
        st.header("Across the full evaluation", anchor=False)
        st.caption("Clear attack successes, lower is better. Measured on the same fictional "
                   "station and model; details on the Evaluation page.")
        results_strip(pd.read_csv(summary_path))

    st.header("Evidence from this run", anchor=False)
    with st.expander("Why the Shield excluded the bulletin"):
        for warning in shielded["warnings"]:
            st.warning(plain(warning))
        table(shielded["trust_decisions"])
    with st.expander("Security event log for this run"):
        table(report["security_event_log"])
    with st.expander("Control: a normal question with no attack"):
        normal = report["scene_a_normal_operation"]
        st.markdown(f"> {plain(normal['question'])}")
        answer_block(normal, nested=True)


def evaluation_page(pipeline: RAGPipeline) -> None:
    page_title("Measured results", "Evaluation results")
    results = pipeline.settings.results_dir
    summary_path = results / "evaluation_summary.csv"
    if not summary_path.exists():
        st.info("No evaluation has been run yet. Run python -m evaluation.run_evaluation "
                "to produce results.")
        return
    st.caption("Measured on a fictional simulation with a small local model. These are laboratory "
               "results, not real-world risk estimates.")
    summary = pd.read_csv(summary_path)
    st.plotly_chart(attack_success_chart(summary), width="stretch", theme=None,
                    config={"displayModeBar": False})
    st.header("Summary table", anchor=False)
    st.caption("Attack success and its interval are percentages of attempts.")
    table(summary, SUMMARY_COLUMNS)
    with st.expander("All summary columns"):
        table(summary)
    ablation_path = results / "ablation_summary.csv"
    if ablation_path.exists():
        ablation = pd.read_csv(ablation_path)
        if ablation.config.nunique() > 2:
            st.header("What each control contributes", anchor=False)
            st.plotly_chart(ablation_chart(ablation), width="stretch", theme=None,
                    config={"displayModeBar": False})
            with st.expander("Table view"):
                table(ablation)
    with st.expander("Download raw files"):
        for path in sorted(results.glob("*.csv")):
            st.download_button(path.name, path.read_bytes(), path.name, "text/csv")


def seconds_text(figures: dict) -> str | None:
    return None if figures["mean_seconds"] is None else f"{figures['mean_seconds']:.2f}s"


def signoff_section(settings) -> None:
    st.header("Sign-off and security log", anchor=False)
    summary = signoff.keyring_summary(settings.registry_path)
    if not summary["enforced"]:
        st.info("Signed sign-off is not enforced for this registry.")
    elif summary["ok"]:
        st.success(f"**Keyring verified.** Signed by the document-control trust root "
                   f"(key {summary['root_key_id']}). A procedure counts as approved only with "
                   f"{summary['min_signatures']} different approvers' signatures"
                   + (", one from the team that owns it." if summary["owner_team_required"] else "."),
                   icon=":material/verified_user:")
    else:
        st.error(f"**Keyring rejected:** {summary['problem']}. Nothing counts as approved "
                 "until it is fixed.", icon=":material/gpp_bad:")
    table([{k: r[k] for k in ("doc_id", "owner", "signed_off", "signers", "problems")}
           for r in signoff.status_rows(settings.registry_path)])
    if summary.get("approvers"):
        with st.expander("Approvers and keys"):
            table(summary["approvers"])
            st.caption("Private keys are encrypted on disk in keys/, which is never committed. "
                       "Adding, rotating or revoking a key needs the trust root's key: "
                       "python -m src.signoff add-approver | rotate-key | revoke")

    if st.button("Verify security log", icon=":material/link:",
                 help="Checks every sealed entry: an edited, deleted, inserted or cut-off "
                      "entry breaks the chain."):
        st.session_state["log_check"] = verify_log(settings.log_path)
    check = st.session_state.get("log_check")
    if check:
        note = (f" {check['unsealed_before_sealing']} older entries predate sealing and "
                "can't be checked." if check["unsealed_before_sealing"] else "")
        if check["ok"] and not check["sealed"]:
            st.info(f"No sealed entries yet. Every new entry is sealed from now on.{note}")
        elif check["ok"]:
            st.success(f"**Security log verified.** {check['sealed']} sealed entries, "
                       f"none changed, removed or inserted.{note}", icon=":material/verified_user:")
        else:
            st.error(f"**Security log failed verification.** {check['problems'][0]}",
                     icon=":material/gpp_bad:")
            with st.expander(f"All {len(check['problems'])} problems"):
                st.markdown("\n".join(f"- {plain(p)}" for p in check["problems"]))

    with st.expander("Deployment checks"):
        st.caption("Files the assistant relies on, and whether its own account can change them. "
                   "On a laptop it runs as you, so they are open. In production the assistant "
                   "runs as a separate read-only account, and only document control can write.")
        table(signoff.access_audit(settings), ["item", "path", "ok", "issue"])


def watch_page(pipeline: RAGPipeline) -> None:
    page_title("Monitoring", "Watch")
    st.caption("The Shield's monitoring stage: integrity scans, alerts, unusual retrieval "
               "patterns, and purge-and-retest before the assistant goes back into use.")
    settings = pipeline.settings
    metrics = governance_metrics(settings)
    procedures = metrics["verified_procedures"]
    detect, contain = metrics["time_to_detect_unauthorized_change"], metrics["time_to_quarantine"]
    stats([
        ("Procedures verified", f"{procedures['verified']} of {procedures['registered']}",
         "Named owner, signed by two approvers, unchanged since"),
        ("Mean time to detect a change", seconds_text(detect),
         f"Over {detect['count']} detected changes" if detect["count"]
         else "No unauthorized changes detected yet"),
        ("Mean time to quarantine", seconds_text(contain),
         f"Over {contain['count']} quarantined documents" if contain["count"]
         else "Nothing quarantined yet"),
    ])
    st.caption(metrics["caveat"])
    for row in procedures["unverified"]:
        st.error(plain(f"{row['doc_id']} {row['filename']}: {', '.join(row['problems'])}"))

    actions = st.columns([1, 1, 2])
    if actions[0].button("Run integrity scan", icon=":material/fact_check:",
                         help="Re-checks every document now. Anything tampered or flagged "
                              "is moved to Quarantine, where it can be restored."):
        st.session_state["scan_report"] = integrity_scan(pipeline)
        st.session_state.pop("result", None)
    with actions[1].popover("Purge and retest", icon=":material/restart_alt:"):
        st.markdown("Scans and quarantines anything suspicious, deletes and rebuilds the "
                    "search index, then re-asks the 10 legitimate questions with the Shield on. "
                    "Takes about a minute and needs Ollama running.")
        if st.button("Purge and retest now", type="primary"):
            with st.spinner("Scanning, rebuilding the index, and re-asking the legitimate "
                            "questions..."):
                try:
                    st.session_state["retest_report"] = purge_and_retest(pipeline)
                except LLMError as exc:
                    st.error(str(exc))
            st.session_state.pop("result", None)

    scan = st.session_state.get("scan_report")
    if scan:
        (st.warning if scan.quarantined or scan.unsigned or not scan.log_check.get("ok")
     else st.success)(
            f"Integrity scan: {scan.documents_scanned} documents checked in {scan.seconds:.2f}s. "
            f"{len(scan.tampered)} tampered, {len(scan.flagged_uploads)} uploads flagged, "
            f"{len(scan.quarantined)} quarantined, {len(scan.unsigned)} without a valid sign-off. "
            f"Security log {'verified' if scan.log_check.get('ok') else 'FAILED verification'}.",
            icon=":material/fact_check:")
    retest = st.session_state.get("retest_report")
    if retest:
        outcome = ("passed. Safe to put back into use." if retest["passed"]
                   else "failed. Keep the assistant offline.")
        (st.success if retest["passed"] else st.error)(
            f"**Retest {outcome}** {retest['legitimate_correct']} of {retest['legitimate_total']} "
            f"legitimate answers correct, {len(retest['unverified_procedures'])} unverified "
            "procedures.",
            icon=":material/verified_user:" if retest["passed"] else ":material/gpp_bad:")
        with st.expander("Retest answers"):
            table([{k: r[k] for k in ("test_id", "status", "correct", "cited")}
                   for r in retest["results"]])

    st.header("Alerts", anchor=False)
    found = alerts(settings.log_path)[::-1]
    if found:
        table(found, ["timestamp", "kind", "detail", "detected_by", "changed_at"])
    else:
        st.info("No alerts yet. They appear here when a scan or a question finds tampering, "
                "a flagged upload, or a document showing up in unusually many answers.")

    signoff_section(settings)

    st.header("Retrieval concentration", anchor=False)
    st.caption("Share of recent RAG Shield questions that retrieved each document, counting "
               "only questions asked while it was indexed. An unapproved document in half or "
               "more, or an approved one whose share jumps, raises an alert.")
    rows = retrieval_concentration(all_events(settings.log_path))
    if rows:
        table(rows)
    else:
        st.info("Needs at least five RAG Shield questions in the log.")

    st.header("Drill", anchor=False)
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
    page_title("Group work", "Review verdicts")
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
    st.header("Rebuild results", anchor=False)
    st.caption("Recomputes the summaries, charts, and FAIR export from the verdicts above.")
    if st.button("Rebuild summaries and FAIR export"):
        summaries.main()
        export_fair.main()
        state = verdicts.status(verdicts.load(path))
        st.success(f"Rebuilt with {state['confirmed']} of {state['total']} verdicts confirmed.")


def render_review_item(item: dict, reviewer: str, path, entries: list[dict]) -> None:
    entry, case = item["entry"], item["case"]
    setup = "Baseline" if entry["config"] == "baseline" else "RAG Shield"
    st.header(f"{entry['test_id']} · {setup} · {humanize(item['scenario'])}", anchor=False)
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
    # Hidden until opened, so each reviewer decides before seeing anyone else's call.
    with st.expander("Compare: proposed verdict, rule-based score, and other reviewers"):
        st.markdown(plain(f"Proposed verdict: {entry.get('proposed_verdict', entry['verdict'])} "
                          f"({entry.get('reviewed_by', '')})"))
        st.markdown(plain(f"Rule-based outcome: {humanize(item['rule_outcome'] or 'unknown')}"))
        for confirmation in entry.get("confirmations", []):
            st.markdown(plain(f"{confirmation['reviewer']} recorded {confirmation['verdict']} "
                              f"at {when(confirmation['at'])}"
                              + (f": {confirmation['note']}" if confirmation["note"] else "")))
    key = f"{entry['test_id']}|{entry['config']}"
    with st.form(f"verdict-{key}"):
        # Nothing preselected: each reviewer makes their own call, then compares.
        choice = st.radio("Your verdict", verdicts.VERDICTS, index=None,
                          captions=[verdicts.VERDICT_HELP[v] for v in verdicts.VERDICTS])
        note = st.text_input("Note", help="Required if your verdict differs from the proposal.")
        if st.form_submit_button("Record verdict", type="primary"):
            try:
                if choice is None:
                    raise ValueError("Choose a verdict first.")
                verdicts.confirm(entries, entry["test_id"], entry["config"],
                                 entry["answer_sha256"], choice, reviewer, note)
                verdicts.save(path, entries)
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))


def main() -> None:
    st.markdown(STYLE, unsafe_allow_html=True)
    st.logo(str(LOGO), size="large")
    try:
        pipeline = get_pipeline()
    except Exception as exc:
        st.error(f"Could not start: {exc}")
        st.stop()

    def page(render, title: str, slug: str, icon: str, default: bool = False) -> st.Page:
        return st.Page(lambda: render(pipeline), title=title, url_path=slug, icon=icon,
                       default=default)

    # Real navigation: each page has its own URL, so a refresh mid-talk stays put.
    navigation = st.navigation({
        "Presentation": [
            page(demo_page, "Demo", "demo", ":material/play_circle:", default=True),
            page(evaluation_page, "Evaluation", "evaluation", ":material/bar_chart:"),
            page(watch_page, "Watch", "watch", ":material/monitor_heart:"),
        ],
        "Assistant": [
            page(ask_page, "Ask", "ask", ":material/chat:"),
            page(documents_page, "Documents", "documents", ":material/description:"),
            page(quarantine_page, "Quarantine", "quarantine", ":material/inventory_2:"),
        ],
        "Group work": [
            page(lambda _: review_page(), "Review verdicts", "review", ":material/rule:"),
        ],
    })
    navigation.run()  # page-specific sidebar controls render first, global notes after
    with st.sidebar:
        st.caption(f"Model: {pipeline.settings.model_label} · Top-k: {pipeline.settings.top_k}")
        st.caption("Fictional simulation. Not connected to any real company or system.")


main()
