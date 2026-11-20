// Simulated employee portal. Text from the assistant and from documents is only ever
// inserted with textContent, never as HTML, so a poisoned document can't inject markup.
"use strict";

const $ = (id) => document.getElementById(id);
const SUGGESTIONS = [
  "How quickly must I notify the Shift Supervisor after a Band Amber alert?",
  "What should I do about alert W-217?",
  "Where do personnel assemble during an emergency?",
  "What do daily rounds cover?",
];
const TRUST = {
  approved: ["Approved procedure", "approved"],
  hash_mismatch: ["Modified since approval", "modified"],
  unapproved: ["Unverified upload", "unverified"],
  untrusted: ["Unverified upload", "unverified"],
};
const WITHHELD = {
  no_approved_evidence: "No approved procedure covers this, so RAG Shield won't let the assistant guess.",
  no_approved_citation: "The draft answer wasn't backed by an approved procedure, so RAG Shield held it back.",
};
const ALERT_NAMES = {
  document_tampered: "Approved procedure modified",
  document_quarantined: "Document quarantined",
  retrieval_concentration: "Unusual retrieval pattern",
  signoff_invalid: "Approval without valid signatures",
  registry_edited: "Registry edited",
  log_tampered: "Security log tampered",
};
const TASKS = [
  ["Walk down compressor unit CX-7", "Check the local display and listen for abnormal noise."],
  ["Record readings in the Station Log", "Start of shift and every four hours."],
  ["Review open work orders", "Two orders are assigned to day shift."],
  ["Check the alarm panel for Band Amber alerts", "Escalate anything abnormal right away."],
  ["Hand over to night shift", "Note any open anomalies for the incoming technician."],
];
const VIEWS = ["assistant", "procedures", "document", "safety", "shift"];

let shieldOn = true;
let revealOn = false;
let knownDocs = null;
let documents = [];
let busy = false;
const answers = new WeakMap();  // message element -> answer data, for the reveal

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function link(href, text, className) {
  const a = el("a", className, text);
  a.href = href;
  return a;
}

function toast(message) {
  const box = $("toast");
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { box.hidden = true; }, 3500);
}

function time(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({ error: "Unexpected response" }));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

// --- Navigation ------------------------------------------------------------------

function route() {
  const hash = location.hash.slice(1) || "assistant";
  const [view, arg] = hash.split("/");
  const name = VIEWS.includes(view) && (view !== "document" || arg) ? view : "assistant";
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== name;
  const navName = name === "document" ? "procedures" : name;
  for (const a of document.querySelectorAll(".topnav a")) {
    if (a.dataset.view === navName) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  if (name === "document") openDocument(decodeURIComponent(arg));
  if (name === "assistant") $("question").focus({ preventScroll: true });
  window.scrollTo({ top: 0 });
}
window.addEventListener("hashchange", route);

// --- Shield switch -----------------------------------------------------------------

function setShield(on) {
  shieldOn = on;
  $("shield-toggle").setAttribute("aria-checked", String(on));
  $("shield-state").textContent = on ? "On" : "Off";
}
$("shield-toggle").addEventListener("click", () => {
  setShield(!shieldOn);
  toast(shieldOn ? "RAG Shield on: sources are checked before the AI sees them."
                 : "RAG Shield off: the assistant trusts every document it finds.");
});

// --- Documents: sidebar, library, safety links -------------------------------------

function docLabel(doc) {
  return doc.shared ? "Shared upload · added today" : `Controlled procedure · ${doc.doc_id}`;
}

function renderDocuments() {
  const fresh = (doc) => knownDocs && !knownDocs.has(doc.doc_id);

  const side = $("docs");
  side.replaceChildren();
  for (const doc of documents) {
    const item = el("li", fresh(doc) ? "new" : "");
    const a = link(`#document/${doc.doc_id}`);
    a.append(el("span", "doc-name", doc.title), el("span", "doc-meta", docLabel(doc)));
    item.append(a);
    side.append(item);
  }

  const query = $("filter").value.trim().toLowerCase();
  const rows = $("doc-rows");
  rows.replaceChildren();
  const shown = documents.filter((d) => !query || `${d.title} ${d.doc_id}`.toLowerCase().includes(query));
  for (const doc of shown) {
    const row = el("tr", fresh(doc) ? "new" : "");
    const title = el("td");
    title.append(link(`#document/${doc.doc_id}`, doc.title));
    const type = el("td");
    type.append(el("span", doc.shared ? "tag shared" : "tag", doc.shared ? "Shared upload" : "Controlled procedure"));
    const open = el("td");
    open.append(link(`#document/${doc.doc_id}`, "Read"));
    row.append(title, el("td", "", doc.doc_id), type, open);
    rows.append(row);
  }
  $("no-match").hidden = shown.length > 0;

  const safety = $("safety-docs");
  safety.replaceChildren();
  for (const doc of documents.filter((d) => !d.shared && /emergency|escalation|response/i.test(d.title))) {
    const item = el("li");
    item.append(link(`#document/${doc.doc_id}`, doc.title));
    safety.append(item);
  }

  knownDocs = new Set(documents.map((d) => d.doc_id));
}
$("filter").addEventListener("input", renderDocuments);

// Headings, lists and paragraphs only, built with textContent so nothing in a
// document can become markup.
function renderDocText(target, text, title) {
  target.replaceChildren();
  let list = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line.startsWith("- ") && !line.startsWith("* ")) list = null;
    if (!line) continue;
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      if (heading[1].length === 1 && heading[2] === title) continue;  // already the page title
      target.append(el(heading[1].length <= 2 ? "h2" : "h3", "", heading[2]));
    } else if (line.startsWith("- ") || line.startsWith("* ")) {
      if (!list) { list = el("ul"); target.append(list); }
      list.append(el("li", "", line.slice(2)));
    } else {
      target.append(el("p", "", line.replace(/\*\*/g, "")));
    }
  }
}

let currentDoc = null;
async function openDocument(docId) {
  currentDoc = null;
  $("doc-title").textContent = "Loading...";
  $("doc-meta").textContent = "";
  $("doc-text").textContent = "";
  try {
    const doc = await api(`/api/doc/${encodeURIComponent(docId)}`);
    currentDoc = doc;
    $("doc-title").textContent = doc.title;
    $("doc-meta").textContent = doc.shared
      ? `${doc.doc_id} · Shared upload · not reviewed`
      : `${doc.doc_id} · Owner: ${doc.owner} · Version ${doc.version}`;
    renderDocText($("doc-text"), doc.text, doc.title);
  } catch (error) {
    $("doc-title").textContent = "Document unavailable";
    $("doc-text").textContent = error.message;
  }
}
$("doc-ask").addEventListener("click", () => {
  if (!currentDoc) return;
  $("question").value = `What does the ${currentDoc.title} say I should do?`;
  location.hash = "#assistant";
});

// --- State from the server ---------------------------------------------------------

function renderState(state) {
  $("model").textContent = state.model;
  // Newest shared uploads first, where people would notice them.
  documents = [...state.documents].sort((a, b) => Number(b.shared) - Number(a.shared));
  renderDocuments();

  const pill = (id, text, kind) => {
    const node = $(id);
    node.textContent = text;
    node.className = `pill ${kind || ""}`;
  };
  pill("bulletin-state", { absent: "Not posted", live: "Live in shared documents",
                           quarantined: "Caught and quarantined" }[state.bulletin],
       { live: "live", quarantined: "caught" }[state.bulletin]);
  $("upload-bulletin").disabled = state.bulletin === "live";
  renderScenarios(state.scenarios);

  const list = $("alerts");
  list.replaceChildren();
  if (!state.alerts.length) {
    list.append(el("li", "quiet", "No alerts. RAG Shield raises them when it catches something."));
  }
  for (const alert of state.alerts) {
    const item = el("li");
    item.append(el("span", "alert-kind", `${ALERT_NAMES[alert.kind] || alert.kind} · ${time(alert.time)}`));
    item.append(el("span", "", alert.detail));
    list.append(item);
  }
}

const SCENARIO_STATUS = {
  original: ["Original", ""], tampered: ["Edited", "live"],
  quarantined: ["Quarantined", "caught"], restored: ["Caught, signed copy restored", "caught"],
};
function renderScenarios(scenarios) {
  const list = $("scenarios");
  list.replaceChildren();
  for (const s of scenarios) {
    const item = el("li", "scenario");
    const head = el("div", "step-head");
    head.append(el("strong", "", s.label));
    const [text, kind] = SCENARIO_STATUS[s.status];
    head.append(el("span", `pill ${kind}`, text));
    const buttons = el("div", "scenario-actions");
    const edit = el("button", "action", "Edit");
    edit.type = "button";
    edit.disabled = s.status === "tampered" || s.status === "quarantined";
    edit.addEventListener("click", () => simulate("/api/sim/tamper-procedure",
      `${s.label}: procedures edited. Ask it with RAG Shield off, then on.`, { scenario: s.key }));
    const use = el("button", "action secondary", "Ask it");
    use.type = "button";
    use.addEventListener("click", () => {
      closePresenter();
      location.hash = "#assistant";
      ask(s.question);
    });
    buttons.append(edit, use);
    item.append(head, el("p", "", s.summary), buttons);
    list.append(item);
  }
  $("tamper-all").disabled = scenarios.some((s) => s.status === "tampered" || s.status === "quarantined");
}

async function refresh() {
  try {
    renderState(await api("/api/state"));
  } catch (error) {
    $("presenter-status").textContent = error.message;
  }
}

// --- Conversation --------------------------------------------------------------------

function friendlyReason(reason) {
  if (reason.startsWith("file does not match")) return "Changed since two approvers signed it";
  const conflict = reason.match(/^conflicts with (\S+)/);
  if (conflict) return `Contradicts approved procedure ${conflict[1]}`;
  if (reason.startsWith("unapproved source")) return "Not an approved procedure, on a safety question";
  if (reason.startsWith("possible prompt injection")) return "Contains hidden instructions aimed at the AI";
  return reason;
}

function answerText(text) {
  const p = el("p", "answer");
  for (const part of text.split(/(\[(?:DOC-\d+|UNREG-[0-9a-f]+)\])/)) {
    const cite = part.match(/^\[(.+)\]$/);
    if (cite) {
      const chip = el("button", "cite", cite[1]);
      chip.type = "button";
      chip.title = "Open this document";
      chip.addEventListener("click", () => { location.hash = `#document/${cite[1]}`; });
      p.append(chip);
    } else {
      p.append(document.createTextNode(part));
    }
  }
  return p;
}

function applyReveal(item) {
  const data = answers.get(item);
  item.querySelector(".factcheck")?.remove();
  item.classList.remove("flagged");
  if (!revealOn || !data) return;
  const strip = el("div");
  const wrong = data.status === "answered" && data.fact_check.length > 0;
  if (wrong) {
    const fact = data.fact_check[0];
    strip.className = "factcheck wrong";
    strip.append(el("span", "mark", "✗"),
      el("span", "", `Wrong. It says "${fact.claim}", but signed procedure ${fact.source} says: ${fact.approved}`));
    item.classList.add("flagged");
  } else {
    strip.className = "factcheck right";
    strip.append(el("span", "mark", "✓"), el("span", "", data.status === "withheld"
      ? "Safe. No unverified guidance was given."
      : "Consistent with the signed procedures' key facts."));
  }
  item.querySelector(".answer-body").after(strip);
}

function renderAnswer(container, data) {
  container.replaceChildren();
  const head = el("div", "bot-head");
  head.append(el("span", "bot-name", "Field Assistant"));
  head.append(el("span", `mode ${data.shield ? "on" : "off"}`,
    data.shield ? "RAG Shield on" : "RAG Shield off"));
  if (data.seconds) head.append(el("span", "bot-time", `${data.seconds}s`));
  container.append(head);

  const body = el("div", "answer-body");
  if (data.status === "withheld") {
    const box = el("div", "callout withheld");
    box.append(el("strong", "", "Answer withheld by RAG Shield"));
    box.append(el("span", "", WITHHELD[data.withheld_reason] ||
      "The answer couldn't be verified against approved procedures."));
    box.append(el("p", "answer", data.answer));
    body.append(box);
  } else {
    body.append(answerText(data.answer));
  }
  container.append(body);

  // Conflicts the Shield found, in its own words, shown right under the answer.
  const conflicts = data.shield ? (data.conflicts || []) : [];
  for (const line of conflicts) {
    const box = el("div", "callout conflict");
    box.append(el("strong", "", "Conflict:"), document.createTextNode(line.slice("Conflict:".length)));
    container.append(box);
  }

  const earlier = data.earlier_conflicts || [];
  const earlierRestored = data.earlier_restored || [];
  if (earlier.length || earlierRestored.length) {
    const box = el("div", "callout earlier");
    box.append(el("strong", "", "Caught earlier by RAG Shield"));
    box.append(el("span", "", "These edits were caught while checking an earlier question, " +
      "and the signed versions were restored before this answer."));
    const list = el("ul");
    for (const line of earlier) list.append(el("li", "", line));
    for (const doc of earlierRestored) list.append(el("li", "", `${doc.doc_id} ${doc.title}: signed version restored`));
    box.append(list);
    container.append(box);
  }

  const restored = data.restored || [];
  if (restored.length) {
    const box = el("div", "callout restored");
    const ids = restored.map((d) => d.doc_id).join(", ");
    box.append(el("strong", "", `Signed version${restored.length > 1 ? "s" : ""} of ${ids} restored`));
    box.append(el("span", "", `The live ${restored.length > 1 ? "copies had" : "copy had"} been altered. ` +
      "RAG Shield quarantined them, restored the versions two approvers signed from the protected " +
      "archive, and answered from those."));
    const list = el("ul");
    for (const doc of restored) list.append(el("li", "", `${doc.doc_id} ${doc.title}`));
    box.append(list);
    container.append(box);
  }

  if (data.shield && data.blocked.length) {
    const box = el("div", "callout shield");
    const n = data.blocked.length;
    box.append(el("strong", "", `RAG Shield blocked ${n} document${n > 1 ? "s" : ""} before the AI saw ${n > 1 ? "them" : "it"}`));
    const list = el("ul");
    for (const doc of data.blocked) {
      const tampered = doc.reasons.some((r) => r.startsWith("file does not match"));
      const reasons = doc.reasons.filter((r) => !(tampered && r.startsWith("unapproved source")));
      list.append(el("li", "", `${doc.title}: ${reasons.map(friendlyReason).join("; ")}`));
    }
    box.append(list);
    if (data.quarantined.length) box.append(el("span", "", "Moved to quarantine and reported to the security team."));
    container.append(box);
  }

  if (data.sources.length) {
    const wrap = el("div", "sources");
    wrap.append(el("h4", "", "Sources"));
    const list = el("ul");
    for (const source of data.sources) {
      const item = el("li");
      item.append(link(`#document/${source.doc_id}`, source.title), el("span", "doc-id", source.doc_id));
      if (data.shield) {  // an ordinary assistant has no idea which sources are trustworthy
        const [label, kind] = TRUST[source.trust] || [source.trust, "unverified"];
        item.append(el("span", `trust ${kind}`, label));
      }
      list.append(item);
    }
    wrap.append(list);
    container.append(wrap);
  }

  const otherNotes = data.shield ? data.warnings.filter((w) => !w.startsWith("Conflict:")) : [];
  if (otherNotes.length) {
    const notes = el("ul", "notes");
    for (const warning of otherNotes) notes.append(el("li", "", warning));
    container.append(notes);
  }
  answers.set(container, data);
  applyReveal(container);
}

async function ask(question) {
  question = question.trim();
  if (!question || busy) return;
  if (location.hash && location.hash !== "#assistant") location.hash = "#assistant";
  busy = true;
  $("ask-button").disabled = true;
  $("empty").hidden = true;
  const thread = $("thread");
  thread.append(el("li", "msg user", question));
  const reply = el("li", "msg bot");
  const thinking = el("div", "thinking");
  const dots = el("span", "dots");
  dots.append(el("span"), el("span"), el("span"));
  thinking.append(dots, el("span", "", shieldOn
    ? "Checking sources with RAG Shield and drafting an answer"
    : "Searching documents and drafting an answer"));
  reply.append(thinking);
  thread.append(reply);
  reply.scrollIntoView({ behavior: "smooth", block: "end" });
  try {
    renderAnswer(reply, await api("/api/ask", { question, shield: shieldOn }));
  } catch (error) {
    reply.replaceChildren(el("div", "callout error", error.message));
  } finally {
    busy = false;
    $("ask-button").disabled = false;
    reply.scrollIntoView({ behavior: "smooth", block: "nearest" });
    refresh();
  }
}

$("ask").addEventListener("submit", (event) => {
  event.preventDefault();
  if (busy) {
    toast("Still answering the last question. Ask again in a moment.");
    return;
  }
  const box = $("question");
  const question = box.value;
  box.value = "";
  ask(question);
});
$("question").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    $("ask").requestSubmit();
  }
});
$("clear-chat").addEventListener("click", () => {
  $("thread").replaceChildren();
  $("empty").hidden = false;
});
for (const text of SUGGESTIONS) {
  const button = el("button", "", text);
  button.type = "button";
  button.addEventListener("click", () => {
    if (busy) toast("Still answering the last question. Ask again in a moment.");
    else ask(text);
  });
  $("suggestions").append(button);
}

// --- Sharing a document ----------------------------------------------------------------

$("upload-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 20000 * 4) {
    $("upload-status").textContent = "That file is too large.";
    $("upload-status").className = "form-status error";
    return;
  }
  $("upload-text").value = await file.text();
  if (!$("upload-name").value) $("upload-name").value = file.name.replace(/\.(md|txt)$/i, "");
});
$("upload").addEventListener("submit", async (event) => {
  event.preventDefault();
  const status = $("upload-status");
  status.className = "form-status";
  status.textContent = "Sharing...";
  try {
    const result = await api("/api/upload", { name: $("upload-name").value, text: $("upload-text").value });
    renderState(result);
    $("upload").reset();
    status.className = "form-status ok";
    status.textContent = "Shared. It's now in Shared documents, and the assistant can find it.";
    toast("Document shared with Station 41.");
  } catch (error) {
    status.className = "form-status error";
    status.textContent = error.message;
  }
});

// --- My shift checklist ------------------------------------------------------------------

function loadTicks() {
  try { return JSON.parse(localStorage.getItem("portal-shift-ticks") || "[]"); } catch { return []; }
}
function saveTicks(ticks) {
  try { localStorage.setItem("portal-shift-ticks", JSON.stringify(ticks)); } catch { /* private mode */ }
}
function renderChecklist() {
  const ticks = new Set(loadTicks());
  const list = $("checklist");
  list.replaceChildren();
  TASKS.forEach(([task, note], i) => {
    const item = el("li");
    const label = el("label");
    const box = el("input");
    box.type = "checkbox";
    box.checked = ticks.has(i);
    box.addEventListener("change", () => {
      const now = new Set(loadTicks());
      box.checked ? now.add(i) : now.delete(i);
      saveTicks([...now]);
      renderChecklist();
    });
    const text = el("span");
    text.append(el("strong", "", task), el("span", "task-note", note));
    label.append(box, text);
    item.append(label);
    list.append(item);
  });
  $("shift-progress").textContent = `${ticks.size} of ${TASKS.length} done`;
}
$("reset-checklist").addEventListener("click", () => { saveTicks([]); renderChecklist(); });

// --- Presenter panel -----------------------------------------------------------------------

let returnFocus = null;
function openPresenter() {
  returnFocus = document.activeElement;
  $("presenter").hidden = false;
  $("scrim").hidden = false;
  $("presenter-close").focus();
  refresh();
}
function closePresenter() {
  $("presenter").hidden = true;
  $("scrim").hidden = true;
  if (returnFocus) returnFocus.focus();
}
$("presenter-open").addEventListener("click", openPresenter);
$("presenter-close").addEventListener("click", closePresenter);
$("scrim").addEventListener("click", closePresenter);
document.addEventListener("keydown", (event) => {
  if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "s") {
    event.preventDefault();
    $("presenter").hidden ? openPresenter() : closePresenter();
  } else if (event.key === "Escape" && !$("presenter").hidden) {
    closePresenter();
  }
});

$("reveal-toggle").addEventListener("click", () => {
  revealOn = !revealOn;
  $("reveal-toggle").setAttribute("aria-checked", String(revealOn));
  $("reveal-state").textContent = revealOn ? "On" : "Off";
  for (const item of document.querySelectorAll(".msg.bot")) applyReveal(item);
});

async function simulate(path, message, body = {}) {
  const status = $("presenter-status");
  status.textContent = "Working...";
  for (const button of document.querySelectorAll(".presenter button.action")) button.disabled = true;
  try {
    renderState(await api(path, body));
    status.textContent = message;
  } catch (error) {
    status.textContent = error.message;
    refresh();
  } finally {
    $("reset").disabled = false;
    $("use-question").disabled = false;
  }
}
$("upload-bulletin").addEventListener("click", () =>
  simulate("/api/sim/upload-bulletin", "Fake bulletin posted to Shared documents."));
$("tamper-all").addEventListener("click", () =>
  simulate("/api/sim/tamper-procedure", "All four edited. Ask each question with RAG Shield off first.",
           { scenario: "all" }));
$("reset").addEventListener("click", async () => {
  await simulate("/api/sim/reset", "Scenario reset: original procedures, no uploads, no alerts.");
  $("thread").replaceChildren();
  $("empty").hidden = false;
  setShield(true);
});
$("use-question").addEventListener("click", () => {
  $("question").value = SUGGESTIONS[0];
  closePresenter();
  location.hash = "#assistant";
  $("question").focus();
});

renderChecklist();
refresh();
route();
