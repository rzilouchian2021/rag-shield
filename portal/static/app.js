// Technician portal (Interface A). Text from the assistant and from documents is only
// ever inserted with textContent, never as HTML, so a poisoned document can't inject markup.
"use strict";

const $ = (id) => document.getElementById(id);
const VIEWS = ["assistant", "procedures", "document", "safety", "shift"];
const DECISION_TEXT = {
  allow: "Allowed", warn: "Warning", redact: "Unsafe content removed", block: "Blocked", none: "Not checked",
};
const CATEGORY_TEXT = {
  clean: "Clean", poisoning: "Poisoned document", prompt_injection: "Prompt injection",
  data_conflict: "Conflicts with live data", authorization: "Access control",
  unverified: "Unverified source", system: "System check failed", unprotected: "RAG Shield off",
  step_up: "Verification needed (another station)", break_glass: "Out-of-region emergency access",
};
const TASKS = [
  ["Walk down the Meter Building", "Check the methane detector display and the meter runs."],
  ["Record pressure readings", "Meter runs 1 and 2, start of shift and every four hours."],
  ["Review open work orders", "Confirm permits before any work near gas piping."],
  ["Check access to isolation valve IV-7", "The north side path must be clear."],
  ["Hand over to night shift", "Note any open alarms for the incoming technician."],
];

let state = null;
let user = "jreyes";
let shieldOn = true;
let busy = false;
let knownDocs = null;

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
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({ error: "Unexpected response" }));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

// --- Navigation --------------------------------------------------------------------

function route() {
  const [view, arg] = (location.hash.slice(1) || "assistant").split("/");
  const name = VIEWS.includes(view) && (view !== "document" || arg) ? view : "assistant";
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== name;
  const navName = name === "document" ? "procedures" : name;
  for (const a of document.querySelectorAll(".topnav a")) {
    if (a.dataset.view === navName) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  if (name === "document") openDocument(decodeURIComponent(arg));
  window.scrollTo({ top: 0 });
}
window.addEventListener("hashchange", route);

// --- User and shield switch ----------------------------------------------------------

function currentUser() {
  return state ? state.users.find((u) => u.id === user) : null;
}
$("user-select").addEventListener("change", (event) => {
  user = event.target.value;
  const u = currentUser();
  $("avatar").textContent = u.name.split(" ").map((w) => w[0]).join("");
  toast(`Signed in as ${u.name}, ${u.title}.`);
  renderDocuments();
  if (location.hash.startsWith("#document/")) route();
});
function setShield(on) {
  shieldOn = on;
  $("shield-toggle").setAttribute("aria-checked", String(on));
  $("shield-state").textContent = on ? "On" : "Off";
}
$("shield-toggle").addEventListener("click", () => {
  setShield(!shieldOn);
  toast(shieldOn ? "RAG Shield on: every source and answer is checked."
                 : "RAG Shield off: the assistant trusts every document it finds.");
});

// --- State: users, sensors, documents, scenarios ----------------------------------------

function renderState(next) {
  state = next;
  $("model").textContent = state.model;
  const select = $("user-select");
  if (!select.options.length) {
    for (const u of state.users) {
      const option = el("option", "", `${u.name} · ${u.title} · ${u.site}`);
      option.value = u.id;
      select.append(option);
    }
  }
  const s = state.sensors;
  const sensors = $("sensors");
  sensors.replaceChildren();
  const fact = (term, value, alarm) => {
    const row = el("div");
    row.append(el("dt", "", term), el("dd", alarm ? "alarm" : "", value));
    sensors.append(row);
  };
  const methane = s.methane_ppm["Meter Building"];
  fact("Methane, Meter Bldg", `${methane.toLocaleString()} ppm`, methane >= 5000);
  fact("Wind", `from the ${{ N: "north", S: "south", E: "east", W: "west" }[s.wind.from]}, ${s.wind.mph} mph`,
       s.wind.from === "N");
  fact("Pressure, run 2", `${s.pressure_psig["Meter run 2"]} psig`);
  $("sensor-time").textContent = `Updated ${new Date(s.updated).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.`;
  renderDocuments();

  const pill = (id, text, kind) => { $(id).textContent = text; $(id).className = `pill ${kind || ""}`; };
  const B = state.scenarios.B, C = state.scenarios.C, D = state.scenarios.D;
  pill("state-B", { clean: "Clean", poisoned: "Poisoned", quarantined: "Quarantined" }[B],
       { poisoned: "live", quarantined: "caught" }[B]);
  pill("state-C", { clean: "Clean", injected: "Injected", caught: "Caught" }[C],
       { injected: "live", caught: "caught" }[C]);
  pill("state-D", D === "north" ? "Wind from north" : "Wind from south", D === "north" ? "live" : "");
  $("sim-poison").disabled = B !== "clean";
  $("sim-inject").disabled = C === "injected";
  $("sim-wind").textContent = D === "north" ? "Wind back to south" : "Wind from north";

  const list = $("alerts");
  list.replaceChildren();
  if (!state.alerts.length) list.append(el("li", "quiet", "No alerts yet."));
  for (const a of state.alerts.slice(0, 6)) {
    const item = el("li");
    item.append(el("span", "alert-kind", a.kind.replaceAll("_", " ")), el("span", "", a.detail));
    list.append(item);
  }
}

function visibleDocs() {
  const u = currentUser();
  if (!state || !u) return [];
  return state.documents.filter((d) => d.roles.includes(u.role))
    .sort((a, b) => Number(b.shared) - Number(a.shared));
}

function siteNote(d) {
  const u = currentUser();
  if (!u || !d.site || d.site === u.site) return "";
  if (d.sensitivity === "emergency") return ` · ${d.site} · break-glass`;
  const granted = (state.grants || []).some((g) => g.user === u.id && g.site === d.site);
  return ` · ${d.site} · ${granted ? "verified" : "PIN required"}`;
}

function renderDocuments() {
  const docs = visibleDocs();
  const fresh = (d) => knownDocs && !knownDocs.has(d.doc_id);
  const side = $("docs");
  side.replaceChildren();
  for (const d of docs) {
    const item = el("li", fresh(d) ? "new" : "");
    const a = link(`#document/${d.doc_id}`);
    a.append(el("span", "doc-name", d.title),
             el("span", "doc-meta", d.shared ? "Shared upload · not reviewed" : `Controlled document · ${d.doc_id}${siteNote(d)}`));
    item.append(a);
    side.append(item);
  }
  const query = $("filter").value.trim().toLowerCase();
  const rows = $("doc-rows");
  rows.replaceChildren();
  const shown = docs.filter((d) => !query || `${d.title} ${d.doc_id}`.toLowerCase().includes(query));
  for (const d of shown) {
    const row = el("tr", fresh(d) ? "new" : "");
    const title = el("td");
    title.append(link(`#document/${d.doc_id}`, d.title));
    const type = el("td");
    type.append(el("span", d.shared ? "tag shared" : "tag", d.shared ? "Shared upload" : "Controlled document"));
    if (siteNote(d)) type.append(el("span", "tag away", siteNote(d).replace(/^ · /, "")));
    const open = el("td");
    open.append(link(`#document/${d.doc_id}`, "Read"));
    row.append(title, el("td", "", d.doc_id), type, open);
    rows.append(row);
  }
  $("no-match").hidden = shown.length > 0;
  const safety = $("safety-docs");
  safety.replaceChildren();
  for (const d of docs.filter((d) => !d.shared && /leak|evacuation|valve/i.test(d.title))) {
    const item = el("li");
    item.append(link(`#document/${d.doc_id}`, d.title));
    safety.append(item);
  }
  knownDocs = new Set(state ? state.documents.map((d) => d.doc_id) : []);
}
$("filter").addEventListener("input", renderDocuments);

async function refresh() {
  try { renderState(await api("/api/state")); } catch (error) { toast(error.message); }
}

// --- Document reader -----------------------------------------------------------------

function renderDocText(target, text, title) {
  target.replaceChildren();
  let list = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!/^\d+\.\s|^[-*]\s/.test(line)) list = null;
    if (!line) continue;
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      if (heading[1].length === 1 && heading[2] === title) continue;
      target.append(el(heading[1].length <= 2 ? "h2" : "h3", "", heading[2]));
    } else if (/^\d+\.\s|^[-*]\s/.test(line)) {
      if (!list) { list = el(/^\d/.test(line) ? "ol" : "ul"); target.append(list); }
      list.append(el("li", "", line.replace(/^(\d+\.|[-*])\s+/, "")));
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
  $("doc-text").replaceChildren();
  try {
    const doc = await api(`/api/doc/${encodeURIComponent(docId)}?user=${encodeURIComponent(user)}`);
    currentDoc = doc;
    $("doc-title").textContent = doc.title;
    $("doc-meta").textContent = doc.shared ? `${doc.doc_id} · Shared upload · not reviewed`
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

// --- Conversation ------------------------------------------------------------------------

function answerText(text) {
  const p = el("p", "answer");
  for (const part of text.split(/(\[(?:DOC-\d+|UNREG-[0-9a-f]+|WO-\d+)\])/)) {
    const cite = part.match(/^\[(DOC-\d+|UNREG-[0-9a-f]+)\]$/);
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

function stepUpForm(d, question) {
  const site = d.step_up.site;
  const form = el("form", "step-up");
  const input = el("input");
  input.type = "password"; input.inputMode = "numeric"; input.autocomplete = "off";
  input.maxLength = 8; input.id = `pin-${d.request_id}`; input.required = true;
  const label = el("label", "", `Your PIN (unlocks ${site} for 15 minutes)`);
  label.htmlFor = input.id;
  const button = el("button", "action", "Verify");
  button.type = "submit";
  const msg = el("p", "step-up-msg");
  msg.setAttribute("role", "status");
  const row = el("div", "step-up-row");
  row.append(input, button);
  form.append(label, row, msg);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    button.disabled = true;
    try {
      const r = await api("/api/step-up", { user, site, pin: input.value });
      input.value = "";
      if (r.granted) {
        msg.textContent = `Verified for ${r.site} for ${r.minutes} minutes. Asking again...`;
        ask(question);
      } else {
        msg.textContent = r.message;
        button.disabled = Boolean(r.locked);
      }
    } catch (error) {
      msg.textContent = error.message;
      button.disabled = false;
    }
  });
  return form;
}

function renderAnswer(container, d, question) {
  container.replaceChildren();
  const head = el("div", "bot-head");
  head.append(el("span", "bot-name", "Field Assistant"),
              el("span", `mode ${d.shield ? "on" : "off"}`, d.shield ? "RAG Shield on" : "RAG Shield off"));
  if (d.shield) head.append(el("span", `decision ${d.decision}`, DECISION_TEXT[d.decision]));
  head.append(el("span", "bot-time", `${d.latency_seconds}s · ${d.request_id}`));
  container.append(head);

  let answer = d.answer;
  if (d.decision === "warn" && answer.startsWith("Warning:")) {
    const [warning, ...rest] = answer.split("\n\n");
    const box = el("div", "callout conflict");
    const heading = (d.break_glass || []).length && /out-of-region/.test(warning)
      ? "Out-of-region emergency access." : "Check live conditions first.";
    box.append(el("strong", "", heading), document.createTextNode(" " + warning.replace(/^Warning:\s*/, "")));
    container.append(box);
    answer = rest.join("\n\n");
  }
  if (d.decision === "block" && d.step_up && d.step_up.site) {
    const box = el("div", "callout withheld step");
    box.append(el("strong", "", "Verification needed"), el("p", "answer", answer), stepUpForm(d, question));
    container.append(box);
  } else if (d.decision === "block") {
    const box = el("div", "callout withheld");
    box.append(el("strong", "", "RAG Shield blocked this answer"), el("p", "answer", answer));
    container.append(box);
  } else {
    container.append(answerText(answer));
  }

  if (d.shield && d.step_up && d.step_up.offered) {
    const box = el("div", "callout withheld step");
    box.append(el("strong", "", `More may be available for ${d.step_up.site}`),
               el("p", "answer", `A sensitive ${d.step_up.site} document also matched and was kept out. Verify with your PIN to include it.`),
               stepUpForm(d, question));
    container.append(box);
  }
  if (d.shield) {
    const why = el("div", `callout why ${d.decision}`);
    why.append(el("strong", "", `Why: ${CATEGORY_TEXT[d.category] || d.category}`), el("span", "", d.explanation));
    if (d.restricted_count && d.decision !== "block") {
      why.append(el("span", "", ` ${d.restricted_count} document(s) you can't access were left out.`));
    }
    container.append(why);
    for (const line of d.conflicts) {
      const box = el("div", "callout conflict");
      box.append(el("strong", "", "Conflict:"), document.createTextNode(line.slice("Conflict:".length)));
      container.append(box);
    }
  }

  const shown = d.sources.filter((s) => d.shield || s.status === "used");
  if (shown.length) {
    const wrap = el("div", "sources");
    wrap.append(el("h4", "", "Sources"));
    const list = el("ul");
    for (const s of shown) {
      const item = el("li");
      item.append(s.status === "used" ? link(`#document/${s.doc_id}`, s.title) : el("span", "", s.title),
                  el("span", "doc-id", s.doc_id));
      if (d.shield) {
        const label = s.status === "used" ? (s.reasons.length ? "Signed version restored" : "Approved, signed")
          : "Excluded";
        item.append(el("span", `trust ${s.status === "used" ? "approved" : "modified"}`, label));
        if (s.status !== "used") item.append(el("span", "source-reason", s.reasons.join("; ")));
      }
      list.append(item);
    }
    wrap.append(list);
    container.append(wrap);
  }
}

async function ask(question) {
  question = question.trim();
  if (!question) return;
  if (busy) { toast("Still answering the last question. Ask again in a moment."); return; }
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
  thinking.append(dots, el("span", "", shieldOn ? "Checking access, sources and live data with RAG Shield"
                                                : "Searching documents and drafting an answer"));
  reply.append(thinking);
  thread.append(reply);
  reply.scrollIntoView({ behavior: "smooth", block: "end" });
  try {
    renderAnswer(reply, await api("/api/ask", { question, shield: shieldOn, user }), question);
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
  if (busy) { toast("Still answering the last question. Ask again in a moment."); return; }
  const box = $("question");
  const question = box.value;
  box.value = "";
  ask(question);
});
$("question").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); $("ask").requestSubmit(); }
});
$("clear-chat").addEventListener("click", () => { $("thread").replaceChildren(); $("empty").hidden = false; });

function renderSuggestions() {
  const box = $("suggestions");
  const seen = new Set();
  for (const list of Object.values(state.questions)) {
    for (const q of list) {
      if (seen.has(q)) continue;
      seen.add(q);
      const b = el("button", "", q);
      b.type = "button";
      b.addEventListener("click", () => ask(q));
      box.append(b);
    }
  }
}

// --- Sharing a document --------------------------------------------------------------------

$("upload-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 80000) { $("upload-status").textContent = "That file is too large."; return; }
  $("upload-text").value = await file.text();
  if (!$("upload-name").value) $("upload-name").value = file.name.replace(/\.(md|txt)$/i, "");
});
$("upload").addEventListener("submit", async (event) => {
  event.preventDefault();
  const status = $("upload-status");
  status.className = "form-status";
  status.textContent = "Sharing...";
  try {
    renderState(await api("/api/upload", { name: $("upload-name").value, text: $("upload-text").value, user }));
    $("upload").reset();
    status.className = "form-status ok";
    status.textContent = "Shared. It's now in Shared documents, and the assistant can find it.";
  } catch (error) {
    status.className = "form-status error";
    status.textContent = error.message;
  }
});

// --- My shift checklist -------------------------------------------------------------------

function loadTicks() { try { return JSON.parse(localStorage.getItem("portal-shift-ticks-kb") || "[]"); } catch { return []; } }
function saveTicks(t) { try { localStorage.setItem("portal-shift-ticks-kb", JSON.stringify(t)); } catch { /* private mode */ } }
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

// --- Presenter panel --------------------------------------------------------------------------

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

async function simulate(path, message) {
  const status = $("presenter-status");
  status.textContent = "Working...";
  for (const b of document.querySelectorAll(".presenter button.action")) b.disabled = true;
  try {
    renderState(await api(path, {}));
    status.textContent = message;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    for (const b of document.querySelectorAll(".presenter button.action.secondary")) b.disabled = false;
    $("sim-wind").disabled = false;
    refresh();
  }
}
$("sim-poison").addEventListener("click", () => simulate("/api/sim/poison", "Valve list and evacuation route edited."));
$("sim-inject").addEventListener("click", () => simulate("/api/sim/inject", "WO-2290 posted to Shared documents."));
$("sim-tamper").addEventListener("click", () => simulate("/api/sim/tamper-log", "Latest audit entry rewritten. Check the console's Integrity panel."));
$("sim-wind").addEventListener("click", () => {
  const north = state && state.scenarios.D === "north";
  simulate(north ? "/api/sim/wind-south" : "/api/sim/wind-north",
           north ? "Wind back from the south." : "Wind now from the north at 14 mph.");
});
$("reset").addEventListener("click", async () => {
  await simulate("/api/sim/reset", "Reset: signed documents, wind from the south, no alerts.");
  $("thread").replaceChildren();
  $("empty").hidden = false;
  setShield(true);
});
for (const b of document.querySelectorAll("[data-ask]")) {
  b.addEventListener("click", () => {
    const [key, index] = [b.dataset.ask[0], Number(b.dataset.ask.slice(1))];
    closePresenter();
    location.hash = "#assistant";
    ask(state.questions[key][index]);
  });
}

(async () => {
  renderChecklist();
  await refresh();
  if (state) renderSuggestions();
  route();
})();
