// Security console (Interface B). Reads the same backend as the technician portal.
// All text is inserted with textContent only.
"use strict";

const $ = (id) => document.getElementById(id);
const CATEGORY = {
  clean: "Clean", poisoning: "Poisoning", prompt_injection: "Prompt injection",
  data_conflict: "Data conflict", authorization: "Authorization", unverified: "Unverified source",
  system: "System failure", unprotected: "RAG Shield off",
  step_up: "Step-up required", break_glass: "Break-glass access",
};
const DECISION = { allow: "Allow", warn: "Warn", redact: "Redact", block: "Block", none: "No checks" };
const STATUS = { used: "Used", excluded: "Excluded", restricted: "Removed (access)" };
const open = new Set();  // request IDs whose audit entry is expanded
let lastKey = "";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function time(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function card(d) {
  const item = el("li", `request ${d.decision}`);
  const head = el("div", "request-head");
  head.append(el("span", "request-time", time(d.timestamp)), el("code", "request-id", d.request_id),
              el("span", "request-user", `${d.user_name} · ${d.role.replaceAll("_", " ")}`),
              el("span", `chip category ${d.category}`, CATEGORY[d.category] || d.category),
              el("span", `chip decision ${d.decision}`, DECISION[d.decision] || d.decision));
  item.append(head);
  item.append(el("p", "request-why", d.explanation));

  if (d.sources.length) {
    const table = el("table", "request-sources");
    const body = el("tbody");
    for (const s of d.sources) {
      const row = el("tr", s.status);
      row.append(el("td", "", s.doc_id), el("td", "", s.title), el("td", `status ${s.status}`, STATUS[s.status] || s.status),
                 el("td", "", s.reasons.join("; ")));
      body.append(row);
    }
    table.append(body);
    item.append(table);
  }
  for (const c of d.conflicts) item.append(el("p", "request-conflict", c));

  const details = el("details", "audit");
  details.open = open.has(d.request_id);
  details.addEventListener("toggle", () => details.open ? open.add(d.request_id) : open.delete(d.request_id));
  details.append(el("summary", "", `Audit log entry${d.audit_entry.chain_seq !== undefined ? ` · sealed #${d.audit_entry.chain_seq}` : ""}`));
  details.append(el("pre", "", JSON.stringify(d.audit_entry, null, 2)));
  item.append(details);
  return item;
}

function check(ok, good, bad) {
  const li = el("li", ok ? "ok" : "bad");
  li.append(el("span", "mark", ok ? "OK" : "!"), el("span", "", ok ? good : bad));
  return li;
}

async function refreshIntegrity() {
  try {
    const r = await fetch("/api/integrity");
    if (!r.ok) throw new Error();
    const i = await r.json();
    $("integrity").replaceChildren(
      check(i.log_ok, `Audit log verified: ${i.log_entries} sealed entries, chain intact`,
            `Audit log does not verify: ${(i.log_problems[0] || "tampering detected")}`),
      check(!i.orphaned_index_entries.length && !i.unindexed_documents.length,
            "Search index matches the documents",
            `Index mismatch: ${[...i.orphaned_index_entries, ...i.unindexed_documents].join(", ")}`),
      check(!i.unsigned_registry_entries.length, "Every registry entry has two valid signatures",
            `Signatures broken: ${i.unsigned_registry_entries.join(", ")}`));
  } catch {
    $("integrity").replaceChildren(check(false, "", "Integrity check unavailable"));
  }
}

async function refresh() {
  refreshIntegrity();
  try {
    const response = await fetch("/api/console");
    if (!response.ok) throw new Error();
    const data = await response.json();
    $("console-status").textContent = `Live · updated ${time(new Date().toISOString())}`;
    const key = JSON.stringify([data.decisions.map((d) => d.request_id), data.alerts.length]);
    if (key === lastKey) return;
    lastKey = key;
    $("console-empty").hidden = data.decisions.length > 0;
    $("requests").replaceChildren(...data.decisions.map(card));
    const counts = {};
    for (const d of data.decisions) counts[d.decision] = (counts[d.decision] || 0) + 1;
    $("counts").replaceChildren(...Object.entries(counts).map(([k, n]) => el("span", `chip decision ${k}`, `${DECISION[k] || k}: ${n}`)));
    const alerts = $("console-alerts");
    alerts.replaceChildren();
    if (!data.alerts.length) alerts.append(el("li", "quiet", "No alerts."));
    for (const a of data.alerts.slice(0, 12)) {
      const li = el("li");
      li.append(el("span", "alert-kind", `${a.kind.replaceAll("_", " ")} · ${time(a.time)}`), el("span", "", a.detail));
      alerts.append(li);
    }
  } catch {
    $("console-status").textContent = "Not connected. Is the portal server running?";
  }
}
refresh();
setInterval(refresh, 2000);
