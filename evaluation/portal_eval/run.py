"""Run the 100 cases against the real local model, RAG Shield off and on.

Each case runs on a fresh disposable copy (storage/eval_portal, separate from the live
demo): reset, apply the attack, ask. Shield-off and Shield-on runs each get their own
reset, because a Shield-on run quarantines and restores files. Results are appended to
results/runs.jsonl, so an interrupted run resumes where it stopped.

    python -m evaluation.portal_eval.run
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from config.settings import PROJECT_ROOT
from portal import server

HERE = Path(__file__).parent
OUT = HERE / "results" / "runs.jsonl"


def apply_setup(portal: server.Portal, setup: dict) -> None:
    if setup["type"] == "edit":
        path = portal.settings.data_dir / setup["file"]
        text = path.read_text(encoding="utf-8")
        if setup["real"] not in text:
            raise RuntimeError(f"setup text not found in {setup['file']}")
        path.write_text(text.replace(setup["real"], setup["fake"]), encoding="utf-8")
        portal.pipeline.sync()
    elif setup["type"] == "upload":
        portal.upload(setup["name"], setup["text"], "jreyes")


def main() -> None:
    cases = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))
    done = set()
    if OUT.exists():
        for line in OUT.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            done.add((r["id"], r["shield"]))
    server.WORK_DIR = PROJECT_ROOT / "storage" / "eval_portal"
    portal = server.Portal()
    portal.policy.limiter.limit = 10 ** 9   # the per-user rate limit would stop a batch run
    print("warming up the model...", flush=True)
    portal.ask("There is a gas leak at the Meter Building. What should I do?", False, "jreyes")
    total, start = len(cases) * 2, time.time()
    n = len(done)
    with OUT.open("a", encoding="utf-8") as out:
        for case in cases:
            for shield in (False, True):
                if (case["id"], shield) in done:
                    continue
                portal.reset()
                portal.policy.limiter.limit = 10 ** 9
                apply_setup(portal, case["setup"])
                view = portal.ask(case["question"], shield, case["user"])
                full = portal.decisions[-1]
                row = {"id": case["id"], "category": case["category"], "kind": case["kind"],
                       "shield": shield, "user": case["user"], "question": case["question"],
                       "decision": full["decision"], "decision_category": full["category"],
                       "categories": full["categories"], "answer": full["answer"],
                       "latency_seconds": full["latency_seconds"],
                       "sources": [{k: s[k] for k in ("doc_id", "status", "reasons", "shared")}
                                   for s in full["sources"]],
                       "restored": full["restored"], "step_up": full["step_up"],
                       "break_glass": full["break_glass"], "explanation": full["explanation"]}
                out.write(json.dumps(row) + "\n")
                out.flush()
                n += 1
                rate = (time.time() - start) / max(1, n - len(done))
                print(f"[{n}/{total}] {case['id']} shield={'on ' if shield else 'off'} "
                      f"{row['decision']:6} {row['latency_seconds']:5.1f}s  "
                      f"~{(total - n) * rate / 60:.0f} min left", flush=True)
    print("done", flush=True)


if __name__ == "__main__":
    sys.exit(main())
