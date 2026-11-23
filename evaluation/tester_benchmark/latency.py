"""Per-request latency, Shield ON vs OFF, single user, clean state, via the HTTP API.

Interleaves ON/OFF to spread drift. One warm-up request each (discarded).
Records client wall time and the server's latency_seconds.
Run: .venv/bin/python -m evaluation.tester_benchmark.latency [--n 20]
"""
import argparse, json, statistics, time, urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8600"
QS = ["There is a gas leak at the Meter Building. What should I do?",
      "Which valve isolates a leak at the Meter Building?"]


def post(path, body):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
    t = time.perf_counter()
    with urllib.request.urlopen(req, timeout=300) as r:
        d = json.loads(r.read())
    return d, time.perf_counter() - t


def pct(xs, p):
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--n", type=int, default=20); a = ap.parse_args()
    post("/api/sim/reset", {})
    res = {True: [], False: []}
    for q in QS:
        post("/api/ask", {"question": q, "shield": True, "user": "jreyes"})
        post("/api/ask", {"question": q, "shield": False, "user": "jreyes"})
    rows = []
    for i in range(a.n):
        q = QS[i % 2]
        for shield in ((True, False) if i % 2 == 0 else (False, True)):
            d, wall = post("/api/ask", {"question": q, "shield": shield, "user": "jreyes"})
            res[shield].append(wall)
            rows.append({"i": i, "q": q, "shield": shield, "wall": round(wall, 3),
                         "server": d.get("latency_seconds"), "decision": d.get("decision")})
            print(rows[-1], flush=True)
    summary = {}
    for shield, xs in res.items():
        summary["on" if shield else "off"] = {"n": len(xs), "p50": round(statistics.median(xs), 2),
                                             "p95": round(pct(xs, 0.95), 2), "mean": round(statistics.mean(xs), 2)}
    summary["added_p50"] = round(summary["on"]["p50"] - summary["off"]["p50"], 2)
    summary["added_p95"] = round(summary["on"]["p95"] - summary["off"]["p95"], 2)
    print(json.dumps(summary, indent=1))
    Path(__file__).resolve().parent.joinpath("results", "latency.json").write_text(
        json.dumps({"summary": summary, "rows": rows}, indent=1))
    post("/api/sim/reset", {})


if __name__ == "__main__":
    main()
