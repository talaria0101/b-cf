#!/usr/bin/env python3
"""
Probe 3: does the Worker's own AbortController fire before workerd's hung-code
detector, and is a wall-clock deadline observable at all in `workerd serve`?

Observed so far:
  probe_timeout.py    never-answering peer -> cancelled at a flat 5.0s, any budget
  probe_slow_upstream  peer sleeping 3/10/20s -> ALL completed at a flat 6.0s
                      budget=1000ms vs 30000ms vs 60000ms -> all 6.0s
                      budget=1000ms + 10s peer -> AbortError, but still at 6.0s

Candidate 1: workerd serve virtualises timers, so setTimeout does not track wall
  clock. Predicts: elapsed is independent of both the peer's sleep and our budget.
Candidate 2: the hung-code detector is a fixed ~5s wall deadline and any timer
  below it loses the race. Predicts: every abort path reports workerd's message.
Candidate 3: the host is slow and both effects are the same measurement.
  Predicts: a peer sleeping 0s would also take ~6s. (rules this out cheaply)

Run: python3 harness/probe_timer_semantics.py
"""

import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rig import Rig  # noqa: E402

TUNED = """
const BUDGET_MS = __BUDGET__;
export default {
	async fetch(request) {
		const target = new URL(request.url).pathname.slice(1);
		const c = new AbortController();
		const t = setTimeout(() => c.abort(), BUDGET_MS);
		const t0 = Date.now();
		try {
			const r = await fetch(target, { signal: c.signal });
			clearTimeout(t);
			const b = await r.text();
			return new Response("OK worker_ms=" + (Date.now() - t0) + " " + b.slice(0, 30), { status: r.status });
		} catch (e) {
			clearTimeout(t);
			return new Response("ERR:" + (e && e.name) + "|worker_ms=" + (Date.now() - t0) + "|" + (e && e.message), { status: 502 });
		}
	},
};
"""

def measure(worker_src, name, path, client_timeout=90):
    with Rig(worker_src, name) as rig:
        t0 = time.time()
        st, hd, body = rig.get(path, timeout=client_timeout)
        return time.time() - t0, st, (body or "").replace("\n", " ")[:130]


def main():
    tmp = tempfile.mkdtemp(prefix="probetimer-")
    try:
        print("STEP 1: does the PEER's sleep length matter at all? (budget 60s)")
        w = os.path.join(tmp, "w0.js")
        with open(w, "w") as fh:
            fh.write(TUNED.replace("__BUDGET__", "60000"))
        for secs in (0, 1, 3, 10):
            el, st, body = measure(w, "s%d" % secs,
                                   "/https://origin.test/__ctl/slow?s=%d" % secs,
                                   client_timeout=90)
            print("  peer sleeps %2ds -> wall=%5.1fs status=%s %s" % (secs, el, st, body[:70]))

        print("\nSTEP 2: does OUR budget move wall time at all? (peer sleeps 30s)")
        for budget in (100, 1000, 5000, 60000):
            p = os.path.join(tmp, "b%d.js" % budget)
            with open(p, "w") as fh:
                fh.write(TUNED.replace("__BUDGET__", str(budget)))
            el, st, body = measure(p, "b%d" % budget,
                                   "/https://origin.test/__ctl/slow?s=30",
                                   client_timeout=90)
            print("  budget=%6dms -> wall=%5.1fs status=%s %s" % (budget, el, st, body[:60]))

        print("\nSTEP 3: never-answering peer, short budgets (race vs the 5s detector)")
        for budget in (100, 250, 1000, 3000):
            p = os.path.join(tmp, "h%d.js" % budget)
            with open(p, "w") as fh:
                fh.write(TUNED.replace("__BUDGET__", str(budget)))
            el, st, body = measure(p, "h%d" % budget,
                                   "/https://origin.test/__ctl/hang",
                                   client_timeout=90)
            print("  budget=%6dms -> wall=%5.1fs status=%s %s" % (budget, el, st, body[:56]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()