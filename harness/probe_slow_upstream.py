#!/usr/bin/env python3
"""
Probe 2: a slow-but-COMPLETING upstream, to isolate the Worker's AbortController
from workerd's hung-code detector.

probe_timeout.py established that a never-answering upstream is cancelled by
workerd at a fixed ~5.0s regardless of the worker's own budget:

  "The Workers runtime canceled this request because it detected that your
   Worker's code had hung and would never return"

So v2's UPSTREAM_TIMEOUT_MS cannot be observed against /__ctl/hang. This probe
uses /__ctl/slow?s=N, which answers after N seconds, so the only thing that can
fire first is the worker's own timer.

Candidate: the slow TAP is ALSO cancelled at ~5s (i.e. workerd cancels any
subrequest slower than 5s, not just hung ones).
  Refuted if: a 3s sleep returns at ~3s and a 10s sleep returns at ~10s.
Candidate: workerd's hung-detector only fires when the code never returns, so a
completing peer is fine and our AbortController becomes observable.
  Confirmed if: with a 1s budget a 10s peer yields 502 at ~1s, and with a 30s
  budget the same peer yields 200 at ~10s.

Run: python3 harness/probe_slow_upstream.py
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
		try {
			const r = await fetch(target, { signal: c.signal });
			clearTimeout(t);
			return new Response("OK " + (await r.text()).slice(0, 40), { status: r.status });
		} catch (e) {
			clearTimeout(t);
			return new Response("ERR:" + (e && e.name) + ":" + (e && e.message), { status: 502 });
		}
	},
};
"""

NO_ABORT = """
export default {
	async fetch(request) {
		const target = new URL(request.url).pathname.slice(1);
		try {
			const r = await fetch(target);
			return new Response("OK " + (await r.text()).slice(0, 40), { status: r.status });
		} catch (e) {
			return new Response("ERR:" + (e && e.name) + ":" + (e && e.message), { status: 502 });
		}
	},
};
"""


def run(worker_src, name, path, client_timeout=120):
    with Rig(worker_src, name) as rig:
        t0 = time.time()
        st, hd, body = rig.get(path, timeout=client_timeout)
        el = time.time() - t0
        return el, st, (body or "").replace("\n", " ")[:100]


def main():
    tmp = tempfile.mkdtemp(prefix="probeslow-")
    try:
        print("STEP 1: no AbortController, slow-but-completing peer.")
        w = os.path.join(tmp, "none.js")
        with open(w, "w") as fh:
            fh.write(NO_ABORT)
        for secs in (3, 10, 20):
            el, st, body = run(w, "slow%d" % secs,
                               "/https://origin.test/__ctl/slow?s=%d" % secs,
                               client_timeout=90)
            print("  peer sleeps %2ds -> elapsed=%5.1fs status=%s %s" % (secs, el, st, body[:50]))

        print("\nSTEP 2: with an AbortController, does elapsed track OUR budget?")
        for budget, secs in ((1000, 10), (30000, 10), (3000, 10), (60000, 20)):
            p = os.path.join(tmp, "w-%d-%d.js" % (budget, secs))
            with open(p, "w") as fh:
                fh.write(TUNED.replace("__BUDGET__", str(budget)))
            el, st, body = run(p, "b%d" % budget,
                               "/https://origin.test/__ctl/slow?s=%d" % secs,
                               client_timeout=120)
            verdict = "ABORTED" if st == 502 else "completed"
            print("  budget=%6dms peer=%2ds -> elapsed=%5.1fs status=%s %-9s %s"
                  % (budget, secs, el, st, verdict, body[:40]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()