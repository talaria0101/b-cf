#!/usr/bin/env python3
"""
Probe: who cancels a hanging upstream fetch, and when?

The suite showed a hanging upstream returning 502 after ~5.0s with
"The Workers runtime canceled this request" -- not the worker's own
AbortController (30s default) and not a client disconnect (client timeout 90s).

Three candidate explanations, each with the observation that would refute it:
  A. workerd cancels a fetch whose response never begins, at a fixed budget.
     Predicts: cancellation still happens with NO AbortController in the worker.
  B. Our AbortController fires early.
     Predicts: elapsed tracks the configured budget (1s -> ~1s, 8s -> ~8s).
  C. The harness client disconnects early.
     Predicts: elapsed tracks the client socket timeout instead of a fixed value.

Run: python3 harness/probe_timeout.py
"""

import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rig import Rig  # noqa: E402

NO_TIMEOUT_WORKER = """
// No AbortController, no timer. Whatever cancels this is not ours.
export default {
	async fetch(request) {
		const target = new URL(request.url).pathname.slice(1);
		try {
			const r = await fetch(target);
			return new Response(await r.text(), { status: r.status });
		} catch (e) {
			return new Response("ERR:" + (e && e.name) + ":" + (e && e.message), { status: 502 });
		}
	},
};
"""

TUNED_WORKER = """
// Same shape as v2's timeout, with the budget inlined so it can be varied.
const BUDGET_MS = __BUDGET__;
export default {
	async fetch(request) {
		const target = new URL(request.url).pathname.slice(1);
		const c = new AbortController();
		const t = setTimeout(() => c.abort(), BUDGET_MS);
		try {
			const r = await fetch(target, { signal: c.signal });
			clearTimeout(t);
			return new Response(await r.text(), { status: r.status });
		} catch (e) {
			clearTimeout(t);
			return new Response("ERR:" + (e && e.name) + ":" + (e && e.message), { status: 502 });
		}
	},
};
"""


def timeit(rig, path, client_timeout):
    t0 = time.time()
    st, hd, body = rig.get(path, timeout=client_timeout)
    return time.time() - t0, st, (body or "").replace("\n", " ")[:120]


def main():
    tmp = tempfile.mkdtemp(prefix="probe-")
    try:
        print("PROBE A: NO AbortController at all. TAP hangs forever.")
        w = os.path.join(tmp, "none.js")
        with open(w, "w") as fh:
            fh.write(NO_TIMEOUT_WORKER)
        with Rig(w, "probeA") as rig:
            el, st, body = timeit(rig, "/https://origin.test/__ctl/hang", 120)
            print("  client_timeout=120s  elapsed=%5.1fs  status=%s" % (el, st))
            print("  body: %s" % body)
        print("  -> if elapsed is well under 120s, the cancellation is NOT the client.")
        print("     if it returned at all, the cancel is NOT ours either.\n")

        print("PROBE B: budget sensitivity. Does elapsed track OUR budget?")
        for budget in (1000, 8000, 30000, 60000):
            p = os.path.join(tmp, "w%d.js" % budget)
            with open(p, "w") as fh:
                fh.write(TUNED_WORKER.replace("__BUDGET__", str(budget)))
            with Rig(p, "probeB") as rig:
                el, st, body = timeit(rig, "/https://origin.test/__ctl/hang", 180)
                print("  budget=%6dms  elapsed=%6.1fs  status=%s  %s"
                      % (budget, el, st, body[:60]))
        print("  -> if elapsed stops tracking budget and pins at one value, that value")
        print("     is workerd's own ceiling and no budget above it is reachable.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()