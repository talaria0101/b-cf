#!/usr/bin/env python3
"""
Probe 4: is the abort-path discriminator stable enough to assert on?

probe_timer_semantics.py showed two DIFFERENT cancellations that both return 502:
  - our own AbortController:  err.name === "AbortError", small worker_ms
  - workerd's hung-code detector: err.name === "Error", "your Worker's code had
    hung", worker_ms === 0

So "502" alone cannot distinguish them, and a wall-clock deadline is unobservable
(sets both peer sleep and our budget clamp into a ~1s worker-time / ~6s wall
envelope in `workerd serve`).

This probe asks the only question that matters before I assert on it: does the
discriminator hold across repeated runs, and does it separate the two cases
reliably? Each case is run REPEATS times, because a single control run is a
coincidence.

Run: python3 harness/probe_abort_discrimination.py
"""

import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rig import Rig  # noqa: E402

WORKER = """
const BUDGET_MS = __BUDGET__;
export default {
	async fetch(request) {
		const _u = new URL(request.url);
		const target = _u.pathname.slice(1) + _u.search;
		const c = new AbortController();
		const t = setTimeout(() => c.abort(), BUDGET_MS);
		const t0 = Date.now();
		try {
			const r = await fetch(target, { signal: c.signal });
			clearTimeout(t);
			await r.text();
			return new Response("OK worker_ms=" + (Date.now() - t0), { status: r.status });
		} catch (e) {
			clearTimeout(t);
			const msg = String(e && e.message);
			const kind = (e && e.name) === "AbortError" ? "own-abort" : "runtime-hung-detector";
			return new Response("ERR kind=" + kind + " name=" + (e && e.name) +
				" worker_ms=" + (Date.now() - t0) + " hung_marker=" + /had hung/.test(msg),
				{ status: 502 });
		}
	},
};
"""

REPEATS = 3


def run_once(worker_src, name, path):
    with Rig(worker_src, name) as rig:
        t0 = time.time()
        st, hd, body = rig.get(path, timeout=60)
        return time.time() - t0, st, (body or "").replace("\n", " ").strip()


def main():
    tmp = tempfile.mkdtemp(prefix="probeabort-")
    try:
        cases = [
            ("own timer vs SLOW peer (s=30)", "/https://origin.test/__ctl/slow?s=30"),
            ("own timer vs HANGING peer", "/https://origin.test/__ctl/hang"),
        ]
        stable = True
        for i, (label, path) in enumerate(cases):
            slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:40]
            p = os.path.join(tmp, "w-%d-%s.js" % (i, slug))
            with open(p, "w") as fh:
                fh.write(WORKER.replace("__BUDGET__", "250"))
            print("%s   budget=250ms, %d runs" % (label, REPEATS))
            kinds = Counter()
            for n in range(REPEATS):
                el, st, body = run_once(p, "ab%d-%d" % (i, n), path)
                kind = "?"
                for token in ("own-abort", "runtime-hung-detector"):
                    if token in body:
                        kind = token
                kinds[kind] += 1
                print("   run %d: wall=%4.1fs status=%s kind=%-24s %s"
                      % (n + 1, el, st, kind, body[:74]))
            if len(kinds) != 1:
                stable = False
                print("   UNSTABLE: %d distinct outcomes across %d runs\n" % (len(kinds), REPEATS))
            else:
                print("   STABLE: always %s\n" % next(iter(kinds)))
        print("discriminator stable across repeats: %s" % ("YES" if stable else "NO"))
        return 0 if stable else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())