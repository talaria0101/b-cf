#!/usr/bin/env python3
"""
Harness: run a Cloudflare Worker under the REAL workerd runtime, hermetically.

Why hermetic. This sandbox refuses every TCP bind()/listen() with EACCES, and
direct TCP connect() to the internet times out -- only an HTTP CONNECT proxy at
169.254.169.1:36179 is reachable. Two consequences shaped this design:

  1. Inbound requests arrive over an AF_UNIX socket. workerd supports
     "unix:/path" socket addresses, and a plain python client can talk to it.
  2. The Worker's outbound fetch() is routed to an in-process TAP worker via
     globalOutbound, instead of to the network.

The TAP is what makes this an assertion harness rather than a demo. It receives
the Request the runtime actually built for the upstream call and returns a JSON
description of it: url, method, every header in iteration order, body. A test can
therefore assert on the proxy's real output rather than on its intent. The TAP is
also scriptable: paths under /__ctl/ produce redirects, status codes and hangs on
demand, so redirect handling and error paths are reachable.

What this proves: the Worker's own logic, executed by Cloudflare's real runtime,
and exactly which Request it handed to fetch().

What this does NOT prove, and no local harness can: the TLS ClientHello
(JA3/JA4), HTTP/2 frame ordering and SETTINGS, the source IP the edge presents, or
whether any anti-bot vendor accepts it. Those are properties of Cloudflare's
network, not of Worker code. See "Limits" in RESEARCH.md.
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The TAP worker terminates the upstream call, records what it was given, and
# answers. It never fetches anything, so the worker under test cannot reach the
# network through it.
TAP_JS = r"""
function describe(req) {
	const order = [];
	const headers = {};
	for (const [k, v] of req.headers.entries()) {
		order.push(k.toLowerCase());
		headers[k.toLowerCase()] = v;
	}
	return {
		method: req.method,
		url: req.url,
		header_order: order,
		headers,
		cf: req.cf ? {
			colo: req.cf.colo,
			country: req.cf.country,
			httpProtocol: req.cf.httpProtocol,
			asn: req.cf.asn,
			botManagement: req.cf.botManagement,
		} : null,
	};
}

export default {
	async fetch(req) {
		const u = new URL(req.url);
		const body = (req.method === "GET" || req.method === "HEAD") ? "" : await req.text();
		const seen = describe(req);
		seen.body = body;

		// Scripted control plane, so redirect and error paths are reachable.
		// The destination is a query parameter, NOT a path segment: a target like
		// "https://other.test/x" contains "//" and a path split mangles it into
		// "https:/other.test/x", which then resolves relative to the current host.
		//   /__ctl/redirect?code=302&to=https://other.test/x
		//   /__ctl/chain?n=7              (n distinct hops, then 200; a cap set
		//                                 below n must surface as 508)
		//   /__ctl/loop?code=302          (redirects to itself, forever)
		//   /__ctl/relredirect?to=...     (relative Location, exercises hop rebuild)
		//   /__ctl/status?code=503
		//   /__ctl/hang
		//   /__ctl/slow?s=N               (answers after N seconds)
		//   /__ctl/hdrs                   (headers no object literal can build:
		//                                 duplicate Set-Cookie, content-encoding,
		//                                 an upstream Vary, cf-* and cdn-loop)
		if (u.pathname.startsWith("/__ctl/")) {
			const code = parseInt(u.searchParams.get("code") || "302", 10);
			const to = u.searchParams.get("to");

			// Headers an object literal cannot express, and response framing the
			// proxy must not corrupt. Built with append() so duplicates survive.
			if (u.pathname === "/__ctl/hdrs") {
				const h = new Headers();
				h.append("set-cookie", "a=1; Path=/");
				h.append("set-cookie", "b=2; Path=/");
				h.set("content-encoding", "identity");
				h.set("vary", "Accept-Encoding");
				h.set("cf-ray", "injected-by-origin-sim");
				h.set("cdn-loop", "cloudflare");
				h.set("x-keep-me", "kept");
				// An origin that opts the caller into credentialed CORS. The proxy
				// must not pass this through, because applyCors reflects the
				// caller's Origin and the pair is the dangerous combination.
				h.set("access-control-allow-credentials", "true");
				h.set("access-control-allow-origin", "https://upstream-allowed.test");
				return new Response("framing-fixture", { status: 200, headers: h });
			}
			if (u.pathname === "/__ctl/redirect" || u.pathname === "/__ctl/loop") {
				const dest = u.pathname === "/__ctl/loop" ? u.href : to;
				if (!dest) return new Response("missing to=", { status: 500 });
				return new Response("redirecting", {
					status: code,
					headers: { location: dest, "x-tap": "redirect" },
				});
			}
			// A finite, countable redirect chain. Each hop has a distinct URL, so
			// the test can tell "stopped at the cap" from "followed every hop".
			if (u.pathname === "/__ctl/chain") {
				const n = parseInt(u.searchParams.get("n") || "0", 10);
				if (n > 0) {
					return new Response("hop " + n, {
						status: code,
						headers: { location: "/__ctl/chain?n=" + (n - 1), "x-tap": "chain" },
					});
				}
				return new Response(JSON.stringify({ tap: true, seen, chain_end: true }), {
					status: 200,
					headers: { "content-type": "application/json", "x-tap": "chain-end" },
				});
			}
			if (u.pathname === "/__ctl/location201") {
				// A Location on a NON-3xx. The redirect loop only consumes 3xx, so
				// this is the only shape that reaches rewriteLocation() at all.
				// A REST origin does exactly this on 201 Created, and a client
				// that followed it verbatim would leave the proxy entirely.
				return new Response("created", {
					status: 201,
					headers: { location: "https://thirdparty.test/thing", "x-tap": "loc201" },
				});
			}
			if (u.pathname === "/__ctl/relredirect") {
				return new Response("relative", {
					status: code,
					headers: { location: to || "/__ctl/relative-target", "x-tap": "relredirect" },
				});
			}
			if (u.pathname === "/__ctl/relative-target") {
				return new Response("arrived via relative Location", {
					status: 200,
					headers: { "x-tap": "rel-target" },
				});
			}
			if (u.pathname === "/__ctl/status") {
				return new Response("scripted " + code, { status: code });
			}
			if (u.pathname === "/__ctl/hang") {
				await new Promise(() => {});
			}
			// Slow BUT COMPLETING. Distinguishes workerd's hung-code detector
			// (which fires on a peer that never answers) from the Worker's own
			// AbortController, which must fire on a peer that is merely slow.
			if (u.pathname === "/__ctl/slow") {
				const secs = Number(u.searchParams.get("s") || "1");
				await new Promise((res) => setTimeout(res, secs * 1000));
				return new Response(JSON.stringify({ tap: true, seen, slept: secs }), {
					status: 200,
					headers: { "content-type": "application/json", "x-tap": "slow" },
				});
			}
		}

		return new Response(JSON.stringify({ tap: true, seen }, null, 2), {
			status: 200,
			headers: { "content-type": "application/json", "x-tap": "echo" },
		});
	},
};
"""


def unix_request(sock_path, method, path, headers=None, body=None, timeout=15, raw_head=False):
    """Minimal HTTP/1.1 client over an AF_UNIX socket.

    Returns (status, headers, body), or (status, headers, body, head_text) when
    raw_head is set. The raw head is the only way to tell two repeated header
    LINES from one header whose value contains a comma: a joined string is
    ambiguous, the wire is not.
    """
    headers = dict(headers or {})
    payload = body.encode() if isinstance(body, str) else (body or b"")
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: proxy.local"]
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    if body is not None:
        lines.append("Content-Length: %d" % len(payload))
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + payload

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    s.sendall(raw)

    # Read the head first, then exactly as many body bytes as Content-Length
    # declares. Reading to EOF instead would block until the socket timeout on
    # every keep-alive connection, which workerd does not close after responding.
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            s.close()
            if not buf:
                return None, {}, b""
            break
        buf += chunk
    head, sep, rest = buf.partition(b"\r\n\r\n")
    head_lines = head.decode("latin-1").split("\r\n")
    parts = head_lines[0].split(" ")
    status = int(parts[1]) if len(parts) > 1 else 0
    hdrs = {}
    for line in head_lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip().lower()
            v = v.strip()
            # Repeated headers are JOINED WITH ", " rather than overwritten.
            # set-cookie is the case that matters: two Set-Cookie lines folded
            # into one string is indistinguishable from a single comma-joined
            # cookie, so an assertion about keeping them separate could not fail
            # against exactly the corruption it was written to catch. Callers
            # that need the individual values read them back out of the joined
            # form via _split_repeated().
            hdrs[k] = (hdrs[k] + ", " + v) if k in hdrs else v

    declared = hdrs.get("content-length")
    body = rest
    if declared is not None and sep:
        want = int(declared)
        while len(body) < want:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            body += chunk
        body = body[:want]
    s.close()
    text = body.decode("utf-8", "replace")
    if raw_head:
        return status, hdrs, text, head.decode("latin-1")
    return status, hdrs, text


def _split_repeated(joined):
    """Recover the individual values from a joined repeated header.

    Splitting on "," is only sound for headers whose grammar has no commas
    inside a value. `set-cookie` is exactly the header where that is false (an
    Expires date contains commas), so this is used only where the fixture's
    values are known to be comma-free.
    """
    return [p for p in joined.split(", ") if p]


def wait_for_unix(path, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(path):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(path)
                s.close()
                return True
            except OSError:
                pass
        time.sleep(0.1)
    return False


CONFIG = """
using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "main", worker = .mainWorker),
    (name = "tap", worker = .tapWorker)
  ],
  sockets = [
    (name = "http", address = "unix:INBOUND", http = (), service = "main")
  ]
);
const mainWorker :Workerd.Worker = (
  modules = [ (name = "worker", esModule = embed "worker.js") ],
  compatibilityDate = "2026-03-24",
  globalOutbound = "tap",
);
const tapWorker :Workerd.Worker = (
  modules = [ (name = "tap", esModule = embed "tap.js") ],
  compatibilityDate = "2026-03-24",
  globalOutbound = "tap",
);
"""


class Rig:
    """Runs one worker source file under workerd with an in-process tap origin."""

    def __init__(self, worker_src, name="rig"):
        self.worker_src = worker_src
        self.name = name
        self.tmp = tempfile.mkdtemp(prefix="apirv-%s-" % name)
        self.in_sock = os.path.join(self.tmp, "in.sock")
        self.workerd = None
        self.logpath = os.path.join(self.tmp, "workerd.log")

    def start(self):
        shutil.copy(self.worker_src, os.path.join(self.tmp, "worker.js"))
        with open(os.path.join(self.tmp, "tap.js"), "w") as fh:
            fh.write(TAP_JS)
        cfg_path = os.path.join(self.tmp, "config.capnp")
        with open(cfg_path, "w") as fh:
            fh.write(CONFIG.replace("unix:INBOUND", "unix:" + self.in_sock))

        self.log = open(self.logpath, "w")
        self.workerd = subprocess.Popen(
            [os.path.join(ROOT, "bin", "wd"), "serve", cfg_path],
            stdout=self.log, stderr=subprocess.STDOUT,
        )
        if not wait_for_unix(self.in_sock):
            self.log.flush()
            with open(self.logpath) as fh:
                raise RuntimeError("workerd did not start for %s:\n%s" % (self.name, fh.read()))
        return self

    def stop(self):
        if self.workerd and self.workerd.poll() is None:
            self.workerd.send_signal(signal.SIGTERM)
            try:
                self.workerd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.workerd.kill()
        try:
            self.log.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def get(self, path, method="GET", headers=None, body=None, timeout=15, raw_head=False):
        return unix_request(self.in_sock, method, path, headers, body, timeout, raw_head)

    @staticmethod
    def seen(body_text):
        """Extract the TAP's record of the upstream request from a response body."""
        try:
            return json.loads(body_text)["seen"]
        except Exception:
            return None

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()


class Results:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail=""):
        self.rows.append((name, bool(ok), detail))
        print("  %s  %-62s %s" % ("PASS" if ok else "FAIL", name, detail))
        return ok

    @property
    def failed(self):
        return [r for r in self.rows if not r[1]]

    def summary(self, label):
        n, f = len(self.rows), len(self.failed)
        print("\n%s: %d/%d passed" % (label, n - f, n))
        for name, _, detail in self.failed:
            print("  FAILED: %s   %s" % (name, detail))
        return f == 0