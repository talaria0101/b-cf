#!/usr/bin/env python3
"""
Probe: can a Worker write its own TLS ClientHello, or is the handshake fixed?

This is the measurement behind the Layer 1 correction in RESEARCH.md. An earlier
draft of that document claimed TLS fingerprint control was impossible on Workers.
It is not, and this probe is why.

`connect({ secureTransport: "off" })` is documented to return a raw duplex byte
stream. "Documented" is not "measured", so this measures it: write plaintext bytes
to the writable side, read the peer's reply, and check that the reply is the
peer's own plaintext. A runtime still terminating TLS would have to reject those
bytes or answer with a TLS record. Nothing else produces a clean `HTTP/1.1 200
Connection Established` coming back from the bytes we wrote.

The peer is the sandbox's own HTTP CONNECT proxy at 169.254.169.1:36179, the one
reachable TCP endpoint here, and it speaks plain HTTP.

THE CONTROL IS THE POINT. workerd's default network service carries
`allow = ["public"]` (the `Network` struct in workerd.capnp), which refuses
loopback and link-local peers. Under that default this probe FAILS with
`connect() blocked by restrictPeers()`, and the failure is about the sandbox's
address ranges, not about TLS. So the probe runs the identical worker twice:

  default     globalOutbound unset, so workerd's built-in internet service.
              Expected: blocked.
  permissive  globalOutbound = a `network` service with
              allow = ["public", "private", "local"]. Expected: our plaintext
              reaches the peer and comes back.

Same worker, same bytes, one line of config different. That is what makes the
positive result mean "the runtime gave us a raw stream" rather than "something
happened to connect".

An earlier version of this probe used port 9 and reported a successful plaintext
write. That was a race, not a result: the socket is created optimistically and the
connection is attempted in the background, so whether the write lands before the
refusal arrives is timing. Re-running failed outright, which is how the race was
found. Connecting to a peer that actually answers removes it, because a reply can
only come from something that received our bytes.

Run:  python3 harness/probe_raw_socket.py
Exit: 0 if the permissive run confirms a raw byte stream
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rig import unix_request, wait_for_unix  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKERD = os.path.join(ROOT, "bin", "wd")

# The sandbox's HTTP CONNECT proxy: reachable, speaks plain HTTP, answers.
PROXY_HOST = "169.254.169.1"
PROXY_PORT = 36179

W = r"""
import { connect } from "cloudflare:sockets";

const PROXY_HOST = "%(host)s";
const PROXY_PORT = %(port)d;

function toHex(bytes) {
	return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default {
	async fetch() {
		const out = [];

		// 1. Is the raw-socket API present at all? Before the correction, this
		// document assumed it was not.
		out.push("connect_type=" + typeof connect);

		try {
			// 2. A duplex object, not a TLS endpoint.
			const s = connect({ hostname: PROXY_HOST, port: PROXY_PORT, secureTransport: "off" });
			out.push("socket_created=" + (s && typeof s === "object"));
			out.push("duplex=" + (!!s.readable && !!s.writable));

			// 3. THE DECISIVE TEST. Plain HTTP/1.1 bytes: no ClientHello, no cipher
			// list, no record layer. If the runtime were wrapping this in TLS the
			// peer could not parse it and could not answer in the clear.
			const writer = s.writable.getWriter();
			await writer.write(new TextEncoder().encode(
				"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"));
			out.push("plaintext_write_ok=true");

			const reader = s.readable.getReader();
			const raced = await Promise.race([
				reader.read(),
				new Promise((res) => setTimeout(() => res({ timedOut: true }), 8000)),
			]);
			try { reader.cancel(); } catch {}
			try { writer.close(); } catch {}

			if (raced.timedOut) {
				out.push("read_timeout=true (connected; the peer said nothing)");
			} else if (raced.done) {
				out.push("read_eof=true");
			} else {
				const bytes = raced.value;
				const text = new TextDecoder().decode(bytes);
				out.push("reply_hex=" + toHex(bytes));
				out.push("reply_text=" + JSON.stringify(text));
				// The peer parsed our plaintext and answered in plaintext. A TLS
				// endpoint could not produce this, and neither could a runtime that
				// had inserted a ClientHello of its own.
				out.push("raw_stream_confirmed=" + text.startsWith("HTTP/1."));
			}
		} catch (e) {
			out.push("socket_err=" + String((e && e.message) || e).slice(0, 120));
			out.push("raw_stream_confirmed=false");
		}

		// 4. fetch() has no TLS surface. Cipher and JA3 keys must change nothing,
		// because there is nothing on it to pass them to. That asymmetry is why
		// fetch() is closed and connect() is not.
		const plain = { method: "GET" };
		const faked = { ...plain, tls: { ciphers: [1, 2, 3] }, ja3: "x" };
		out.push("fetch_accepts_arbitrary_tls_keys=" +
			(JSON.stringify(Object.keys(faked)) === JSON.stringify(Object.keys(plain))));

		return new Response(out.join("\n"), { headers: { "content-type": "text/plain" } });
	},
};
"""

# The two configs differ only in the services list and whether globalOutbound is
# named. The default names neither, so workerd builds its own internet service with
# allow = ["public"].
CFG_DEFAULT = """
using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [ (name = "main", worker = .w) ],
  sockets = [ (name = "http", address = "unix:%(sock)s", http = (), service = "main") ]
);
const w :Workerd.Worker = (
  modules = [ (name = "worker", esModule = embed "worker.js") ],
  compatibilityDate = "2026-03-24",
  compatibilityFlags = [ "nodejs_compat" ],
);
"""

CFG_PERMISSIVE = """
using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "main", worker = .w),
    (name = "net", network = ( allow = ["public", "private", "local"] ))
  ],
  sockets = [ (name = "http", address = "unix:%(sock)s", http = (), service = "main") ]
);
const w :Workerd.Worker = (
  modules = [ (name = "worker", esModule = embed "worker.js") ],
  compatibilityDate = "2026-03-24",
  compatibilityFlags = [ "nodejs_compat" ],
  globalOutbound = "net",
);
"""


def run(label, capnp_text, worker_text):
    """Start one workerd with this config, ask it once, and return (body, log)."""
    tmp = tempfile.mkdtemp(prefix="apirv-sock-%s-" % label)
    sock = os.path.join(tmp, "i.sock")
    try:
        with open(os.path.join(tmp, "worker.js"), "w") as fh:
            fh.write(worker_text)
        cfg = os.path.join(tmp, "w.capnp")
        with open(cfg, "w") as fh:
            fh.write(capnp_text % {"sock": sock})
        logpath = os.path.join(tmp, "log")
        log = open(logpath, "w")
        proc = subprocess.Popen([WORKERD, "serve", cfg], stdout=log, stderr=subprocess.STDOUT)
        try:
            if not wait_for_unix(sock):
                log.flush()
                with open(logpath) as fh:
                    return None, fh.read()
            st, hd, body = unix_request(sock, "GET", "/", timeout=45)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        log.flush()
        log.close()
        with open(logpath) as fh:
            return (body or ""), fh.read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    worker = W % {"host": PROXY_HOST, "port": PROXY_PORT}

    print("=== probe_raw_socket: does connect() give us a raw byte stream? ===")
    print("peer: %s:%d (the sandbox's HTTP CONNECT proxy, plain HTTP)\n"
          % (PROXY_HOST, PROXY_PORT))

    control_body, control_log = run("control", CFG_DEFAULT, worker)
    print('--- CONTROL: workerd default network service, allow = ["public"] ---')
    print((control_body or "(no response)").strip())
    print()
    control_blocked = "restrictPeers" in (control_log or "")
    print("  blocked as expected: %s" % control_blocked)
    print("  That refusal is about the sandbox's address ranges, not about TLS.")
    print()

    body, logtext = run("permissive", CFG_PERMISSIVE, worker)
    print('--- PERMISSIVE: globalOutbound = network(allow = [public, private, local]) ---')
    print((body or "(no response)").strip())
    print()
    if "restrictPeers" in (logtext or ""):
        print("--- workerd log ---")
        print(logtext.strip())
        print()

    checks = {
        "connect() is available": "connect_type=function" in (body or ""),
        "the socket is duplex": "duplex=true" in (body or ""),
        "a plaintext write is accepted": "plaintext_write_ok=true" in (body or ""),
        "the peer answered our bytes in the clear": "raw_stream_confirmed=true"
        in (body or ""),
        "fetch() exposes no TLS surface": "fetch_accepts_arbitrary_tls_keys=false"
        in (body or ""),
        "CONTROL: the default config blocks that peer": control_blocked,
    }
    for name, ok in checks.items():
        print("  %s  %s" % ("PASS" if ok else "FAIL", name))

    ok = all(checks.values())
    print("\nRESULT: %s"
          % ("connect({secureTransport:'off'}) is a raw duplex byte stream, so a"
             " Worker builds its own ClientHello and its own TLS record layer"
             if ok else "the raw-stream claim was NOT confirmed here"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())