# api.rv v2

A Cloudflare Workers reverse proxy. Plain ES2022, no build step, no dependencies.
Alongside it: the measurements behind each design decision, and a harness that
runs the worker under Cloudflare's own `workerd` runtime.

Full write-up, evidence, and pricing: **[RESEARCH.md](RESEARCH.md)**.

## Quick start

```bash
wrangler secret put AUTH_TOKEN     # the binding v2 reads; without it the proxy is open
wrangler deploy
```

`wrangler.toml` pins `main = "rig/v2.js"` and the compatibility date the
measurements ran against. `AUTH_TOKEN` is read from the binding, so the secret
command takes effect.

Optional allowlist, in `wrangler.toml`:

```toml
[vars]
ALLOWED_HOSTS = "example.com,githubusercontent.com"
```

Comma-separated, whitespace tolerated. The parsed list is reported at
`GET /__config`. Entries match on hostname, so a port in an entry is ignored.

Three request forms, all supported:

```
/https://example.com/path?a=1
/example.com/path
/?url=https%3A%2F%2Fexample.com%2Fpath
```

`GET /__config` reports the resolved timeout and its scope, the effective
allowlist and how it matches, whether auth is required, and whether a
`TLS_TRANSPORT` binding is present and whether it can send a body.

## Request identity

Three values of `X-Proxy-Persona`:

| value | what the destination sees | applies when |
|---|---|---|
| `edge` (default) | `User-Agent: Cloudflare-Workers`, no Client Hints | the caller's own UA looks like a script or command-line client |
| `chrome` | Chrome UA + low-entropy hints + `Upgrade-Insecure-Requests` | `X-Proxy-Engine: tls` **and** a bound transport |
| `pass` | the caller's UA, verbatim | opt-in |

The `edge` default is not unconditional, and the distinction matters. A caller
arriving with a genuine browser User-Agent and no `X-Proxy-Persona` has its own UA
**forwarded verbatim, Client Hints included**: a real browser's identity is
coherent, so rewriting it would only make it less accurate. The `edge` identity is
what replaces a *scripted* client, because a script announcing itself honestly is
what a proxy choosing to be identifiable is saying. Set `X-Proxy-Persona: pass` to
make the no-rewrite behaviour explicit rather than incidental.

Client Hints and `Upgrade-Insecure-Requests` from the `chrome` persona are emitted
over `https` only. Both are secure-context features a real Chrome withholds on a
plaintext target.

The default is `edge` because v1 did the opposite. v1 announced Safari 18.5 on
every request, over a handshake that `tls.peet.ws` reports as
`t13d1312h2_a44d0ee8b3cc_e381dae6da6b`. A real Chrome 155 is
`t13i1516h2_8daaf6152771_...`: both TLS 1.3, but 13 ciphers against Chrome's 15
and 12 extensions against 16. A browser User-Agent on a handshake that is not
that browser's is a weaker signal than an accurate one, because the mismatch is
the inconsistency. So the default states the transport, and `chrome` is opt-in,
gated on a transport that can back the claim.

When the proxy replaces a User-Agent it also drops the caller's Client Hints,
since a caller's `sec-ch-ua-platform` beside this proxy's UA is the same kind of
mismatch. A caller whose own UA is forwarded untouched keeps its hints.

`X-Proxy-Engine: tls` selects a userland TLS transport bound as `TLS_TRANSPORT`,
which must expose `fetch(url, { method, headers, body, signal }) -> Response`.
Without that binding the request gets a **501** naming the missing binding, rather
than quietly using the `fetch()` path the caller was avoiding. `TLS_TRANSPORT` is
not implemented here; see `RESEARCH.md` section 3.3 and Limits item 4.

A transport that cannot send a request body must say so. If the request has a
body and the transport does not declare `supportsBody = true`, the request is
refused with a **501** rather than sent without its payload. `GET /__config`
reports `tls_transport_supports_body` so a deployment can tell the two apart.

Both headers are stripped before the request reaches the destination.

## What is forwarded, and where

Cookie forwarding is opt-in per request (`X-Proxy-Forward-Cookies: 1`) and is
scoped to the host the caller named. A redirect to a different host does not
carry the consent: the caller consented to the origin they asked for, not to
wherever that origin points.

`X-Proxy-Timeout-Ms` bounds time to response **headers**. It does not bound the
body. The timer is cleared once the headers arrive, so an origin that sends
headers at once and then stalls still completes. `GET /__config` reports this as
`timeout_scope`.

`ALLOWED_HOSTS` matches on hostnames. A port in an entry is ignored rather than
making the entry match nothing, and port-based restriction is not available on
this path. `GET /__config` reports this as `allowed_hosts_match`.

## Run the proofs

```bash
python3 harness/test_proxy.py            # 407 assertion rows (32 controls), ~3s
python3 harness/mutation_check.py        # 58 mutations, all must be caught, ~30s
python3 harness/probe_raw_socket.py      # the TLS-raw-stream measurement, ~0.3s
```

All three exit non-zero on failure. `test_proxy.py` accepts a worker path as
`argv[1]`, which is how the mutation check runs variants without ever writing to
`rig/v2.js`.

`probe_raw_socket.py` runs one worker twice, under workerd's default network
policy and under a permissive one, so the positive result is backed by a control
that actually fails.

The four timeout probes (`probe_timeout.py`, `probe_slow_upstream.py`,
`probe_abort_discrimination.py`, `probe_timer_semantics.py`) are the measurements
behind section 8.6. Each is standalone and states what it separates.

## Scope

This does not solve Turnstile, reCAPTCHA, or Cloudflare's JavaScript challenges,
and cannot. Those tokens are issued inside a browser. `RESEARCH.md` section 3
has the evidence; section 6.3 lists the limits written into the worker as
comments.

It also does not change the egress address, which is the layer that decides most
bot-managed sites. Section 3.3 concerns the layer above that one.

Section 6.2 lists the behaviour changes that will affect an existing v1 caller,
including that cookies and `Authorization` are not forwarded. Cookies can be
opted back into per request; `Authorization` cannot, because forwarding it is how
the proxy's own credential reached third-party origins, and there is no header a
caller can send to re-enable it.

## Layout

```
rig/v2.js             the worker: plain ES2022, no build step, no dependencies
rig/v1-baseline.js    v1, reformatted, with an 11-line provenance header (RESEARCH.md 1)
wrangler.toml         deploy config; pins the tested compatibility date
LICENSE               0BSD
harness/rig.py        runs a worker under real workerd with an in-process TAP origin
harness/test_proxy.py the suite
harness/mutation_check.py
harness/probe_*.py    five standalone probes
tools/ja4.py          JA4 from a raw ClientHello, computed from the specification
proofs/               captured output cited by RESEARCH.md
evidence/             upstream artefacts used as inputs, mirrored verbatim
bin/wd                workerd 2026-10-13, Cloudflare's actual runtime
```

## Requirements

`bin/wd` must be present: the harness drives `workerd` directly over an AF_UNIX
socket using only its own CAPNP config. Nothing else is needed. The harness is
pure Python standard library, with no third-party packages and no `node_modules`
directory.

To rebuild `bin/wd`:

```bash
mkdir -p bin
curl -sL -o /tmp/wd.gz \
  https://github.com/cloudflare/workerd/releases/download/v1.20261013.1/workerd-linux-64.gz
# gunzip writes `wd` and REMOVES wd.gz, so there is nothing left to move.
gunzip -f /tmp/wd.gz && mv /tmp/wd bin/wd && chmod +x bin/wd
```

`tools/ja4.py` needs no network and no dependencies.