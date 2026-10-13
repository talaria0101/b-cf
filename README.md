# api.rv v2

A Cloudflare Workers reverse proxy, plus the research behind it and a harness that
runs the code under Cloudflare's real runtime.

Full write-up, evidence, and pricing: **[RESEARCH.md](RESEARCH.md)**.

## Quick start

```bash
wrangler secret put AUTH_TOKEN     # v1 shipped unauthenticated; do not repeat that
wrangler deploy
```

`wrangler.toml` is shipped and pins `main = "rig/v2.js"` and the compatibility date
the proofs were run against. `AUTH_TOKEN` is read from the binding, so the secret
command takes effect.

Optional allowlist, in `wrangler.toml`:

```toml
[vars]
ALLOWED_HOSTS = "example.com,githubusercontent.com"
```

Three request forms, all supported:

```
/https://example.com/path?a=1
/example.com/path
/?url=https%3A%2F%2Fexample.com%2Fpath
```

`GET /__config` reports the resolved timeout, effective allowlist, whether auth is
required, and whether a `TLS_TRANSPORT` binding is present.

## Identity: three personas, and the default is honest

| `X-Proxy-Persona` | the origin sees | applies when |
|---|---|---|
| `edge` (**default**) | `User-Agent: Cloudflare-Workers`, no Client Hints | always |
| `chrome` | Chrome UA + low-entropy hints + `Upgrade-Insecure-Requests` | `X-Proxy-Engine: tls` **and** a bound transport |
| `pass` | your UA, verbatim | opt-in |

The default is `edge` because v1's habit was backwards. It announced Safari 18.5
over a handshake that `tls.peet.ws` reports as `t13d1312h2_a44d0ee8b3cc_e381dae6da6b`,
and a real Chrome 155 is `t13i1516h2_8daaf6152771_...`: both TLS 1.3, but 13
ciphers against Chrome's 15 and 12 extensions against 16. A browser User-Agent on
a handshake that is not that browser's is a louder signal than an honest one,
because the mismatch is the tell. So the default describes the transport, and
`chrome` is opt-in and gated on a transport that can back the claim.

`X-Proxy-Engine: tls` selects a userland TLS transport bound as `TLS_TRANSPORT`,
which must expose `fetch(url, { headers }) -> Response`. Without that binding the
request gets a **501** naming the missing binding, not a silent downgrade to the
`fetch()` path it was meant to avoid. `TLS_TRANSPORT` is not implemented here; see
`RESEARCH.md` section 3.3 and Limits item 4.

Both headers are stripped before the request reaches the origin.

## Run the proofs

```bash
python3 harness/test_proxy.py            # 172 assertion rows (5 controls), ~2s
python3 harness/mutation_check.py        # 40 mutations, all must be caught, ~8s
python3 harness/probe_raw_socket.py      # the TLS-raw-stream measurement, ~0.3s
```

All three exit non-zero on failure. `harness/test_proxy.py` accepts a worker path
as `argv[1]`, which is how the mutation check runs variants without ever writing
to `rig/v2.js`.

`harness/probe_raw_socket.py` is what corrected the document's claim that TLS
fingerprint control was impossible on Workers. It runs the same worker twice, once
under workerd's default network policy and once under a permissive one, so the
positive result is backed by a control that actually fails.

The four timeout probes (`probe_timeout.py`, `probe_slow_upstream.py`,
`probe_abort_discrimination.py`, `probe_timer_semantics.py`) are the measurements
behind section 8.6 of the research document. They are standalone and each states
the candidates it is separating.

## What this is not

It does not defeat Turnstile, reCAPTCHA, or Cloudflare's JS challenges, and it
cannot. Those require a real browser and a solved token. `RESEARCH.md` section 3
has the evidence, and section 6.3 lists the limits that are written into the
worker as comments.

It also does not change the egress IP, which is the layer that decides most
bot-managed sites. `RESEARCH.md` section 3.3 is about the layer above that one.

`RESEARCH.md` section 6.2 lists the behaviour changes that will break an existing
v1 caller (cookies and `Authorization` are no longer forwarded by default).

## Layout

```
rig/v2.js             the worker: plain ES2022, no build step, no dependencies
rig/v1-baseline.js    v1 + a 2-line provenance header, as the negative control
wrangler.toml         deploy config; pins the tested compatibility date
LICENSE               0BSD
harness/rig.py        runs a worker under real workerd with an in-process TAP origin
harness/test_proxy.py the suite
harness/mutation_check.py
harness/probe_*.py    five standalone probes
tools/ja4.py          JA4 from a raw ClientHello, from the spec
proofs/               captured output cited by RESEARCH.md
evidence/             upstream artefacts used as inputs, mirrored verbatim
bin/wd                workerd 2026-10-13, Cloudflare's actual runtime
```

## Requirements

`bin/wd` must be present: the harness drives `workerd` directly over an AF_UNIX
socket, using only its own CAPNP config. **`harness/node_modules/` is NOT required**
to run the proofs (verified by removing it). Neither is any Python package: the
harness is pure standard library.

To rebuild `bin/wd` and `bin/node` from scratch:

```bash
mkdir -p bin
curl -sL -o /tmp/wd.gz \
  https://github.com/cloudflare/workerd/releases/download/v1.20261013.1/workerd-linux-64.gz
# gunzip writes `wd` and REMOVES wd.gz, so there is nothing left to move.
gunzip -f /tmp/wd.gz && mv /tmp/wd bin/wd && chmod +x bin/wd

curl -sL https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-x64.tar.xz \
  | tar xJ --no-same-owner -C bin
mv bin/node-v24.21.0-linux-x64 bin/node

# `npm` is a shim that runs `#!/usr/bin/env node`, so node must be on PATH.
cd harness && PATH="$PWD/../bin/node/bin:$PATH" ../bin/node/bin/npm install --no-audit --no-fund
```