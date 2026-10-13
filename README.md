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

`GET /__config` reports the resolved timeout, effective allowlist, and whether auth
is required.

## Run the proofs

```bash
python3 harness/test_proxy.py       # 115 assertions + 3 negative controls, <1s
python3 harness/mutation_check.py   # 23 mutations, all must be caught, ~4s
```

Both exit non-zero on failure. `harness/test_proxy.py` accepts a worker path as
`argv[1]`, which is how the mutation check runs variants without ever writing to
`rig/v2.js`.

The four `harness/probe_*.py` scripts are the measurements behind the timeout
claims in section 8.6 of the research document. They are standalone and each
states the candidates it is separating.

## What this is not

It does not defeat Turnstile, reCAPTCHA, or Cloudflare's JS challenges, and it
cannot. Those require a real browser and a solved token. `RESEARCH.md` section 3
has the evidence, and section 6.3 lists the limits that are written into the
worker as comments.

`RESEARCH.md` section 6.2 lists the behaviour changes that will break an existing
v1 caller (cookies and `Authorization` are no longer forwarded by default).

## Layout

```
rig/v2.js             the worker: plain ES2022, no build step, no dependencies
rig/v1-baseline.js    v1 + a 2-line provenance header, as the negative control
wrangler.toml         deploy config; pins the tested compatibility date
harness/rig.py        runs a worker under real workerd with an in-process TAP origin
harness/test_proxy.py the suite
harness/mutation_check.py
harness/probe_*.py    four standalone probes
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