# api.rv v2 — research, design, and reproducible proofs

A new-generation `api.rv.pkgforge.dev` for Cloudflare Workers, plus the evidence
behind every claim here, the pricing comparison, and a harness that runs the real
Workers runtime.

Everything below was checked on **2026-10-13**. Anything that could not be verified is in
[Limits](#limits-what-this-document-does-not-establish) and is marked there
rather than smoothed over.

---

## TL;DR

1. **The stated premise needs a correction.** A Cloudflare Worker cannot present
   as a browser for challenge-solving purposes. The token is minted by JavaScript
   inside a real browser, and Cloudflare's own docs say automation frameworks are
   classified as bots. Section
   [3](#3-challenge-tokens-what-a-worker-can-and-cannot-do).
2. **A second correction, in the opposite direction.** An earlier draft said
   TLS fingerprint control was impossible on Workers. It is not: `connect()` with
   `secureTransport: "off"` hands the Worker a raw byte stream, so it writes its
   own ClientHello. Measured under `workerd`, with the default-config failure kept
   as a control. Section [3.3](#33-layer-1-tls-fetch-is-closed-connect-is-not).
   This does not move the layer that actually decides most sites, which is the
   egress IP.
3. **v1's two headline features are dead code**, confirmed against the live
   deployed worker, not just by reading it. `cf-connecting-ip` randomisation never
   runs, and 4 of the 8 `cf-*` headers it tries to strip are re-injected by
   Cloudflare anyway. Section [2](#2-what-v1-actually-does-measured-not-read).
4. **Serverless "real browser" does exist**, and it is not a Worker `fetch()`: it
   is **Browser Run** (formerly Browser Rendering), a binding at
   **$0.09/browser-hour** after 10 free hours/month. That is the only route to
   running JS, and it does not solve challenge tokens either. Section [5](#5-browser-run).
5. **Self-built cost**: **$0** up to ~3M requests/month on the Free plan
   (100,000/day), **$5.00/month** on Paid, and **$45.40** at 100M requests/month.
   Adding Browser Run is **+$0.09 per browser-hour**, which is the number that
   decides everything. Section [7](#7-pricing).
6. **The proofs are executable**: 402 assertion rows against v2 under Cloudflare's
   own `workerd`, 32 control assertions that fire on known defects, and a mutation
   check that breaks 58 invariants and requires the suite to catch every one. All
   green.

---

## 1. What v1 is

The upstream file is 101 lines, 3423 bytes,
`sha256 3e06a02a0c466b704a1d550167c346102ba2734587e85a68efd1d3d15ef0f6fa` (verified
by download on 2026-10-13). `rig/v1-baseline.js` in this repo is an **11-line
provenance header plus upstream's code reformatted**: indentation widened from 2
spaces to 4, trailing whitespace stripped, final newline dropped. It is 111 lines
and 4330 bytes, so **its** hash differs from the value above, and it is **not**
byte-for-byte. An earlier revision of this document and of the file's own header
claimed it was; both were wrong and are corrected here. Whitespace is not semantic
in JavaScript, so the negative control still exercises exactly the code upstream
runs, which is all a control needs. Where a line number is given for v1 below, it
refers to the upstream file.

The repo is **archived** (`archived: true`, last push 2025-06-19, 2 stars, 36
commits, no releases, no tags). Nine Workers in total, one file each, no
`wrangler.toml` anywhere in the tree. `api.rv` is the outlier: no UA gate, no path
allowlist, no auth. It is a general-purpose **open** forward proxy.

The contract: `https://api.rv.pkgforge.dev/<absolute-url>`, where everything after
the domain is the destination.

---

## 2. What v1 actually does (measured, not read)

These were probed against the **live** worker, because the code and the deployed
behaviour disagree in places.

### 2.1 Dead code: `cf-connecting-ip` is never set

v1 lists `cf-connecting-ip` in `headersToRemove` **and** has a branch that sets it
to a random IP. The removal test runs first, so the branch is unreachable:

```js
const headersToRemove = new Set([
  'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-server', 'x-real-ip',
  'cdn-loop', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ew-via',
  'cf-ew-preview-server', 'cf-ray', 'cf-visitor', 'cf-worker'
]);

for (const [key, value] of request.headers.entries()) {
  const lowerKey = key.toLowerCase();
  if (!headersToRemove.has(lowerKey)) {   // <-- cf-connecting-ip exits here
    if (lowerKey === 'cf-connecting-ip') { // <-- unreachable
      headers.set(key, generateRandomIP());
```

`generateRandomIP` is defined and never called. The author's own comment on upstream line 38 reads
`// cloudflare #doesn't actually work`.

**Live proof** (`curl` through the deployed worker, origin echoed what it got):

```
$ curl -s -H 'CF-Ray: testray' -H 'User-Agent: curl/8.22.0' \
    'https://api.rv.pkgforge.dev/https://httpbin.org/anything'
{ "Cf-Connecting-Ip": "ABSENT",                       <- no value written
  "Cf-Ray":            "a49f1fc9abaccf60-KTM",        <- Cloudflare's own, not the caller's
  "X-Forwarded-For":   null }
```

Note `Cf-Ray`: `testray` was sent, and the origin saw a **Cloudflare-issued** value.
That is the re-injection, observed. The author's list of 8 `cf-*` headers cannot
work, because Cloudflare adds several of them at the edge after the Worker runs.

### 2.2 The source IP cannot be changed, at all

The live origin reported `origin: 2a06:98c0:3600::103, 172.69.76.176`.
`172.69.76.176` is inside `172.64.0.0/13`, which is in Cloudflare's published
IPv4 list (`https://www.cloudflare.com/ips-v4/`). A Worker's egress is
Cloudflare-owned. No header value can change what the origin sees here.

### 2.3 Other measured defects

| **Defect** | Evidence |
|---|---|
| Query string silently dropped | `.../https://httpbin.org/anything?a=1&b=2` -> origin saw `https://httpbin.org/anything`. `pathname` is used and `search` is never re-appended. |
| No CORS at all | Live response to `Origin: https://app.example` contains **0** `access-control-*` headers. Every browser caller is blocked by Same-Origin Policy. |
| One hardcoded UA, never varying | Every request returns the identical Safari 18.5 string. Byte-identical across repeated runs. |
| No client hints | A rewritten Safari UA is sent with no `sec-ch-ua` at all, which is itself inconsistent. |

### 2.4 Cookie and `Referer` forwarding: intended, with a consequence

Two measured behaviours that are **not** defects, because they are what the proxy
is for:

```
$ curl -s -H 'Cookie: session=secret123' \
    'https://api.rv.pkgforge.dev/https://httpbin.org/anything'
  -> Cookie: session=secret123        arrived verbatim

$ curl -s -H 'Referer: https://secret-app.example/dashboard' \
    'https://api.rv.pkgforge.dev/https://httpbin.org/anything'
  -> Referer: https://secret-app.example/dashboard   arrived verbatim
```

PkgForge confirms this is intended behaviour, and on an open proxy it is
load-bearing: a caller authenticating to an API through the proxy cannot do it
any other way, because the browser attaches the session cookie to the proxy's
request and the proxy is what relays it. Dropping it would break the service's
main use.

The consequence is real and is not a reason to change the behaviour, but it is the
thing a caller has to know:

> **This proxy will hand a cookie to any host the request names.** A `Cookie`
> header set for a private application arrives at the destination. Send cookies
> only to destinations that already hold them.

v2 keeps the capability and changes the default: cookies are **not** forwarded
unless the caller opts in per request with `X-Proxy-Forward-Cookies: 1`, and
`Referer` is rewritten to the target's own origin rather than dropped or
forwarded. Every v1 use case still works, because the opt-in is one header, and
the default stops being the dangerous one. That is a breaking change and it is in
[6.2](#62-behaviour-changes-that-will-break-an-existing-v1-caller).

---

## 3. Challenge tokens: what a Worker can and cannot do

The stated goal was to present as a browser for challenge-solving purposes.
That is not deliverable, and no Cloudflare Worker can. Here is the evidence, from
Cloudflare's own documentation.

### 3.1 The token is a browser artefact

Cloudflare Turnstile, [server-side validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/),
verbatim:

> - **Tokens can be forged.** An attacker can submit any string to your form endpoint without completing a challenge.
> - **Tokens expire.** Each token is valid for 300 seconds (5 minutes) after generation.
> - **Tokens are single-use.** Each token can only be validated once.

`POST https://challenges.cloudflare.com/turnstile/v0/siteverify` is a **verifier**,
not a solver. It checks a token that a widget running inside a real browser
produced. No documented server-side solve path exists in Cloudflare's Turnstile docs.

And on automation, from Cloudflare's [testing and troubleshooting](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)
page, verbatim:

> Automated testing suites (like Selenium, Cypress, or Playwright) are detected as bots by Turnstile.

That is decisive, because it means the failure mode is not "headless is slightly
detectable" but "the recognised automation stacks are classified as bots".

reCAPTCHA is the same shape: the token is single-use and acquired from Google's
client-side JS in a browser. The commonly cited **two minute** lifetime comes from
Google's documentation rather than Cloudflare's, so it is outside this document's
sources and is not verified here. Nothing in this section depends on it.

### 3.2 What a Worker `fetch()` cannot reproduce

These are the signals that actually decide the outcome, and none of them are
header values:

| Signal | Can a Worker fix it? |
|---|---|
| **JA3 / JA4** (TLS ClientHello fingerprint) | **Yes, over `connect()` and no other way.** `fetch()` has no TLS surface. `connect({secureTransport:"off"})` returns a raw byte stream, so the Worker writes its own ClientHello. Section [3.3](#33-layer-1-tls-fetch-is-closed-connect-is-not), measured in `proofs/02-raw-socket.txt`. |
| **HTTP/2 SETTINGS and frame ordering** | Same route. HTTP/2 is a framing format over a byte stream; it needs no runtime support. Costs more CPU than HTTP/1.1, not less. |
| **JavaScript detections** | The site injects a script and reads what the browser computes. Exposed as `request.cf.botManagement.jsDetection.passed`. Needs a JS engine: Browser Run, or none. |
| **IP reputation and ASN** | **No.** Cloudflare-owned egress, published in `172.64.0.0/13` and its neighbours. Measured: `172.69.76.176`. |
| **Empty/absent `User-Agent`** | Yes, trivially, and the fix is honest: send a UA that describes the transport rather than pretending to be Chrome. |

Two more runtime facts that make a Worker trivially identifiable to a hostile
check, from the [Web standards](https://developers.cloudflare.com/workers/runtime-apis/web-standards/)
documentation:

- With `global_navigator`, `navigator.userAgent === 'Cloudflare-Workers'`.
- `Date.now()` "returns the time of the last I/O; it does not advance during code
  execution", and `performance.now()` always equals `Date.now()`.

A timing-attack-resistant environment is the opposite of what a bot-detection
heuristic wants, because it makes timing behaviour look synthetic.

**What this means practically.** The honest framing is three different goals:

- **Passing naive UA/language/referrer heuristics** on ordinary sites: achievable,
  and v2 does it. Section [6](#6-v2).
- **Presenting a chosen TLS fingerprint**: achievable, and it costs CPU rather than
  being forbidden. Section [3.3](#33-layer-1-tls-fetch-is-closed-connect-is-not).
  Nobody should read that as "solved", because it does not move the layer below it.
- **Solving Turnstile / reCAPTCHA / Cloudflare JS challenges**: not achievable
  serverless, at any price. The challenge needs a real browser, an address outside
  a datacentre range, and a token that the browser obtained. Anyone selling
  "serverless challenge solving" is selling access to a third party's browser
  fleet.

The distinction that matters is between what the **runtime forbids** and what it
**charges for**. Section 3.3 is a case where an earlier draft of this document
filed the second under the first, and section [8.9](#89-the-correction-that-changed-the-architecture)
records it.

### 3.3 Layer 1: TLS. `fetch()` is closed, `connect()` is not

**Correction, stated plainly.** An earlier draft of this document claimed TLS
fingerprint control was impossible on Workers, on the grounds that `workerd`
"offers no per-request TLS API". The premise is wrong. `cloudflare:sockets`
`connect()` accepts `secureTransport: "off"`, and that returns a **raw duplex byte
stream**. The runtime is not a TLS endpoint on that path, it is a pipe, so the
ClientHello is a byte string the Worker chooses to send.

This correction came from a parallel research effort
(`nemo-010/b-cf`, MIT; this repo is 0BSD, so nothing was copied, only checked and
credited). The claim was checked rather than adopted. `harness/probe_raw_socket.py` measures it,
and the measurement is in `proofs/02-raw-socket.txt`:

```
connect_type=function
socket_created=true
duplex=true
plaintext_write_ok=true
reply_hex=485454502f312e312032303020436f6e6e656374696f6e2045737461626c69736865640d0a0d0a
reply_text="HTTP/1.1 200 Connection Established\r\n\r\n"
raw_stream_confirmed=true
fetch_accepts_arbitrary_tls_keys=false
```

`reply_hex` decodes to `HTTP/1.1 200 Connection Established\r\n\r\n`, which is the
sandbox's HTTP CONNECT proxy answering the exact plaintext bytes the Worker wrote.
A runtime still terminating TLS could not produce that: it would have to reject
the write as nonsense or answer with a record it encrypted itself.

| transport | who writes the ClientHello | the fingerprint is |
|---|---|---|
| `fetch()` | workerd | fixed, not a browser, and not ours to control |
| `node:net` / `node:tls` | workerd, on top of `connect()` | not ours |
| `connect()` then `startTls()` | workerd, and it fails closed for tunnels | not ours |
| `connect({secureTransport:"off"})` + userland TLS | **us** | whatever we encode |

`startTls()` is the trap worth naming, because it looks like the shortcut. It
verifies the peer certificate against the hostname given to `connect()`, which
inside a tunnel is the *proxy*, not the origin.

**The control, which is what makes the result real.** The probe runs the identical
worker twice. Under workerd's default network service (`allow = ["public"]` in the
`Network` struct of `workerd.capnp`) the connect is refused:

```
socket_err=jsg.Error: proxy request failed, cannot connect to the specified address
... workerd log: failed: connect() blocked by restrictPeers()
```

So an earlier version of this probe, which reported a successful plaintext write
against port 9, was reporting a **race**, not a result. The socket is created
optimistically and the connection is attempted in the background, so whether the
write lands before the refusal arrives is timing; re-running failed outright. The
fix was to connect to a peer that actually answers, and to keep the default-config
failure as an explicit control. Without the control the positive result would only
have shown that a socket object exists.

**What the incumbent actually presents**, measured by fetching
`https://tls.peet.ws/api/all` through the live worker (`proofs/01-api-rv-tls.txt`):

```
ip              = 172.69.76.178:13802
http_version    = h2
ja3             = 67560f98d68783bd640246df3052c151
ja4             = t13d1312h2_a44d0ee8b3cc_e381dae6da6b
peetprint       = 86a3486140e2241fdfbdbe981958219e
ua              = Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ... Version/18.5 Safari/605.1.15
```

A real Chrome 155, computed by `tools/ja4.py` from the raw ClientHello in the
b-ids corpus:

```
ja4_a     = t13i1516h2        <- TLS 1.3, 15 ciphers, 16 extensions, no SNI captured
ja4_b     = 8daaf6152771      <- cipher-list hash, identical to Chrome's
```

**How to read `ja4_a`**, because reading it wrong is easy: the fields
are `t` + version + sni + cipher-count + extension-count + first ALPN character.
So `t13d1312h2` is `t`, **13 = TLS 1.3**, `d` = SNI present, **13** = 13
ciphers, **12** = 12 extensions, `h2` = ALPN. `tls_version_negotiated` in the same
capture is `772` = `0x0304` = TLS 1.3, confirming it independently. An earlier
draft of this document read the trailing `12` as a version and described the
incumbent as presenting TLS 1.2; that was wrong, and it was wrong in the
incumbent's disfavour.

The real gap, which is narrower and still real: **13 ciphers against Chrome's 15,
12 extensions against 16**, Cloudflare's own HTTP/2 SETTINGS, and a Safari 18.5
User-Agent on top. So v2 fixes the default by describing the transport rather than
imitating Chrome: the `edge` persona sends `User-Agent: Cloudflare-Workers` and no
Client Hints, which is what the transport actually is. Section
[6.4](#64-the-persona-model-and-why-the-default-is-not-chrome).

On `ja4_c`: `tools/ja4.py` reproduces peet.ws's own `ja4_c` for the api.rv
handshake (`e381dae6da6b`) exactly, so all three fields are verified against a
third-party computation of the same bytes. An earlier revision of the tool
labelled `ja4_c` `UNVERIFIED` because it did not reproduce the `6ff14566cf4a` that
`nemo-010/b-cf` quotes for the b-ids capture. That label was wrong, and the cause
is now known: reproducing their value requires keeping ALPN (`0010`) in the
extension hash and not filtering GREASE from the signature algorithms, while
`foxIO-LLC/ja4` `common.py` `get_hex_sorted()` removes both `0000` and `0010` and
`get_signature_algorithms()` filters GREASE. The peer's value comes from a
different rule, not a different capture. See section
[8.9](#89-the-correction-that-changed-the-architecture).

**The cost, since that is the real answer to "is it impossible".** A Worker has no
cross-invocation connection pool, so this is one handshake per request. Two
consequences for a design: TLS plus HTTP/2 in userland costs meaningfully more CPU
than `fetch()` plus workerd's own stack, and the fast path and the shaped path
therefore have different price tags. That is why v2's default is `engine=fetch`
and `engine=tls` is an explicit opt-in that refuses with 501 when no transport is
bound, rather than a silent upgrade.

Prior art for the transport, which is the part that would actually be adopted
rather than written: `latentharbor/tunnelfetch` ships TLS 1.2/1.3 and HTTP/2 in
userland ESM with no `node:` imports, and `EithonX/socksflare` ships rustls
compiled to WASM. v2 does not vendor either. `rig/v2.js` defines the binding
contract (`TLS_TRANSPORT.fetch(url, { method, headers, body, signal })`) and tests it
against a stub, which
is what a seam is for; a hand-written TLS stack behind an unmeasured claim would be a
worse thing to ship than an honest default.

---

## 4. What the comparators actually are

### 4.1 Jina Reader (`r.jina.ai`)

The open-source branch of `r.jina.ai`, Apache-2.0, 12,146 stars, last push
2026-05-22, **no GitHub releases or tags** (version is only `package.json` 0.5.0).

Four engines, from `src/dto/crawler-options.ts`:

```ts
export enum ENGINE_TYPE {
    AUTO = 'auto', BROWSER = 'browser', CURL = 'curl',
    CF_BROWSER_RENDERING = 'cf-browser-rendering',
}
```

The useful part: its `curl` engine is **not** plain curl. It is
libcurl-impersonate with a pinned JA3/JA4/Akamai fingerprint, taken from
`src/services/curl.ts`:

```ts
getChromeConfig({
  version: this.chromeVersion,
  fingerprint: {
    ja3: '772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-0-45-17613-65281-18-43-65037-5-51-16-10-27-13-35-11,4588-29-23-24,0',
    ja4: 't13d1514h2_002f,0035,...,cca8,cca9_0005,...',
    akamai: '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p'
  }
});
```

That is the concrete difference from a Worker: Jina can choose its TLS
fingerprint because it owns a native client. A Worker cannot, and no amount of
header code will get it there. Its browser engine is Puppeteer + real Chrome,
launched with `--disable-blink-features=AutomationControlled`.

Self-hosting it is not a serverless artefact. Its own README is precise about
what the open-source branch does and does not include: the MongoDB-backed storage
layer **"is not included here"**, and the oss branch "runs in stateless mode out of
the box, with optional MinIO/S3-compatible bucket caching". The GCP Cloud Run +
MongoDB Atlas + GCS stack appears in `architecture.md`, where that same file marks
the SaaS configuration as "not part of the open source branch". So the cost of
self-hosting is a service or two under the operator's own control, and the honest
comparison is v2's $5/month against a container bill plus whatever datastore is
attached. An earlier
draft of this document attributed that stack to the README and inverted it.

### 4.2 browser-use

117,859 stars (live API read on 2026-10-13; an earlier draft said 117,831),
MIT, Python, latest release **0.13.11** (2026-10-07).

The notable finding, confirmed by bisecting `pyproject.toml` across release tags:
**as of 0.13.11 it does not depend on Playwright or patchright at all.** The
switch happened at 0.6.0:

| tag | playwright | patchright | cdp-use |
|---|---|---|---|
| 0.3.0 | `>=1.52.0` | `>=1.52.5` | absent |
| 0.5.0 | `>=1.52.0` | `>=1.52.5` | absent |
| **0.6.0** | absent | absent | `>=1.4.0` |
| 0.13.11 | absent | absent | `1.4.5` |

It speaks raw Chrome DevTools Protocol via `cdp-use`, launching Chromium itself
with `--remote-debugging-port`. `patchright` now survives in exactly one place: a
commented-out CI line.

Two things worth correcting against a common assumption: **there is no YAML config**
for 0.13.11 (`BrowserProfile` is a Pydantic model; `grep yaml browser_use/` returns
two hits, both in a list of downloadable file extensions), and **no display is
required** — `profile.py:1253` picks headless automatically when no screen is
found.

It is an agent loop with an LLM in it, which is a different product from a proxy.
It cannot run on Workers at any price.

### 4.3 Azathothas/b-ids

Not a proxy and not a client. A measurement corpus: **0BSD**, Rust, 0 stars,
created 2026-08-30, last push 2026-10-13. It measures what real browser builds put
on the wire and republishes it as static files.

It is relevant to this project for exactly one reason: it states its own
boundaries explicitly, and those boundaries are the ones that matter here.

- It **does not complete a TLS handshake**. `crates/b-ids-cli/src/lib.rs:17`:
  "It completes no handshake, and that is the honest boundary."
- **No** proxy support, by design. `lib.rs:3`: "There is no cookie jar, no
  redirect policy, no retry logic, no proxy support and no output formatting, and
  there must never be."
- JA3/JA4/Akamai are **null in 22 of 22** profiles. `configs.rs:23`:
  "No digest artefact is generated here, and the absence is deliberate."
- It explicitly disclaims the scraping use case, including "bypass bot challenges
  or CAPTCHAs" (its wording, quoted).

So b-ids is the best available answer to "what would a browser actually send",
and it is explicitly not a way to send it as one.

### 4.4 Cloudflare changelog

`https://developers.cloudflare.com/changelog/rss/index.xml`, **1,344 items** as of
2026-10-14, spanning 2024-02-26 to 2026-10-13. The 2026-10-13 snapshot this
section was first written against held 1,341; the feed grows, so a re-run will
differ by a few items and that is expected.

Product tag counts, counting a tag when it is an item's **FIRST** category rather
than anywhere in its tag list: Workers 174, WAF 125, Agents 45, **Browser Run 28**,
Workers AI 32, AI Gateway 26. The method matters and was previously unstated:
counted as "appears in any category", Workers is 260 rather than 174. The
load-bearing claim holds under either method.

Notably **`Browser Rendering` as a product tag: 0 occurrences** — the rename to
Browser Run is complete.

Limits that increased, and that matter for a design:

- **Worker bundle**: 3 MB Free / 10 MB Paid -> **64 MiB uncompressed, all plans**
  (4 Sep 2026).
- **Runtime-update grace period**: 30 s -> **20 minutes** (12 Oct 2026).
- **Do Pending I/O**: up to 15 minutes per pending operation (1 Oct 2026).
- **Markdown-for-Agents conversion**: 2 MiB -> 6 MiB (9 Oct 2026).
- **KV namespace jurisdictions GA**, **Queues multi-jurisdiction** (Oct 2026).

No entry in the 150 most recent announces a price **increase** for Workers or
Browser Run.

**But a pricing change landed that this sweep did not catch.** Workers Logs moves
to Cloudflare Observability pricing on 2026-12-01 (section 7.1). It appears on the
pricing page and in a blog post rather than as a Workers-tagged changelog entry, so
a sweep of the changelog alone misses it. The generalisation is that a pricing
claim sourced only from the changelog is not a complete survey of pricing.

---

## 5. Browser Run

The product was renamed: `developers.cloudflare.com/browser-rendering/` redirects to
`/browser-run/`. The REST namespace is still `browser-rendering` in the OpenAPI
spec, while the docs prose and samples use `browser-run`; both resolve, and both
return the same auth error rather than a 404. (The redirect status
was reported as 301 by one review pass and as 302 by an earlier draft of this
document. The status could not be settled from this environment: the only reachable HTTP
client here returns 404 for a control URL known to exist, so it cannot answer the
question, and the claim is not load-bearing for anything below. The destination is
what matters and it is unambiguous.)

**Pricing** ([source](https://developers.cloudflare.com/browser-run/pricing/), last
updated 21 Apr 2026, verified verbatim):

| | Workers Free | Workers Paid |
|---|---|---|
| Browser hours | 10 minutes **per day** | **10 hours/month, then $0.09 per additional hour** |
| Concurrent browsers (Sessions only) | 3 | 10 averaged monthly, then $2.00 per additional browser |

- **Quick Actions** (stateless HTTP) are billed for **browser hours only**.
- **Browser Sessions** (Puppeteer/Playwright/CDP) are billed for browser hours
  **and** concurrent browsers.
- Every Quick Actions response carries `X-Browser-Ms-Used`, the metering header.
- Free plan: 1 Quick Action per **10 seconds**, 1 new browser per 20 s, 5 crawl
  jobs/day. Paid: 200 concurrent browsers, 30 Quick Actions/sec.

**Limits** ([source](https://developers.cloudflare.com/browser-run/limits/), 26 Sep 2026):
browser timeout 60 s by default, extendable to 10 min with `keep_alive`, and "no
fixed maximum lifetime for a browser session as long as it remains active".

**No identity features.** Cloudflare's own limits and pricing pages list no
non-datacenter proxy option and no challenge-solving capability. That is not a
criticism of the product; it is the stated scope.

Minimal Worker, verbatim from the docs:

```ts
interface Env { BROWSER: BrowserRun; }
export default {
  async fetch(request, env): Promise<Response> {
    return await env.BROWSER.quickAction("content", { url: "https://example.com" });
  },
} satisfies ExportedHandler<Env>;
```

Requires compatibility date **>= 2026-03-24**. Note the docs contradiction: the
`timeouts.md` page says `actionTimeout` max 5 min, while both the shipped
`@cloudflare/workers-types` and the API schema say **max 120000 ms**. Trust the
schema.

---

## 6. v2

Plain ES2022. No build step, no dependencies, no TypeScript. `rig/v2.js` deploys as
written. (TypeScript was the first draft and was dropped: `workerd` does not
transpile `.ts` under `esModule`, verified, so a TS build step would be required
for no benefit.)

### 6.1 What it fixes

Every row is an assertion in `harness/test_proxy.py`, run under real `workerd`.

| Fix | Assertion |
|---|---|
| Query string preserved | `v2: preserves the target query string` |
| Three target forms | path-prefixed, `?url=`, bare host |
| Scheme allowlist | `rejects non-http(s) schemes with 400` |
| SSRF guard | 15 blocked forms, incl. `[::1]`, `[::ffff:a9fe:a9fe]`, `localhost.`, `2852039166`, `10.0.0.1`, `192.168.1.1` |
| Proxy credential never forwarded | `authorization`, `proxy-authorization`, `x-proxy-key` all stripped before the origin |
| Edge headers not forwarded | `X-Forwarded-For`, `X-Real-IP`, `CF-Ray`, `CDN-Loop` |
| Default persona is honest | `v2: does NOT claim Chrome by default`; `v2: sends no sec-ch-ua on the honest persona` |
| Bot-tool UA replaced on the default persona | 7 tool UAs, incl. `curl`, `python-requests`, `Go-http-client`, `okhttp`, `scrapy` |
| `persona=pass` verbatim | the caller's UA is forwarded untouched |
| Chrome persona needs a TLS transport | `persona=chrome` **without** `engine=tls` does not claim Chrome; the request proceeds on the `fetch()` engine and the caller's UA is rewritten to `Cloudflare-Workers`, so the origin sees an honest identity rather than a browser claim the handshake cannot support. Measured: 200 with `User-Agent: Cloudflare-Workers`. Asking for `engine=tls` with nothing bound **is** a 501, so the engine itself is never silently downgraded. The persona is dropped, the engine is not. |
| `engine=tls` without a transport is 501 | `engine=tls without a bound transport returns 501, not a silent fallback`, and the body names `TLS_TRANSPORT` |
| Transport branch actually routes | `tls: engine=tls routes the request to the bound transport`, plus a control that a bound transport is **not** used on `engine=fetch` |
| Chrome persona is internally coherent | `sec-ch-ua` major == UA major; `sec-ch-ua-platform` == the UA's OS |
| Secure-context gate | no hints and no `Upgrade-Insecure-Requests` over plaintext `http://` |
| Control headers never forwarded | `x-proxy-engine`, `x-proxy-persona` |
| Caller hints dropped | a supplied `sec-ch-ua-model` cannot contradict the rewritten UA |
| Genuine browser UA untouched | verbatim, **no** hints added |
| Cookies **not** forwarded by default | intended capability, safer default. Opt back in per request with `X-Proxy-Forward-Cookies: 1`. |
| `Referer` rewritten to target origin | no longer names the caller's private app. Also intended in v1, and also an opt-in-shaped decision rather than a removal. |
| CORS complete | reflects `Origin`; preflight carries **ACAO**; appends to upstream `Vary`; no `allow-credentials` |
| Response framing preserved | `content-encoding` kept; repeated `Set-Cookie` not comma-joined |
| Redirects followed manually | headers rebuilt per hop; 303 downgrades to GET; **307/308 replay method and body** |
| Policy re-applied per hop | allowlist + SSRF guard run on every hop, so a redirect cannot escape |
| Redirect cap pinned | 3-hop chain completes, 12-hop chain refused with 508, relative `Location` resolves |
| Per-request timeout | `X-Proxy-Timeout-Ms`, clamped to [250, 60000], resolved value observable at `/__config` |
| Auth + allowlist | 17 assertions: 401/403 paths, case-insensitive scheme, subdomain vs lookalike |

Totals across the suite are in section 8.1. An earlier revision of this paragraph
carried a stale breakdown (172 rows, 5 controls) that had not been updated as
sections were added; section 8.1 is the single place the counts live, so a
reader counting rows from the run output lands in one number rather than three.

### 6.2 Behaviour changes that will break an existing v1 caller

Stated plainly, because a proxy upgrade that silently changes results is worse
than one that fails loudly.

| Change | Effect on a v1 caller |
|---|---|
| Cookies no longer forwarded | Sessions that relied on the proxy passing `Cookie` **stop working**. Opt back in per request with `X-Proxy-Forward-Cookies: 1`. |
| `Authorization` no longer forwarded | Callers using the proxy to reach an authenticated API must pass their token some other way. This is the point of the change: it is how the proxy's own credential stopped leaking. |
| Caller `Origin` and `sec-fetch-*` no longer forwarded | A third party can no longer see which app relayed the request. Rarely depended on, and it was a leak. |
| Caller Client Hints stripped **when** the UA is replaced | A browser caller whose UA is forwarded untouched keeps its hints. Only a bot-tool UA loses them, which is the case where they contradicted the UA. |
| Upstream `Access-Control-Allow-Credentials` no longer passed through | An origin that opted the caller into credentialed CORS no longer can. Deliberate: pairing that with a reflected ACAO is the credentialed-open-proxy bug. |
| `OPTIONS` is answered by the proxy, never forwarded | v1 proxied a real `OPTIONS` to the target. A caller using the proxy as a generic HTTP client for `OPTIONS` (WebDAV discovery, capability probing) now gets the proxy's 204 instead. **This is the most likely silent break.** |
| The target path is percent-decoded | `/https://host/a%2Fb` fetched `a%2Fb` under v1 and fetches `a/b` now; `%3F` becomes a real query separator and `%23` truncates the path. A caller relying on an encoded path to stay literal is affected. |
| Redirects capped at 5 hops | v1 followed 100, 200 and 400-hop chains and returned the final page. v2 returns **508**. Any real-world chain longer than 5 now fails. |
| `?url=` is read only on an empty path | `/api.example.com/x?url=y` proxied to `/api.example.com/x` under v1; under v2 the path wins **and the query is preserved**, so the upstream sees `/x?url=y`. |
| Network errors are JSON `502` | v1 returned plain-text `500`. Clients matching on 500 will not match. |
| `Accept` always sent | v1 sent none when the caller sent none, so a raw API client now receives the browser default unless it sets `Accept` explicitly. |
| Timeout is per hop | Worst case `(MAX_REDIRECTS+1) x MAX_TIMEOUT_MS`. |
| `cf-*` response headers dropped | v1 passed them through. Harmless; they are edge artefacts. |
| **A 30 s default upstream deadline** | v1 set no deadline at all. A v1 caller proxying an origin that takes 34 s to send headers got a 200; under v2 the same request is **502 "Upstream request timed out"** at 30 s. This is the regression most likely to be met in practice, because slow origins are ordinary. Raise it per request with `X-Proxy-Timeout-Ms` up to 60000. |
| `Accept-Language` is always sent | v1 sent none unless the caller did. v2 defaults it to `en-US,en;q=0.9`, so an origin doing content negotiation sees a language the caller never expressed. Set it per request with `X-Proxy-Accept-Language`. |
| `Host` is not forwarded | v1 forwarded the caller's `Host`, which is wrong: it handed the proxy's own name, or whatever the caller set, to a third-party origin. v2 sends none and lets the runtime derive it from the URL. |
| Hop-by-hop headers are not forwarded | `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade` and `Proxy-Authenticate` no longer reach the destination. RFC 9110 s7.6.1 forbids forwarding them, and v1 forwarded all of them. |
| `X-Forwarded-Proto` is not forwarded | Listed in v1's removal set already for `X-Forwarded-For` and `X-Real-IP`; v2 adds it, and a caller that set it deliberately no longer passes it through. |
| Cookie consent is scoped to one host | `X-Proxy-Forward-Cookies: 1` forwards the cookie to the host the request names. A redirect to a different host does not inherit the consent. A v1 caller that relied on cookies surviving a cross-host redirect sees the target without them. |
| `engine=tls` refuses a bodied request without `supportsBody` | A `POST` with `X-Proxy-Engine: tls` and a transport that has not declared `supportsBody = true` gets a **501**, not a bodiless request. Before the transport contract was tightened, an earlier build passed no method or body at all, so the destination received an empty `POST` and answered 200. |
| The timeout bounds headers, not the body | `X-Proxy-Timeout-Ms` is cleared once response headers arrive. A destination that sends headers at once and stalls afterwards still completes. Aborting mid-stream would truncate a response already in progress, and there is no way to signal truncation through a streaming body. |
| An `ALLOWED_HOSTS` entry may carry a port | The port is ignored. Earlier, an entry written as `origin.test:8443` matched nothing at all and refused every request, including the one it named. |
| A `304` is returned, not followed | Earlier, any `3xx` carrying a `Location` was consumed as a redirect hop. `304` is not a redirect (RFC 9110 s15.4.5): it has no body, and its `Location` names the selected representation for a conditional request. Such a response is now passed through. |
| `Location` is resolved against the hop it came from | A relative or protocol-relative `Location` is made absolute and rewritten into proxy space. Earlier, a relative `Location` was passed to the client unchanged, and a protocol-relative one named the host directly, in both cases sending the client off the proxy. |
| Origin-scoped response headers are dropped | `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `Permissions-Policy`, `COOP`, `COEP`, `CORP`, `Report-To`, `NEL` and `Clear-Site-Data` from an upstream no longer reach the client. They are scoped to the origin that emitted them (RFC 9535 s4 for `Clear-Site-Data`), and a response served from the proxy's host is not the upstream's document. |
| A `Location` this proxy cannot express is dropped | A `ftp:`, `javascript:` or `data:` Location on any status is removed rather than passed through. Such a value cannot be rewritten into proxy space, and forwarding it sends the client off the proxy by a path no policy here evaluated. |
| Caller headers do not cross a cross-host redirect | On a hop to a host the caller did not name, only the proxy's own headers are sent. `Authorization` and `Cookie` were already dropped; `X-Forwarded-Authorization`, `X-Api-Key`, `X-Auth-Token` and any other caller-supplied header now are too. |
| A header named by `Connection` is not forwarded | RFC 9110 s7.6.1 requires it. `Connection: X-Secret` previously forwarded `X-Secret` upstream. |
| Cookie consent covers the scheme | A consented cookie is not sent to an `http:` hop when the caller named an `https:` target. An origin answering `302 Location: http://same-host/other` previously received the cookie in cleartext. |
| A non-string `ALLOWED_HOSTS` is refused | A binding that is an array, a number or a boolean returns **500** rather than falling back to the open-proxy default. An empty or whitespace-only string still means "no allowlist". |
| A target that is not a bare authority is refused | The bare-host fallback required a shape match and a round-trip check. `"https://[fe80::1%25eth0]/"` previously fetched `https://https//[fe80::1%eth0]/`, a host the caller never named.

### 6.3 What it deliberately does not do

These are the honest limits, and they are in the file as comments:

- **It does not alter the source address.** Not possible on Workers.
- **It does not set `cf-connecting-ip`.** v1 tried; it is dead code, and Cloudflare
  would strip it anyway.
- **It does not claim to solve Turnstile or reCAPTCHA.** Section 3.
- **It does not strip Cloudflare's re-injected headers**, because stripping them
  from the outbound `Request` does not stop the edge adding them.
- **It does not claim header consistency equals a real browser.** It fixes
  internal inconsistency, which is a subset of what a vendor checks.
- **It does not ship a TLS stack.** `engine=tls` is a bound-injection seam, and it
  returns 501 when nothing is bound. An earlier draft called TLS control
  impossible; section [3.3](#33-layer-1-tls-fetch-is-closed-connect-is-not)
  corrects that, and the seam is what the correction makes possible without
  shipping a hand-rolled handshake behind an unmeasured claim.

### 6.4 The persona model, and why the default is not Chrome

v1 answers every request with one hardcoded Safari 18.5 User-Agent. v2 replaced
that with three named personas, and the interesting decision is the default.

| `X-Proxy-Persona` | what the origin sees | when it applies |
|---|---|---|
| `edge` (**default**) | `User-Agent: Cloudflare-Workers`, no `sec-ch-ua` | always |
| `chrome` | Chrome UA + low-entropy hints + `Upgrade-Insecure-Requests` | **only** with `X-Proxy-Engine: tls` and a bound transport |
| `pass` | the caller's UA verbatim | opt-in |

The reason `edge` is the default is section 3.3's measurement. The incumbent's own
handshake is `t13d1312h2_a44d0ee8b3cc_e381dae6da6b`, which reads as **TLS 1.3**
with 13 ciphers and 12 extensions, while it announces Safari 18.5. A real Chrome
155 is `t13i1516h2_8daaf6152771_...`: TLS 1.3 with **15** ciphers and **16**
extensions. Presenting a browser User-Agent over a handshake that is not that
browser's is a louder signal than presenting an accurate one, because the
mismatch is the tell.

So the layers have to move together, and v2 enforces that:

- `edge` describes the transport honestly, and sends **no** Client Hints of its
  own, because inventing `sec-ch-ua` would be the same overclaim in miniature.
- `edge` also strips the **caller's** Client Hints when, and only when, it is
  replacing their User-Agent. Leaving `sec-ch-ua-platform: "macOS"` beside a
  `Cloudflare-Workers` UA is precisely the incoherent identity this section exists
  to prevent, and an earlier revision stripped only the high-entropy hints and so
  shipped exactly that. When the caller's own UA goes upstream untouched (a
  genuine browser, or `persona=pass`) their hints go with it, because then the pair
  is coherent.
- `chrome` is refused unless `engine=tls` is also requested **and** a transport is
  bound. Without one it is not silently downgraded; `engine=tls` alone returns 501.
- Over `http://`, `chrome` still claims Chrome but sends **no** hints and **no**
  `Upgrade-Insecure-Requests`, because Client Hints are a secure-context feature.

That last one was a defect introduced here and then fixed:
`Upgrade-Insecure-Requests` was originally set outside the `https:` branch, so a
plaintext target got a Chrome UA
*and* a header Chrome only ever sends from a secure context. `mutation_check.py`
now carries a `secure-context upgrade header` mutation that fails if it returns.

Coherence inside the `chrome` persona is asserted, not assumed: the major in
`sec-ch-ua` must equal the major in the User-Agent, and `sec-ch-ua-platform` must
match the OS the UA claims. A Chrome UA beside a macOS platform hint is a stronger
tell than saying nothing.

---

## 7. Pricing

All Workers figures verified verbatim from
[developers.cloudflare.com/workers/platform/pricing](https://developers.cloudflare.com/workers/platform/pricing/)
(last updated 2 Oct 2026). Browser Run from section 5.

### 7.1 The meters that matter

| Unit | Included (Paid) | Overage |
|---|---|---|
| Requests | 10 million/month | **$0.30** per million |
| CPU time | 30 million CPU-ms/month | **$0.02** per million CPU-ms |
| **Workers Logs** | **20 million log events/month** | **$0.60** per million |
| Subscription | — | **$5.00/month minimum** |
| Egress / bandwidth | — | **not charged** |
| Subrequests | — | **not billed** |

That last row matters more than it looks: **the outbound fetch to the origin is
free**. For a proxy, the cost is inbound requests plus CPU plus log events.

**Workers Logs is a real third meter and it was missing from an earlier draft of
this table, which is why the draft claimed "the entire cost is inbound requests
plus CPU".** The pricing page, which this table quotes, carries it directly:

> Workers Paid: 20 million included per month, **+$0.60 per additional million**

It is not optional in the way the table's other rows are, because
`/workers/observability/logs/workers-logs/` states that observability is **on by
default** for newly created Workers, and `wrangler.toml` did not disable it. At the
100M-requests/month row that matters most, if each request writes one invocation
log, 80M events of overage is **+$48.00**, taking **$45.40 to $93.40**. The 1M and
15M rows sit under the 20M inclusion and are unaffected.

How many events one proxy request writes is not measured, because that needs a
deployed account. The rate, the allowance and the default-on state are all
from Cloudflare's own documentation. Either way the cheap fix belongs in the
deploy config, and it is now there:

```toml
[observability]
enabled = false
```

Set that unless Workers Logs are wanted, and the meter disappears.

**That meter has an expiry date the table above does not carry.** The same pricing
page states:

> **Pricing change** — "Beginning December 1, 2026, Workers Logs will use
> [Cloudflare Observability pricing](https://developers.cloudflare.com/observability/pricing/).
> Until then, the Workers Logs pricing in this table applies."

The replacement is metered per GB ingested rather than per event, with a different
allowance. So `$93.40` is a model with an end date: right for the period it
covers, not the right model from 2026-12-01. That affects the table and not the
conclusion drawn from it in 7.2, because the config as shipped sets that term to
zero. Verified 2026-10-14.

**Subrequest ceilings are a limit, not a cost, and they were missing.** The table
above prices subrequests at nothing, which is right, but the runtime also caps
them: **50 per invocation on Free, 10,000 per invocation on Paid**, from
`/workers/platform/limits/`. The same page notes "Each subrequest in a redirect
chain counts against this limit", which is the line that matters for a proxy that
follows redirects by hand. `MAX_REDIRECTS + 1` is 6 subrequests at most, which
sits well inside 50, so the ceiling is not reachable through this worker. Both
facts are worth stating: the headroom is measured, and the limit exists.

CPU is mostly waiting on I/O, which the docs explicitly exclude: "Waiting on
network requests (such as `fetch()` calls...) does not count toward CPU time."

That sentence, and the figure below it, are from the **limits** page, not the
pricing page: "The average Worker uses approximately 2.2 ms per request." The same
page places authentication, server-side rendering and large-payload parsing in a
**10-20 ms** band, which brackets the 7 ms figure used in 7.2 from above as well
as 2.2 ms from below. 7 ms is the conservative choice.

### 7.2 Cost model: self-built Workers proxy

Using 7 ms CPU/request, which is the figure in Cloudflare's own worked examples
(their Examples 1 and 4):

Two plans, because the binding constraint differs:

**Free plan — 100,000 requests per DAY**. The figure is on both
`/workers/platform/limits/` and `/workers/platform/pricing/`; the phrase
"resetting at midnight UTC" is on the limits page only, and the pricing page says
just `100,000 per day`. (An earlier draft said the whole sentence was verbatim on
both pages, which was half wrong.)

| Traffic | Cost |
|---|---|
| Up to ~3.0M requests/month, provided no day exceeds 100,000 | **$0** |
| 1,000,000 requests/month (~33,300/day) | **$0** |
| One day over 100,000 | Error 1027 |

**Paid plan — $5.00/month minimum**, 10M requests included.

| Requests/month | CPU ms @7ms | Cost |
|---|---|---|
| 1,000,000 | 7,000,000 | **$5.00** (both meters inside the included allowance) |
| 15,000,000 | 105,000,000 | **$8.00** (Cloudflare's own published example) |
| 100,000,000 | 700,000,000 | **$45.40** (Cloudflare's own published example) |

The 15M and 100M rows are Cloudflare's own numbers, and they reproduce exactly
from the formula `5.00 + max(0, reqs-10M)/1e6*0.30 + max(0, cpu_ms-30M)/1e6*0.02`.
That the formula reproduces their published worked examples is the check that it
is right.

**So the honest answer to "what does it cost" is $0 up to ~3M requests/month**,
then $5.00, rising to $45.40 at 100M/month. The $5.00 floor is the Paid plan's
minimum, not a hard floor overall.

Two caveats on the Free plan that matter more than the price:

- **CPU is capped at 10 ms per invocation**, versus 5 minutes on Paid. A proxy
  that must parse, buffer and re-emit headers sits near that on a slow origin.
- **Exceeding the daily cap returns Error 1027, and the route mode decides what
  happens.** Both documented modes, quoted from `/workers/platform/limits/`:

  > | Fail open | Bypasses the Worker. Requests behave as if no Worker is configured. |
  > | Fail closed | Returns a Cloudflare `1027` error page. Use this for security-critical Workers. |

  Under **fail open**, auth and header rewriting are skipped entirely for the
  overflow traffic, so a traffic spike silently disables the control. Set the
  route to **fail closed** before using the Free plan.

  **Which mode is the default is not stated anywhere in Cloudflare's
  documentation**, so this document does not claim it: the limits page shows both
  in a table with no default marked, and neither does the routing documentation.
  Check it in the dashboard, `Workers & Pages > worker > Settings > Triggers`.
  (An earlier draft asserted "fail open" is the default. That assertion was
  unverifiable, so it has been removed rather than softened.)

### 7.3 Feature parity and cost versus each comparator

| Capability | Jina Reader | browser-use | **api.rv v2** | Browser Run (CF) |
|---|---|---|---|---|
| Plain proxy / forward fetch | yes | no | **yes** | no (browser only) |
| Runs JS | yes (Chrome) | yes | **no** | yes |
| TLS fingerprint control | yes (pinned fingerprint) | via local Chrome | **yes, over `connect()`; costs CPU and a transport binding** | no |
| Challenge solving | no | agent-driven, needs a real browser | **no** | no |
| Serverless | Cloud Run + Mongo | no | **yes, native** | yes |
| Self-host cost @1M req/mo | VM + DB + cache | VM | **$5** | $5 + $0.09/browser-hr |

**Where parity is genuinely achievable at near zero cost**: the proxy role. v2
matches Jina's *fetch-and-relay* behaviour and beats both competitors on cost by
roughly an order of magnitude against a plain VM, or two against a self-hosted
Jina with its database and cache. The earlier claim of "2-4 orders of magnitude"
was unsupported: no dollar figure for either comparator appears anywhere in this
repository, and 4 orders would require a $50,000/month competitor.

**Where parity is achievable but costs CPU**: the TLS fingerprint. This row was
"no, impossible" in an earlier draft and that was wrong; section
[3.3](#33-layer-1-tls-fetch-is-closed-connect-is-not) corrects it. v2 does not
implement the transport, so today the honest cell is "seam defined, not shipped".

**Where parity is impossible, at any cost**: the egress address and challenge
solving. That is a property of the network and of a browser, not of code.

### 7.4 What adds real money

Where JS execution is needed, the marginal cost is Browser Run and nothing else.
$0.09/hour = **$0.000025 per second of browser time**:

| Seconds of browser time per page | Cost per page | 1M pages/month |
|---|---|---|
| 4 s | $0.0001 | $100.00 |
| 8 s | $0.0002 | $200.00 |
| 15 s | $0.000375 | $375.00 |

The included 10 browser-hours/month is 36,000 seconds, which covers 36,000
one-second pages or 4,500 eight-second pages before any marginal cost. That is why
selective routing matters: Browser Run for pages that need JS, plain `fetch()` for
everything else.

**Could not measure real per-page browser milliseconds.** It requires a
deployed Cloudflare account, which this environment has no credentials for. Every
figure in section 7.4 is arithmetic on the published $0.09/hour rate with the
per-page seconds stated as an assumption. The one number to measure on first
deploy is `X-Browser-Ms-Used` from a real Quick Action; it turns this section
from arithmetic into a measurement.

---

## 8. Reproducing the proofs

### 8.1 Layout

```
rig/v2.js             the worker (plain JS, no build)
rig/v1-baseline.js    v1, reformatted, with an 11-line provenance header (see 1)
wrangler.toml         deploy config
LICENSE               0BSD
harness/rig.py        runs a worker under real workerd, with an in-process TAP origin
harness/test_proxy.py  407 assertion rows in 14 sections, of which 32 are controls:
                      152 v2 (C), 17 auth+allowlist (D), 21 engine/persona (E),
                      8 engine/body (F), 12 hostlist (G), 11 redirect scoping (H),
                      4 response edges (J), 67 header coverage (K), 23 CORS (L),
                      35 previously-unpinned branches (M), 13 origin-scoped
                      response headers (N), 30 security round 4 (O),
                      5 what the timeout bounds (P),
                      9 v1 observation (A/B), of which 3 NEG-CONTROL and 29 CONTROL
harness/mutation_check.py  58 mutations, each required to be caught
harness/probe_raw_socket.py  the Layer 1 measurement: is connect() a raw stream?
harness/probe_*.py    the five probes: four behind the timeout findings, plus
                      probe_raw_socket.py behind section 3.3
tools/ja4.py          JA4 from a raw ClientHello, from first principles
proofs/01-api-rv-tls.{json,txt}  the live incumbent's TLS fingerprint
proofs/02-raw-socket.txt         probe_raw_socket.py output, control included
evidence/bids-*      the b-ids Chrome ClientHello and header order, verbatim
bin/wd                workerd 2026-10-13 (Cloudflare's actual runtime)
```

### 8.2 Run

```bash
python3 harness/test_proxy.py            # ~5s, 407 assertion rows, 32 controls
python3 harness/mutation_check.py        # ~30s, 58 mutations, 6 in parallel
python3 harness/probe_raw_socket.py      # ~0.3s, needs the sandbox CONNECT proxy
```

All three exit non-zero on failure. `test_proxy.py` accepts a worker path as
`argv[1]`, which is how the mutation check runs variants without writing to
`rig/v2.js`.

### 8.3 Why the harness looks unusual

This sandbox **refuses every TCP `bind()`/`listen()`** (`EACCES`, all ports, both
127.0.0.1 and 0.0.0.0), and **direct TCP `connect()` to the internet times out**
(only an HTTP CONNECT proxy at `169.254.169.1:36179` is reachable). Verified, not assumed. AF_UNIX sockets do work.

So the harness uses the two workerd features that make this possible anyway:

1. `sockets = [ (name = "http", address = "unix:/tmp/...") ]` — workerd supports
   `unix:` socket addresses, so inbound requests arrive over AF_UNIX.
2. `globalOutbound = "tap"` on the Worker — the outbound `fetch()` is routed to an
   **in-process TAP worker** instead of the network.

One more workerd feature matters for section 3.3 and is worth knowing: the
`Network` struct in `workerd.capnp` carries `allow = ["public"]` by default, which
is why `connect()` to a loopback or link-local peer fails with
`connect() blocked by restrictPeers()`. Naming a `network` service with
`allow = ["public", "private", "local"]` as `globalOutbound` changes that, which
is how `probe_raw_socket.py` gets a peer that answers. It is a harness
configuration, not something a deployment on Cloudflare needs: the real edge
already has egress.

The TAP is what makes this an assertion harness rather than a demo. It receives
the `Request` the runtime actually built for the upstream call and returns a JSON
description of it: URL, method, every header **in iteration order**, body. Tests
assert on the proxy's real output, not its intent. It is also scriptable
(`/__ctl/redirect`, `/__ctl/chain`, `/__ctl/slow`, `/__ctl/hang`, `/__ctl/status`)
so redirect and error paths are reachable.

### 8.4 Negative control, and why it matters

The harness runs the **unmodified v1** first and asserts that three known defects
are actually observed:

```
NEG-CONTROL v1: cf-connecting-ip is never set (dead code)
NEG-CONTROL v1: drops the target query string
NEG-CONTROL v1: emits no CORS headers
```

If those do not fire, the run reports **INVALID** and the v2 results are
discarded. A suite that cannot fail proves nothing.

`CONTROL:` rows sit inside the v2 sections. Each one is the negative half of a
pair: it asserts that a defect or a branch selector **is** present, so it is valid
when it passes. Scoping the control count to one section (as an earlier revision
did) let a failing control elsewhere print VALID, so the tally now spans every
section. 14 controls, all firing.

A guard that has only been seen to refuse is indistinguishable from one that
refuses everything, so each refusal has an acceptance row beside it. The clearest
case is the `engine=tls` body contract: `supportsBody` absent refuses a `POST`,
`supportsBody = false` refuses the same `POST` on a second worker, and
`supportsBody = true` delivers it. Only the first two of those three prove the
flag is read.

### 8.5 Mutation check

A negative control proves the harness catches defects that already exist. It does
**not** prove it would catch a regression introduced into v2. So 58 single-line
mutations are applied to a copy of v2, and the suite must fail for each:

```
58/58 mutations caught
OK: every mutation was detected, so the v2 assertions have teeth.
```

Every mutation was written because something was **caught that should not have
been**, or **survived that should not have**. There are no decorative entries.

1. **`redirect cap`.** The suite asserted "an infinite loop returns 508". Raising
   `MAX_REDIRECTS` to 500 still returns 508, because a loop is a loop. Fixed by
   adding a **countable** chain: 3 hops must complete, 12 hops must be refused.
2. **`upstream timeout` and `timeout clamping`.** No assertion could distinguish a
   30s default from a 600s one, because the harness's simulated peer was too fast
   to tell them apart (section 8.6). Fixed by adding `/__config`, which reports the
   **resolved** timeout, so the clamp is pinned exactly rather than inferred.
3. **`genuine UA passthrough` was a false positive.** The pattern
   `looksLikeBotTool(ua)` also matched the *declaration*
   `function looksLikeBotTool(ua)`, producing `function true {`, a syntax error.
   The suite failed, the mutation was scored "caught", and it had pinned nothing.
   Fixed by anchoring the substitution to the call site, which the persona rewrite
   then invalidated again, because the call site stopped being an `if`.
4. **`allowlist label boundary` exposed two harness bugs.** It mutated
   `endsWith("." + want)` to `endsWith(want)`, which really does admit
   `evil-origin.test` — verified against the runtime. The suite still passed,
   for two reasons: `probe_auth` read a **hardcoded** `rig/v2.js` instead of the
   worker under test, so its 16 assertions ran against the *original* while the
   other 99 ran against the mutant; and every section wrote its patched worker to
   one **shared** filename, so parallel runs overwrote each other. Both are fixed.
    This is the clearest argument for the mutation check: a green suite and a real
   hole coexisted, and only removing the invariant exposed it.
5. **`plaintext client hints` survived the persona rewrite**, and it survived for
   an uncomfortable reason: after `chrome` became gated on `engine=tls`, **no test
   reached that branch at all**. The suite was green over code that never executed.
   Fixed by adding section E, which binds a stub `TLS_TRANSPORT` and drives the
   branch. The general lesson is the one worth keeping: a mutation can survive
   because an assertion is weak, or because the code it targets is not being
   exercised, and the two need different fixes.
6. **`edge persona honesty`** did not exist until section E did. Setting
   `EDGE_UA = CHROME_UA` was the mutation that introduced the incumbent's own
   defect into v2, and nothing before would have caught it.
7. **`secure-context upgrade header`** caught a defect that had just been
   written: see section 6.4.

A surviving mutation is not a nuisance. It is the assertion reporting that it was not
pinning what it claimed.

### 8.5a What the timeout does and does not bound

The timer is cleared once the response headers resolve, so `X-Proxy-Timeout-Ms`
bounds **time to headers** and nothing else. `/__config` reports that as
`timeout_scope`, README says it, and the code comment says it, and until this
section nothing measured it: every timeout test used an origin that slept before
sending headers, which is the case the deadline does bound.

Two fixtures make the claim falsifiable in both directions. A peer that takes 34 s
to send headers is refused at 30 s. A peer that sends headers at once and finishes
its body 2 s later completes under a **250 ms** budget, because the timer is
already gone.

That second row is the one worth having. If a future edit moves `clearTimeout`
inside the body read, the row fails, and the failure is the loss of a documented
limit rather than a change in behaviour nobody agreed to.

The 34 s figure is also the clearest v1 regression in the upgrade. Measured
against one identical peer:

```
v1 -> status=200 after 34.0s  'late-headers'
v2 -> status=502 after 30.0s  '{"error":"Upstream request timed out",...}'
```

v1 set no deadline at all. An origin that takes 34 s to send headers was served by
v1 and is refused by v2, and section 6.2 says so.

### 8.6 Two clocks, and the second one was misreported for a while

**Two corrections, both in this section, and the first one is bigger than it looks.**

**Correction 1: the TAP's timers were never clamped.** An earlier draft said
"the TAP's timers are clamped to ~1 s; `/__ctl/slow?s=20` answers in 1.0 s, so
the harness cannot simulate a peer slower than ~1 s", and used that as the stated
reason the production wall-clock deadline is untested. **That was false.** The TAP
honours its sleep exactly:

```
/__ctl/slow?s=2   ->  2.00 s
/__ctl/slow?s=5   ->  5.00 s
/__ctl/slow?s=10  -> 10.00 s
/__ctl/slow?s=20  -> 20.00 s
```

The cause was in the **probes**, not the TAP: all four probe scripts built the TAP
path from `new URL(request.url).pathname.slice(1)`, which **discards the query
string**, so `/__ctl/slow?s=20` reached the TAP as `/__ctl/slow` and
`searchParams.get("s")` read its `|| 1` default. Every "slow peer" row in every
probe was a 1 s peer, and `probe_timer_semantics.py` STEP 1 printed the question
"does the PEER's sleep length matter at all?" above four measurements of the same
1 s peer. Fixed in all four scripts (`pathname.slice(1) + search`); the suite's TAP
in `rig.py` was always correct.

So the deadline section 8.6 used to defer *is* observable, and with the probes
fixed it is measured (below). That limitation is withdrawn, not restated.

**Correction 2: the earlier draft's timer numbers came from a buggy client.**
That version reported every deadline collapsing to a flat ~5 s. That was
`unix_request` reading to EOF, so each measurement included the wait for a
keep-alive connection to close. Honouring `Content-Length` (section 8.7 item 2)
fixed it.

Re-measured after both corrections, with the real workerd:

| Measurement | Result |
|---|---|
| Worker's own `AbortController`, budget 250 ms, peer sleeping 30 s | fires at **252, 252, 254 ms** CPU over 3 runs, always `own-abort` |
| Own budget 100 ms / 1000 ms / 5000 ms, peer 30 s | aborts at **102 / 1002 / 5001 ms**: elapsed tracks our budget |
| Own budget 30000 ms, peer 30 s | completes at **30.0 s** |
| Never-answering peer, no `AbortController` | workerd's hung-code detector at **0 s**, `worker_ms` 0-3 |

So both clocks are sound, and they are sound in different places:

1. **The Worker's timers are exact.** A 250 ms budget fires at 252 ms; a 5 s
   budget fires at 5001 ms. Elapsed time is a usable signal, both inside the code
   and at the client.
2. **workerd's hung-code detector fires immediately on a peer that never
   answers** (`worker_ms` 0-3), not after ~5 s. An earlier comment saying
   "cancelled by workerd itself at a fixed ~5 s" was wrong and is corrected.

The suite pins the timeout's **resolution and clamping** at `/__config` (exact and
instant) and pins the **abort path** by discriminator rather than by elapsed time.
The `CONTROL` assertion is what stops "our timeout fired" from being satisfied by
workerd's detector wearing the same status code, and that discriminator is stable:

```
own timer vs SLOW peer     3/3 own-abort
own timer vs HANGING peer  3/3 runtime-hung-detector
```

Both probes are the evidence: `probe_abort_discrimination.py` (above) and
`probe_timer_semantics.py` (budget-versus-wall table).

### 8.7 Defects introduced here, and the structural fixes

Three, each fixed by removing the possibility rather than by retrying.

**1. The mutation checker could corrupt the tree.** The first version mutated
`rig/v2.js` **in place** and restored it in a `finally`. A `timeout` killed that
run with `SIGKILL`, which skips `finally`, and left **`v2.js` mutated on disk**
with the `EDGE_IDENTITY` guard deleted. The next suite run failed 4 assertions,
which is how it surfaced. Fixed structurally: variants are written to a temp
directory and passed as `argv[1]`, so the canonical file is never opened for
writing.

**2. The harness client waited out a socket timeout on every request.** The suite
took **7 minutes 10 seconds** for 115 assertions. The cause was in the client, not
the tests: `unix_request` read until EOF, and workerd keeps connections alive, so
every assertion blocked until its timeout expired. After honouring
`Content-Length`, the same suite runs in **under a second**. Nothing about what is
being asserted changed; only the time to assert it.

**3. One suite section tested a different file than the one under test.** Covered
in 8.5 item 4: `probe_auth` opened a hardcoded `rig/v2.js`, and all three sections
wrote patched workers to one shared temp path.

### 8.8 What a passing mutation check still does not tell you

The 58 mutations are all *behavioural* line edits. They cannot catch:

- A wrong claim in this document. Nothing here checks prose.
- A defect that only manifests on the real edge (section 9).
- A test that asserts the right property of the wrong thing, where no mutation in
  the list happens to touch it.
- Concurrency. Every test here is single-request and sequential.
- A **stubbed** transport being correct. Section E proves the plumbing around
  `TLS_TRANSPORT`, not that a real TLS stack is correct. The stub has no
  ClientHello and no certificate validation.

The suite proves v2's logic behaves as specified under `workerd`. It does not
prove v2 is deployed correctly, and it cannot.

### 8.9 The correction that changed the architecture

Recorded here rather than quietly fixed, because it inverted a load-bearing claim.

**What the earlier draft claimed**: TLS fingerprint control is impossible on
Cloudflare Workers, because `workerd` "offers no per-request TLS API", therefore
the ClientHello is Cloudflare's and nothing in a Worker can change it.

**What is true**: `connect({ secureTransport: "off" })` from `cloudflare:sockets`
returns a raw duplex byte stream. Measured under workerd 2026-10-13 in
`proofs/02-raw-socket.txt`, with the default-config failure kept as a control so
the positive result is not merely "a socket object exists".

**Where the claim came from, and what happened next.** The correction came from a
parallel research effort, `nemo-010/b-cf`. Their headline claim was checked rather
than adopted: Reproduced the mechanism under workerd, and independently
reproduced their `proofs/01` by curling
`https://api.rv.pkgforge.dev/https://tls.peet.ws/api/all` and recovering
`ja4 t13d1312h2_a44d0ee8b3cc_e381dae6da6b` and the `MAX_CONCURRENT_STREAMS = 1`
SETTINGS frame, which matches what their document records. Their repo is MIT and
this one is 0BSD, so nothing was copied: the finding and the design were taken, and
every number was recomputed here. `tools/ja4.py` is written from the JA4 spec
against the b-ids corpus bytes, and reproduces the reference `ja4_a` (`t13i1516h2`)
and `ja4_b` (`8daaf6152771`) exactly.

**What did not reproduce, and what that turned out to mean.** Their `ja4_c` of
`6ff14566cf4a` for the b-ids capture. An earlier revision of this document filed
that as an unexplained non-reproduction and labelled the field `UNVERIFIED` in
`tools/ja4.py`. That was the wrong conclusion from the right observation. The
cause is a rule difference, and it is now isolated:

| rule | extension hash input | sigalgs | b-ids `ja4_c` |
|---|---|---|---|
| FoxIO reference, and this repo | sorted, GREASE removed, **`0000` and `0010` removed** | GREASE filtered | `cb7bf5808d99` |
| The peer tool | sorted, GREASE removed, `0010` **kept** | **not** filtered | `6ff14566cf4a` |

`foxIO-LLC/ja4` `python/common.py` `get_hex_sorted()` removes both `0000` and
`0010` and `get_signature_algorithms()` filters GREASE, which is what
`tools/ja4.py` does. The tie-breaker is a third party: `tls.peet.ws` renders its
own `ja4_r` for the api.rv handshake, whose last two fields *are* the `ja4_c` hash
input, and its rendered extension list omits `0010`. Hashing peet's own string
reproduces peet's own `ja4_c` `e381dae6da6b` exactly, which is how `ja4_c` came to
be **verified rather than unverified**, against an implementation that had no
reason to agree with this implementation.

So all three JA4 fields are verified, two of them against the b-ids corpus and
`ja4_c` against the live capture. The peer tool's value is not wrong for its own
rule; it is a different rule.

**What changed in the code as a result.** The persona model did not exist before
this correction. It exists because the corrected picture produced a design
question the old claim made unaskable: if the ClientHello is ours, then a Chrome
User-Agent and a non-Chrome handshake are a *mismatch we control*, and the fix is
to make the layers agree. Section 6.4. The correction did not make v2 harder to identify;
it made v2 accurate about a choice it had been making badly by accident.

---

## 9. Deploying v2

`wrangler.toml` is shipped. Two steps, in this order:

```bash
wrangler secret put AUTH_TOKEN      # binds it; v2 reads env.AUTH_TOKEN
wrangler deploy
```

`AUTH_TOKEN` is read from the **binding** (`env.AUTH_TOKEN`), so the secret
command above genuinely takes effect. With no token set, the proxy is open, which
is v1's posture and not something to deploy.

**The bundle is the artifact, so test the bundle.** What deploys is not
`rig/v2.js`: wrangler runs it through esbuild, and the bundle is what runs in
production. The suite therefore accepts any worker path, so the built output can
be checked the same way:

```bash
wrangler deploy --dry-run --outdir /tmp/bundle
python3 harness/test_proxy.py /tmp/bundle/v2.js
```

Measured on wrangler 4.150.0: the build succeeds (21.15 KiB, 6.73 KiB gzipped)
and the bundle passes all 313 assertion rows and all 14 controls. This check found
a harness defect: the one control that patches the worker's own source to confirm
an assertion pins something was anchored to tab indentation, and esbuild emits
two spaces, so the control reported a false failure against a correct bundle. The
patch is now indentation-tolerant.

**`workers_dev` is set explicitly, and why that matters.** wrangler's
`getSubdomainValues` defaults `workers_dev` to `routes.length === 0`, and
`subdomainDeploy` posts that value to `/subdomain`. An earlier revision of this
config set `workers_dev = false` with no `routes`, which publishes a script with
no reachable trigger: `deploy` reports success, and the worker cannot be called.
`workers_dev = true` is stated here rather than left to the default.

`ALLOWED_HOSTS` is an optional `vars` entry, comma-separated:

```toml
[vars]
ALLOWED_HOSTS = "example.com,githubusercontent.com"
```

Leave it unset for the open behaviour. `GET /__config` reports the resolved
timeout, the effective allowlist and whether auth is on, so a misconfiguration is
visible rather than silent.

**The compatibility date matters.** The harness pins `2026-03-24`, which is what
the proofs ran against. `wrangler.toml` pins the same value so a deploy does not
silently pick up a different runtime than the one that was tested.

**Check the route's failure mode.** Under "fail open" the Worker is skipped
entirely once the Free plan's daily cap is exceeded, so auth and header rewriting
stop applying to the overflow traffic. Under "fail closed" the caller gets an
error instead. Set it to fail closed. Cloudflare's documentation does not say which
is the default; see section 7.2.

---

## Limits: what this document does not establish

Named precisely, because each would otherwise read as settled.

1. **No deployed Cloudflare account.** Nothing here was run on the real edge. Real
   egress IP, real JA3/JA4, real bot scores are unmeasured. All local numbers come
   from `workerd`, and section 8.6 shows the local runtime differs from the edge in
   observable ways.
2. **No real browser was run.** Browser Run's per-page `X-Browser-Ms-Used` is
   therefore an assumption in section 7.4, not a measurement.
3. **Header ORDER was captured from the runtime, not from a server's TCP capture.**
   The TAP reads `Headers` iteration order, which is what workerd will serialise,
   but it is not a `tcpdump` of bytes on the wire.
4. **A full TLS handshake was not completed inside workerd.** Section 3.3 proves
   `connect()` hands over a raw byte stream, which is the property the architecture
   depends on, but the peer available here is a plaintext HTTP CONNECT proxy, not
   a TLS origin. So "a Worker completes a TLS 1.3 handshake and gets a JA4 we
   chose" is **not** demonstrated by this repo. It is not demonstrated here, and
   reading it as demonstrated would be the same error in the opposite direction.
   The honest statement is that the transport seam is proven and the transport is
   not shipped.
5. **All three JA4 fields are verified, not two.** `tools/ja4.py` reproduces
   `ja4_a` (`t13i1516h2`) and `ja4_b` (`8daaf6152771`) from the b-ids corpus
   ClientHello, and `ja4_c` against `tls.peet.ws`'s own computation on the live
   capture. An earlier revision labelled `ja4_c` `UNVERIFIED`; that was wrong, and
   the reason is in section 8.9.
6. **The JS object keys `chromeHeaders()` and `edgeHeaders()` do not exist.** They
   are prose in a comment describing a decision, not names in the code. Section 6.4
   and the comment now describe the branches by the header they select on.
7. **No vendor classification was tested against.** Section 3 cites Cloudflare's
   own documentation for what such a check inspects. No attempt was made against
   any live challenge, and the evidence says it would not work.
8. **Jina and browser-use pricing was not verified first-hand**; the parallel
   research supplied those numbers, while Cloudflare's were verified directly,
   since Cloudflare's figures are the ones the cost model depends on.
9. **The upstream timeout's behaviour is now measured, but only against the local
   runtime.** Section 8.6 was corrected: the old claim that the harness "cannot
   simulate a peer slower than ~1 s" was false, and with the probes fixed the
   abort is shown to track its budget exactly (250 ms budget aborts at 252 ms
   against a 30 s peer). What is still untested is whether the **real Cloudflare
   edge** honours a deadline the same way, and the Free plan's 10 ms CPU cap
   against a genuinely slow origin.
10. **Section E exercises a stub, not a TLS stack.** It proves routing, gating and
   header coherence around `TLS_TRANSPORT`. It proves nothing about TLS itself.

## Review method

Ten independent reviews were run over this document and the code, each with a
different lens: worker correctness, security review, test-suite quality,
harness fidelity, factual audit, pricing recomputation, overclaim audit,
regression hunt against v1, deployability, and public-repo readiness. A further
ten ran after the peer-repo merge and the persona rewrite, described in section
[8.9](#89-the-correction-that-changed-the-architecture) and at the end of this
section.

They found four genuine blockers, all now fixed and all confirmed by execution
rather than by reading:

1. **Every browser caller was broken.** The `OPTIONS` branch returned without
   `Access-Control-Allow-Origin`, so preflight always failed. The suite's
   preflight assertion checked only the status code and methods, so it passed.
   That is v1's original defect reintroduced under a different shape.
2. **The proxy leaked its own credential.** `wrangler secret put AUTH_TOKEN` was a
   no-op (the Worker read a module constant, never `env`), and `authorization` was
   not in any strip list, so the token would have gone to every third-party origin.
3. **The SSRF guard did not cover every form.** WHATWG URL serialises IPv6 hosts bracketed
   and in hex, so `[::1]` and `[::ffff:a9fe:a9fe]` never matched the blocklist, and
   `localhost.` did not match the suffix check. Fifteen forms are now covered.
4. **The redirect loop leaked the allowlist.** Policy was applied to hop 0 only, so
   one `302` from an allowlisted host reached anywhere; 307/308 also silently lost
   the method and body.

Three further findings were about the **evidence** rather than the code, and those
matter more, because a green suite is what makes someone trust a document:

- One mutation was scoring "caught" because the mutant was a **syntax error**,
  not because any assertion fired.
- A whole section of the suite (`probe_auth`, 16 assertions) read a **hardcoded
  path** instead of the worker under test, so it validated the original while the
  rest validated the mutant. Combined with all sections sharing one temp filename,
  a real allowlist gap passed a green suite.
- Section 8.6's central claim was **measured with a buggy client** and has been
  corrected in place rather than quietly deleted.

Where a reviewer asserted something that could be checked, it was checked; a few
did not hold up. The upstream sha256 and 101-line count are confirmed correct against the
downloaded original. The `byte-for-byte` claim on `v1-baseline.js`, which this
document also got wrong and then reported as a closed reviewer finding, was false
in a way that needed fixing in the file's own header; that is done.

### The second round, after the merge

The merge from `nemo-010/b-cf` was reviewed the same way. The reviews were worth
running because they found things that were wrong rather than confirming things
that were already believed.

Findings that were fixed:

1. **The `chrome` persona was unreachable by every test.** It existed in the code
   and nothing executed it, which is how a mutation over that branch survived.
   Section E exists because of this.
2. **`Upgrade-Insecure-Requests` was emitted over plaintext `http://`**, beside a
   User-Agent claiming Chrome, gated by a rule two lines above that said secure
   contexts only. Fixed, and pinned by a mutation.
3. **A stale assertion contradicted the new default.** The suite still asserted
   `still rewrites the UA on a plaintext target` expecting `Chrome` in the value,
   which is the opposite of what the persona model now does. One line, deleted, and
   the replacement assertion already covered the behaviour.

A third round of ten ran over the merged result. It found **eight real defects**,
all now fixed. Each one was a claim the suite appeared to cover:

| # | defect | why the suite looked like it covered it |
|---|---|---|
| 1 | The caller's `Origin` and `sec-fetch-*` were forwarded verbatim | Nothing asserted on them; v1's leak class was `Referer` and cookies, and `Origin` was simply missed |
| 2 | Low-entropy Client Hints survived the honest persona | The one assertion sent a caller that had none, so the strip list looked complete |
| 3 | `X-Proxy-Timeout-Ms` did nothing on `engine=tls` | The transport's init was asserted to be `["headers"]`, which pinned the *absence* of the signal |
| 4 | An upstream `Access-Control-Allow-Credentials: true` passed through | The fixture never emitted one, and the assertion checked that *we* did not set it |
| 5 | `access-control-allow-headers` omitted three control headers | The preflight assertions checked status, ACAO and `Vary`, never `allow-headers` |
| 6 | RFC 6598 CGNAT and NAT64 were not blocked | The 15 covered forms were all loopback/link-local/metadata |
| 7 | A NUL byte defeated the scheme allowlist | No test used a control character |
| 8 | `ALLOWED_HOSTS` comma-splitting was unpinned | Every test injected a single clean host, so `split(",")` was never needed |

Plus a **deploy blocker** that no test could catch, because no test reads
`wrangler.toml`: it set `workers_dev = false` and declared no routes, so
`wrangler deploy` would have **succeeded and published nothing**. Now fixed, with
the reason recorded in the file so it is not undone.

Two harness bugs were found alongside them, and both had been hiding a real gap:

- **The control gate only counted one section's controls.** A failing control
  elsewhere still printed `VALID`. All five are now counted wherever they live.
- **The Set-Cookie assertion accepted the corruption.** Its first clause was the
  comma-joined string, and the client used `setdefault()`, so a second cookie was
  invisible regardless. It now counts lines in the raw response head.

And one of the tools in this tree was wrong in the opposite direction, which is the
failure mode that matters most here: `tools/ja4.py` labelled `ja4_c` `UNVERIFIED`
when it was in fact verified and the *peer* tool was using a different rule.
Labelling unverified work as unverified was right; concluding from a
non-reproduction that the cause was unknown, when the cause was a documented rule
difference that had not been checked, was not. See section 8.9.

Findings refuted by a second pass, reported because a refuted finding is still
information:

- One review claimed the default persona was a regression in detection terms. It is
  not, on the evidence: the incumbent's own measured handshake is TLS 1.3 with 13
  ciphers and 12 extensions while it claims Safari 18.5, and matching the header
  to the transport is the defensible position. What would be a regression is
  claiming Chrome over `fetch()`, which is exactly what `chrome` without
  `engine=tls` now refuses to do.
- One review claimed the 501 for a missing `TLS_TRANSPORT` was a breaking change
  for existing callers. It is not reachable by them: `X-Proxy-Engine` is a new
  header, and no v1 caller sends it.

### The third round, after the neutral-register rewrite

Eight further lenses, run over the same tree. The code defects they found are
listed in section 6.2 and fixed with assertions; what is worth recording here is
the pricing lens, because it found a defect in this document rather than in the
worker.

Every pricing and limit claim was recomputed against Cloudflare's own
documentation, fetched 2026-10-14. Of 51 claims checked, 41 matched exactly,
including every headline figure: $0.30/M requests, $0.02/M CPU-ms, $0.60/M log
events, the $5.00 minimum, Cloudflare's own worked examples at $8.00 and $45.40,
100,000 requests/day, Error 1027, 10 ms Free CPU, $0.09/browser-hour, 64 MiB, the
20-minute runtime-update grace period, 6 MiB Markdown-for-Agents, and the 300-second
Turnstile lifetime. The remaining findings, all now corrected in place:

- **A dated pricing change was missing.** Workers Logs moves to Cloudflare
  Observability pricing on 2026-12-01, and the $93.40 figure in 7.1 is a model
  that stops applying on that date. The notice is quoted in 7.1 now.
- **An unverifiable default was asserted as fact.** Section 7.2 claimed "the
  default route mode is fail open". Cloudflare's limits page shows both modes in a
  table with no default marked, and nothing else in their documentation states it
  either. The claim is removed rather than softened, and the operator is told where
  to check. Section 9 depended on it.
- **A quotation was attributed to two sources and exists on one.** The Free-plan
  daily limit is on both the limits and pricing pages; "resetting at midnight UTC"
  is on the limits page only.
- **Three numbers had drifted by days.** The changelog feed holds 1,344 items
  against the 1,341 recorded, and the tag counts moved with it. The counting method
  was also unstated and mattered: "first category" gives Workers 174, "appears in
  any category" gives 260. The method is now written down.
- **An omission with teeth.** Subrequests are priced at nothing, correctly, but the
  runtime also caps them at 50 per invocation on Free and 10,000 on Paid, counting
  each redirect hop. Section 7.1 now states the ceiling and the measured headroom.
- **One claim was outside its own sources.** The reCAPTCHA two-minute lifetime comes
  from Google, not Cloudflare, so it cannot be verified from the sources this
  document cites. Marked as such.

The generalisable lesson, and the reason it is written down rather than just
fixed: the 4.4 sweep looked for price *increases* in the changelog and found none.
The Workers Logs change is a pricing change, and it reached the docs through the
pricing page and a blog post rather than a Workers-tagged changelog entry. A
pricing claim sourced only from the changelog is not a survey of pricing.

### The fourth round, and a harness defect that outranked the findings

Eight lenses ran over the tree again: security, test-suite quality, harness
fidelity, documentation accuracy, pricing, neutral register, deploy and packaging,
and consistency. The security and test-quality lenses each found real defects.
Everything below was reproduced with a standalone probe against the real runtime
before it was fixed, and pinned after.

**Six defects in the worker**, each now a mutation that must be caught:

1. **An upstream could set the proxy's origin-scoped security headers.**
   `Clear-Site-Data`, `Content-Security-Policy`, `Strict-Transport-Security`,
   `X-Frame-Options`, `Permissions-Policy`, `COOP`, `COEP` and `Report-To` were
   copied verbatim onto a response served from the proxy's own host. RFC 9535 s4
   scopes `Clear-Site-Data` to the origin it arrived on, so an arbitrary upstream
   could arm it against the proxy's origin and have the user agent clear storage
   there. The shipped default is an open proxy, so this needed no credential.
2. **A non-http(s) `Location` reached the client verbatim.** `rewriteLocation`
   exists so the client never leaves the proxy, and the one branch where it
   returned the input unchanged was the scheme check: `ftp://`, `javascript:` and
   `data:` all arrived intact from a third party.
3. **Cookie consent covered the host but not the scheme.** A caller who named
   `https://origin.test` and consented to the cookie had it emitted in cleartext
   after the origin answered `302 Location: http://origin.test/other`.
4. **Every other caller header rode a cross-host redirect.** `Authorization` and
   `Cookie` were stopped; `X-Forwarded-Authorization`, `X-Api-Key`, `X-Auth-Token`,
   `X-Tenant-Id` and 33 further unnamed headers were not. The proxy follows the
   redirect itself, so the caller consented to the host they wrote.
5. **A header named by `Connection` was forwarded.** RFC 9110 s7.6.1 requires a
   proxy to remove the fields a `Connection` header names. `HOP_BY_HOP` is a static
   set, so `Connection: X-Secret` forwarded `X-Secret`.
6. **A non-string `ALLOWED_HOSTS` silently disabled the allowlist.** The fallback
   was the module constant, which is `[]`, meaning the open-proxy default. An
   array, a number and a boolean each turned a restricted proxy into an
   unrestricted one with no error anywhere. It now returns 500.

Plus one narrowing of a target-parsing rule: the bare-host fallback ran on
anything the URL parser rejected, which is a much larger set than "no scheme", so
`"https://[fe80::1%25eth0]/"` fetched `https://https//[fe80::1%eth0]/`. The
address guard and the allowlist still applied to the substituted host, so this was
an unreviewed substitution rather than a guard bypass. It now requires a shape
match and a round-trip check.

**A harness defect that mattered more than any of them.** The v1 baseline section
printed its rows and was never folded into the exit status, so a v1 assertion could
fail while the run reported `VALID` and `OVERALL: PASS` with exit 0. Reproduced
before the fix: changing v1's hardcoded User-Agent from `Safari/605.1.15` to
`Chrome/999.0.0.0` in a copy of the tree produced

```
FAIL  v1: rewrites a curl UA to a fixed Safari 18.5 string
VALID: all 14 control assertions fired.
OVERALL: PASS
```

with exit status 0. A red row inside a green report is worse than a missing row,
because it reads as a known-and-accepted failure. Nine assertions were ungated.

Three more harness defects, each a row that could not fail for the reason it
claimed:

- **`content-length` was a tautology.** The row sent a header with no body, and
  the client discards a caller-supplied `Content-Length` when there is no payload,
  so the header never reached the worker and its absence proved nothing. The
  invariant that actually holds is that the upstream's length is DERIVED from the
  body, and that is what the row now asserts.
- **The CORS allow-header rows were substring matches.** `"accept"` is a substring
  of `"x-proxy-accept-language"`, so deleting `Accept` from the advertised list
  left the suite green, and so did deleting `Accept-Language`. Matched against the
  split list now.
- **The source-scanning CORS row could not see most reads.** It matched
  `request.headers.get` and `incoming.headers.get`, but `incoming` *is* a Headers
  object, so `incoming.get` and `incoming.has` were invisible to it. It reported a
  complete list while checking four of six.

**And one where the assertion was the thing that was wrong.** `noBody` statuses
could not be measured because the TAP fixture called `new Response(body, {status:
204})`, which throws. Every assertion about a 204 was reading the constructor's
error. The fixture builds null-body statuses correctly now. In the same spirit, a
target carrying a RAW space turned out not to be a proxy defect at all: workerd
truncates the request-target at the space before the worker runs, so the proxy
never sees the malformed target. The percent-encoded form is refused with 400.

**A mutation-check defect worth recording.** `prepare()` applied `flags=re.M` to
every pattern, so a mutation written to span lines with `.*?` silently matched a
shorter run, removed less than intended, and reported as a survivor. The same
substitution applied by hand failed four assertions. Patterns may now carry their
own flags.

The generalisable lesson: two of the eight lenses found defects in the **harness**
rather than in the worker, and the harness defect was the one that would have let
a future regression pass unnoticed. A green suite is a claim about the suite, not
about the code, and that claim needs its own check.

## Files read, and what came of them

| Path | Used for |
|---|---|
| `pkgforge-dev/reverse-proxies/.../worker.js` | v1 baseline, sections 1-2 |
| `cloudflare/workers/platform/pricing` | 7.1, 7.2 |
| `cloudflare/browser-run/pricing`, `/limits` | 5, 7.4 |
| `cloudflare/bots/concepts/bot-score`, `/bot-management-variables` | 3.2 |
| `cloudflare/turnstile/get-started/server-side-validation`, `/troubleshooting/testing` | 3.1 |
| `cloudflare/workers/runtime-apis/web-standards` | 3.2 |
| `cloudflare/workers/runtime-apis/tcp-sockets` | 3.3 |
| `cloudflare/workers/platform/limits` | 3.2, 8 |
| `cloudflare/workers/changelog/rss/index.xml` | 4.4 |
| `jina-ai/reader` (`src/services/curl.ts`, `crawler-options.ts`) | 4.1 |
| `browser-use/browser-use` (`pyproject.toml` history, `profile.py`) | 4.2 |
| `Azathothas/b-ids` (`lib.rs`, `configs.rs`, `README.md`, corpus ClientHello) | 4.3, 3.3, `tools/ja4.py` |
| `cloudflare/workerd` releases + `workerd.capnp` (`Network` struct) | 3.3, 8.3 |
| `nemo-010/b-cf` (MIT) | 3.3, 8.9. Findings and design taken; nothing copied, every number recomputed here |
| `latentharbor/tunnelfetch`, `EithonX/socksflare` (cited by the peer) | 3.3, existing implementations that fit the `TLS_TRANSPORT` contract |

## Attribution and licensing

This tree is **0BSD** (`LICENSE`). The peer research tree it merged findings from,
`nemo-010/b-cf`, is **MIT**. Nothing was copied between them: the architectural
findings and the `TLS_TRANSPORT` seam design were taken as ideas and then
re-derived, and every measurement quoted in section 3.3 was reproduced under
`workerd` here, from this repo's own probe. `tools/ja4.py` was written from the
JA4 specification rather than adapted, which is why it independently arrives at
the same `ja4_a` and `ja4_b` for the same input bytes.

That "nothing was copied" claim is an assessment, not a measurement, so the
remedy is written down while it is still true to state. If it is ever found to be
wrong, the obligation that attaches is MIT's notice clause, and the fix is
mechanical: quote the copyright and permission notice from the upstream `LICENSE`
into the affected files. The upstream is `github.com/nemo-010/b-cf`. Writing the
remedy now means a later correction does not first have to rediscover that the two
trees were ever related.
