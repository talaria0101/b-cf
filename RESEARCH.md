# api.rv v2 — research, design, and reproducible proofs

A new-generation `api.rv.pkgforge.dev` for Cloudflare Workers, plus the evidence
behind every claim here, the pricing comparison, and a harness that runs the real
Workers runtime.

Everything below was checked on **2026-10-13**. Anything I could not verify is in
[Limits](#limits-what-this-document-does-not-establish) and is marked there
rather than smoothed over.

---

## TL;DR

1. **The premise needs one correction, stated plainly.** A Cloudflare Worker
   cannot "pass as 100% real browser for captchas". The captcha token is minted by
   JavaScript inside a real browser, and Cloudflare's own docs say automation
   frameworks are detected as bots. No header work changes that. Section
   [3](#3-the-captcha-question-the-unwelcome-answer).
2. **v1's two headline features are dead code**, confirmed against the live
   deployed worker, not just by reading it. `cf-connecting-ip` randomisation never
   runs, and 4 of the 8 `cf-*` headers it tries to strip are re-injected by
   Cloudflare anyway. Section [2](#2-what-v1-actually-does-measured-not-read).
3. **Serverless "real browser" does exist**, and it is not a Worker `fetch()`: it
   is **Browser Run** (formerly Browser Rendering), a binding at
   **$0.09/browser-hour** after 10 free hours/month. That is the only route to
   running JS, and it is still not a captcha solver. Section [5](#5-browser-run).
4. **Self-built cost**: **$0** up to ~3M requests/month on the Free plan
   (100,000/day), **$5.00/month** on Paid, and **$45.40** at 100M requests/month.
   Adding Browser Run is **+$0.09 per browser-hour**, which is the number that
   decides everything. Section [7](#7-pricing).
5. **The proofs are executable**: 115 assertions against v2 under Cloudflare's own
   `workerd`, a negative control on the unmodified v1, and a mutation check that
   breaks 23 invariants and requires the suite to catch every one. All green.

---

## 1. What v1 is

The upstream file is 101 lines, 3423 bytes,
`sha256 3e06a02a0c466b704a1d550167c346102ba2734587e85a68efd1d3d15ef0f6fa` (verified
by download on 2026-10-13). `rig/v1-baseline.js` in this repo adds a 2-line
provenance header and is otherwise identical; it is 103 lines, so **its** hash
differs from the value above. Where a line number is given for v1 below, it
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
{ "Cf-Connecting-Ip": "ABSENT",                       <- not spoofed
  "Cf-Ray":            "a49f1fc9abaccf60-KTM",        <- Cloudflare's own, not mine
  "X-Forwarded-For":   null }
```

Note `Cf-Ray`: I sent `testray`, and the origin saw a **Cloudflare-issued** value.
That is the re-injection, observed. The author's list of 8 `cf-*` headers cannot
work, because Cloudflare adds several of them at the edge after the Worker runs.

### 2.2 The source IP cannot be changed, at all

The live origin reported `origin: 2a06:98c0:3600::103, 172.69.76.176`.
`172.69.76.176` is inside `172.64.0.0/13`, which is in Cloudflare's published
IPv4 list (`https://www.cloudflare.com/ips-v4/`). A Worker's egress is
Cloudflare-owned. No header value can change what the origin sees here.

### 2.3 Other measured defects

| Defect | Evidence |
|---|---|
| Query string silently dropped | `.../https://httpbin.org/anything?a=1&b=2` -> origin saw `https://httpbin.org/anything`. `pathname` is used and `search` is never re-appended. |
| No CORS at all | Live response to `Origin: https://app.example` contains **0** `access-control-*` headers. Every browser caller is blocked by Same-Origin Policy. |
| Client cookies leaked to third parties | `Cookie: session=secret123` reached the origin verbatim. |
| Caller's `Referer` leaked verbatim | `Referer: https://secret-app.example/dashboard` reached the origin, naming an unrelated private app. |
| One hardcoded UA, never varying | Every request returns the identical Safari 18.5 string. Byte-identical across repeated runs. |
| No client hints | A rewritten Safari UA is sent with no `sec-ch-ua` at all, which is itself inconsistent. |

The cookie and Referer findings are the ones I would flag hardest. v1 is an open,
unauthenticated proxy that forwards a caller's session cookies and private
`Referer` to **any destination on the internet**. That is a credential-disclosure
primitive, and it is a finding independent of everything else in this document.

---

## 3. The captcha question: the unwelcome answer

The request was for something that "can pass as 100% real browser for captchas etc".
I cannot deliver that, and no Cloudflare Worker can. Here is the evidence, from
Cloudflare's own documentation.

### 3.1 The token is a browser artefact

Cloudflare Turnstile, [server-side validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/),
verbatim:

> - **Tokens can be forged.** An attacker can submit any string to your form endpoint without completing a challenge.
> - **Tokens expire.** Each token is valid for 300 seconds (5 minutes) after generation.
> - **Tokens are single-use.** Each token can only be validated once.

`POST https://challenges.cloudflare.com/turnstile/v0/siteverify` is a **verifier**,
not a solver. It checks a token that a widget running inside a real browser
produced. There is no documented server-side solve path, and I found none across
Cloudflare's Turnstile docs.

And on automation, from Cloudflare's [testing and troubleshooting](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)
page, verbatim:

> Automated testing suites (like Selenium, Cypress, or Playwright) are detected as bots by Turnstile.

That is decisive, because it means the failure mode is not "headless is slightly
detectable" but "the recognised automation stacks are classified as bots".

reCAPTCHA is the same shape: the token is valid **two minutes** and single-use,
acquired from Google's client-side JS in a browser.

### 3.2 What a Worker `fetch()` cannot reproduce

These are the signals that actually decide the outcome, and none of them are
header values:

| Signal | Why header work cannot fix it |
|---|---|
| **JA3 / JA4** (TLS ClientHello fingerprint) | Derived from the TLS stack. Cloudflare exposes `request.cf.botManagement.ja3Hash` and `.ja4` **to the site being protected**. `workerd` offers no per-request TLS API. |
| **JavaScript detections** | The site injects a script and reads what the browser computes. Exposed as `request.cf.botManagement.jsDetection.passed`. No JS engine in a Worker to run it. |
| **HTTP/2 SETTINGS and frame ordering** | Fixed by the runtime's TLS/H2 implementation. |
| **IP reputation** | Datacenter, Cloudflare-owned egress. |
| **Empty/absent `User-Agent`** | Per Cloudflare's [bot score](https://developers.cloudflare.com/bots/concepts/bot-score/) docs: "Requests with a missing or empty `User-Agent` header are immediately assigned a bot score of **1** by the Heuristics engine." |

Two more runtime facts that make a Worker trivially identifiable to a hostile
check, from the [Web standards](https://developers.cloudflare.com/workers/runtime-apis/web-standards/)
documentation:

- With `global_navigator`, `navigator.userAgent === 'Cloudflare-Workers'`.
- `Date.now()` "returns the time of the last I/O; it does not advance during code
  execution", and `performance.now()` always equals `Date.now()`.

A timing-attack-resistant environment is the opposite of what a bot-detection
heuristic wants, because it makes timing behaviour look synthetic.

**What this means practically.** The honest framing is two different goals:

- **Passing naive UA/language/referrer heuristics** on ordinary sites: achievable,
  and v2 does it. Section [6](#6-v2).
- **Passing Turnstile / reCAPTCHA / Cloudflare JS challenges**: not achievable
  serverless, at any price, because the challenge requires a real browser plus a
  residential IP and a solved token. Anyone selling you "serverless captcha
  solving" is selling a proxy to someone else's browser farm.

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

Self-hosting it needs GCP Cloud Run, MongoDB Atlas and GCS, per its README, across
two clusters. It is not a serverless artefact.

### 4.2 browser-use

117,831 stars, MIT, Python, latest release **0.13.11** (2026-10-07).

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

Two things worth correcting from the brief's framing: **there is no YAML config**
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

It is relevant to this project for exactly one reason: it documents its own
boundaries honestly, and those boundaries are the ones that matter here.

- It **does not complete a TLS handshake**. `crates/b-ids-cli/src/lib.rs:17`:
  "It completes no handshake, and that is the honest boundary."
- **No** proxy support, by design. `lib.rs:3`: "There is no cookie jar, no
  redirect policy, no retry logic, no proxy support and no output formatting, and
  there must never be."
- JA3/JA4/Akamai are **null in 22 of 22** profiles. `configs.rs:23`:
  "No digest artefact is generated here, and the absence is deliberate."
- It explicitly disclaims the scraping use case, including "bypass bot challenges
  or CAPTCHAs".

So b-ids is the best available answer to "what would a browser actually send",
and it is explicitly not a way to send it as one.

### 4.4 Cloudflare changelog

`https://developers.cloudflare.com/changelog/rss/index.xml`, 8,279,463 bytes,
**1,341 items**, spanning 2024-02-26 to 2026-10-13. Product tag counts include
Workers 172, WAF 125, Agents 45, **Browser Run 28**, Workers AI 32, AI Gateway 25.
Notably **`Browser Rendering` as a product tag: 0 occurrences** — the rename is
complete.

Limits that increased, and that matter for a design:

- **Worker bundle**: 3 MB Free / 10 MB Paid -> **64 MiB uncompressed, all plans**
  (4 Sep 2026).
- **Runtime-update grace period**: 30 s -> **20 minutes** (12 Oct 2026).
- **Do Pending I/O**: up to 15 minutes per pending operation (1 Oct 2026).
- **Markdown-for-Agents conversion**: 2 MiB -> 6 MiB (9 Oct 2026).
- **KV namespace jurisdictions GA**, **Queues multi-jurisdiction** (Oct 2026).

No entry in the 150 most recent announces a price **increase** for Workers or
Browser Run.

---

## 5. Browser Run

The product was renamed: `developers.cloudflare.com/browser-rendering/` **302** to
`/browser-run/`. The REST namespace is still `browser-rendering` in the OpenAPI
spec, while the docs prose and samples use `browser-run`; both resolve, and I
confirmed both return the same auth error rather than a 404.

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

**No stealth.** Cloudflare's own limits and pricing pages state no residential
proxy, no stealth, and no CAPTCHA solving. That is not a criticism of the product;
it is the accurate scope.

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
| Bot-tool UA replaced, coherently | 7 tool UAs; UA version matches `sec-ch-ua`; OS matches `sec-ch-ua-platform` |
| Only low-entropy hints sent | `sec-ch-ua-arch`/`-bitness` withheld, as Chrome does without `Accept-CH` |
| No hints over plaintext | `sends no sec-ch-ua to a plaintext http target` |
| Caller hints dropped | a supplied `sec-ch-ua-model` cannot contradict the rewritten UA |
| Genuine browser UA untouched | verbatim, **no** hints added |
| Cookies not leaked by default | opt-in via `X-Proxy-Forward-Cookies: 1` |
| `Referer` rewritten to target origin | no longer names the caller's private app |
| CORS complete | reflects `Origin`; preflight carries **ACAO**; appends to upstream `Vary`; no `allow-credentials` |
| Response framing preserved | `content-encoding` kept; repeated `Set-Cookie` not comma-joined |
| Redirects followed manually | headers rebuilt per hop; 303 downgrades to GET; **307/308 replay method and body** |
| Policy re-applied per hop | allowlist + SSRF guard run on every hop, so a redirect cannot escape |
| Redirect cap pinned | 3-hop chain completes, 12-hop chain refused with 508, relative `Location` resolves |
| Per-request timeout | `X-Proxy-Timeout-Ms`, clamped to [250, 60000], resolved value observable at `/__config` |
| Auth + allowlist | 16 assertions: 401/403 paths, case-insensitive scheme, subdomain vs lookalike |

### 6.2 Behaviour changes that will break an existing v1 caller

Stated plainly, because a proxy upgrade that silently changes results is worse
than one that fails loudly.

| Change | Effect on a v1 caller |
|---|---|
| Cookies no longer forwarded | Sessions that relied on the proxy passing `Cookie` **stop working**. Opt back in per request with `X-Proxy-Forward-Cookies: 1`. |
| `Authorization` no longer forwarded | Callers using the proxy to reach an authenticated API must pass their token some other way. This is the point of the change: it is how the proxy's own credential stopped leaking. |
| `?url=` no longer read from a non-empty path | `/api.example.com/x?url=y` previously proxied to `/api.example.com/x`; it now does the same thing (path wins). |
| Network errors are JSON `502` | v1 returned plain-text `500`. Clients matching on 500 will not match. |
| `Accept` always sent | v1 sent none when the caller sent none, so a raw API client now receives the browser default unless it sets `Accept` explicitly. |
| Timeout is per hop | Worst case `(MAX_REDIRECTS+1) x MAX_TIMEOUT_MS`. |
| `cf-*` response headers dropped | v1 passed them through. Harmless; they are edge artefacts. |

### 6.3 What it deliberately does not do

These are the honest limits, and they are in the file as comments:

- **It does not spoof the source IP.** Impossible on Workers.
- **It does not set `cf-connecting-ip`.** v1 tried; it is dead code, and Cloudflare
  would strip it anyway.
- **It does not claim to defeat Turnstile or reCAPTCHA.** Section 3.
- **It does not strip Cloudflare's re-injected headers**, because stripping them
  from the outbound `Request` does not stop the edge adding them.
- **It does not claim header consistency equals a real browser.** It fixes
  internal inconsistency, which is a subset of what a vendor checks.

---

## 7. Pricing

All Workers figures verified verbatim from
[developers.cloudflare.com/workers/platform/pricing](https://developers.cloudflare.com/workers/platform/pricing/)
(last updated 2 Oct 2026). Browser Run from section 5.

### 7.1 The two meters that matter

| Unit | Included (Paid) | Overage |
|---|---|---|
| Requests | 10 million/month | **$0.30** per million |
| CPU time | 30 million CPU-ms/month | **$0.02** per million CPU-ms |
| Subscription | — | **$5.00/month minimum** |
| Egress / bandwidth | — | **not charged** |
| Subrequests | — | **not billed** |

That last row matters more than it looks: **the outbound fetch to the origin is
free**. For a proxy, the entire cost is inbound requests plus CPU. And CPU is
mostly waiting on I/O, which the docs explicitly exclude: "Waiting on network
requests (such as `fetch()` calls...) does not count toward CPU time."

That sentence, and the figure below it, are from the **limits** page, not the
pricing page: "The average Worker uses approximately 2.2 ms per request." The same
page places authentication, server-side rendering and large-payload parsing in a
**10-20 ms** band, which brackets the 7 ms figure used in 7.2 from above as well
as 2.2 ms from below. 7 ms is the conservative choice.

### 7.2 Cost model: self-built Workers proxy

Using 7 ms CPU/request, which is the figure in Cloudflare's own worked examples
(their Examples 1 and 4):

Two plans, because the binding constraint differs:

**Free plan — 100,000 requests per DAY**, resetting at midnight UTC
(verified verbatim on both `/workers/platform/limits/` and `/workers/platform/pricing/`).

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
- **Exceeding the daily cap returns Error 1027, and the default route mode is
  "fail open"**: "Bypasses the Worker. Requests behave as if no Worker is
  configured." For this proxy that means auth and header rewriting are skipped
  entirely for the overflow traffic. Set the route to **fail closed** before using
  the Free plan, or a traffic spike silently disables the control you added.

### 7.3 Feature parity and cost versus each comparator

| Capability | Jina Reader | browser-use | **api.rv v2** | Browser Run (CF) |
|---|---|---|---|---|
| Plain proxy / forward fetch | yes | no | **yes** | no (browser only) |
| Runs JS | yes (Chrome) | yes | **no** | yes |
| TLS fingerprint control | yes (impersonate) | via local Chrome | **no, impossible** | no |
| Real captcha solving | no | agent-driven, needs a real browser | **no** | no |
| Serverless | Cloud Run + Mongo | no | **yes, native** | yes |
| Self-host cost @1M req/mo | VM + DB + cache | VM | **$5** | $5 + $0.09/browser-hr |

**Where parity is genuinely achievable at near zero cost**: the proxy role. v2
matches Jina's *fetch-and-normalise* behaviour minus JS execution, and beats both
competitors on cost by 2-4 orders of magnitude.

**Where parity is impossible, at any cost**: TLS fingerprinting and captcha
solving. That is a capability of the network and of a browser, not of code.

### 7.4 What adds real money

If you need JS execution, the marginal cost is Browser Run and nothing else.
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

**I could not measure real per-page browser milliseconds.** It requires a
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
rig/v1-baseline.js    v1 with a 2-line provenance header, as the negative control
wrangler.toml         deploy config
harness/rig.py        runs a worker under real workerd, with an in-process TAP origin
harness/test_proxy.py 115 assertions (92 v2 + 16 auth/allowlist + 7 observation)
                      and 3 negative controls
harness/mutation_check.py  23 mutations, each required to be caught
harness/probe_*.py    the four probes behind the timeout findings
bin/wd                workerd 2026-10-13 (Cloudflare's actual runtime)
```

### 8.2 Run

```bash
python3 harness/test_proxy.py          # <1s
python3 harness/mutation_check.py      # ~4s, 6 in parallel
```

Both exit non-zero on failure. `test_proxy.py` accepts a worker path as `argv[1]`,
which is how the mutation check runs variants without writing to `rig/v2.js`.

### 8.3 Why the harness looks unusual

This sandbox **refuses every TCP `bind()`/`listen()`** (`EACCES`, all ports, both
127.0.0.1 and 0.0.0.0), and **direct TCP `connect()` to the internet times out**
(only an HTTP CONNECT proxy at `169.254.169.1:36179` is reachable). Verified, not
assumed. AF_UNIX sockets do work.

So the harness uses the two workerd features that make this possible anyway:

1. `sockets = [ (name = "http", address = "unix:/tmp/...") ]` — workerd supports
   `unix:` socket addresses, so inbound requests arrive over AF_UNIX.
2. `globalOutbound = "tap"` on the Worker — the outbound `fetch()` is routed to an
   **in-process TAP worker** instead of the network.

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
NEG-CONTROL v1: cf-connecting-ip is NOT spoofed (dead code)
NEG-CONTROL v1: drops the target query string
NEG-CONTROL v1: emits no CORS headers
```

If those do not fire, the run reports **INVALID** and the v2 results are
discarded. A suite that cannot fail proves nothing.

### 8.5 Mutation check

A negative control proves the harness catches defects that already exist. It does
**not** prove it would catch a regression introduced into v2. So 23 single-line
mutations are applied to a copy of v2, and the suite must fail for each:

```
23/23 mutations caught
OK: every mutation was detected, so the v2 assertions have teeth.
```

Five mutations were **survivors at some point**, and every one of them found a real
defect rather than a weak assertion:

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
   Fixed by anchoring the substitution to the call site.
4. **`allowlist label boundary` exposed two harness bugs.** It mutated
   `endsWith("." + want)` to `endsWith(want)`, which really does admit
   `evil-origin.test` — verified against the runtime. The suite still passed,
   for two reasons: `probe_auth` read a **hardcoded** `rig/v2.js` instead of the
   worker under test, so its 16 assertions ran against the *original* while the
   other 99 ran against the mutant; and every section wrote its patched worker to
   one **shared** filename, so parallel runs overwrote each other. Both are fixed.
   This is the clearest argument for the mutation check: a green suite and a real
   hole coexisted, and only removing the invariant exposed it.

A surviving mutation is not a nuisance. It is the assertion telling you it was not
pinning what it claimed.

### 8.6 Two clocks in this harness, and I measured the wrong one first

**Correction to an earlier draft of this document.** That version reported every
deadline collapsing to "a flat 5.0 s / 6.0 s" and concluded wall-clock deadlines
are unobservable here. That was wrong, and the fault was in the **harness**, not
the runtime: `unix_request` read to EOF, so every measurement included the time the
client waited for a keep-alive connection to close. Honouring `Content-Length`
(section 8.7 item 2) changed the numbers completely.

Re-measured after that fix:

| Measurement | Result |
|---|---|
| Worker's own `AbortController`, budget 250 ms, slow peer | fires at **251, 252, 291 ms** over 3 runs |
| Own budget 1000 ms, peer that stalls | **aborted** |
| Own budget 3000 ms, same peer | **completed** |
| Never-answering peer, no `AbortController` | workerd's hung-code detector, `worker_ms` 1-12 ms |
| The TAP's own `setTimeout(20_000)` | returns at **1.0 s** |

So there are two clocks and only one of them is broken:

1. **The Worker's timers are accurate.** A 250 ms budget fires at 250 ms. Elapsed
   time is a usable signal inside the code under test.
2. **The TAP's timers are clamped to ~1 s.** `/__ctl/slow?s=20` answers in 1.0 s,
   not 20 s. That is the harness's simulated origin, not v2, so it does not change
   what v2 does — but the harness **cannot simulate a peer slower than ~1 s**.

Consequences, because they bound what the suite proves:

- The suite pins the timeout's **resolution and clamping** at `/__config`, and pins
  the **abort path** by discriminator rather than by elapsed time. Both remain
  valid, and the `CONTROL` assertion is what stops "our timeout fired" from
  being satisfied by workerd's cancel wearing the same status code.
- A production wall-clock deadline is still untested (Limits item 7).

The discriminator is stable, which is the property the suite relies on:

```
own timer vs SLOW peer     3/3 own-abort
own timer vs HANGING peer  3/3 runtime-hung-detector
```

### 8.7 Defects I introduced, and the structural fixes

Three, each fixed by removing the possibility rather than by retrying.

**1. The mutation checker could corrupt the tree.** The first version mutated
`rig/v2.js` **in place** and restored it in a `finally`. A `timeout` killed that
run with `SIGKILL`, which bypasses `finally`, and left **`v2.js` mutated on disk**
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

The 23 mutations are all *behavioural* line edits. They cannot catch:

- A wrong claim in this document. Nothing here checks prose.
- A defect that only manifests on the real edge (section 9).
- A test that asserts the right property of the wrong thing, where no mutation in
  the list happens to touch it.
- Concurrency. Every test here is single-request and sequential.

The suite proves v2's logic behaves as specified under `workerd`. It does not
prove v2 is deployed correctly, and it cannot.

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

**Set the route's failure mode to closed.** Cloudflare's default is "fail open",
which bypasses the Worker entirely when the Free plan's daily cap is exceeded,
skipping auth and header rewriting for the overflow.

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
4. **Egress is blocked in this sandbox**, so "does the edge's TLS stack look like
   Chrome" is untestable here. This is also the one claim section 3 says is
   unfixable anyway.
5. **No anti-bot vendor was tested against.** Section 3 cites Cloudflare's own
   documentation for what it inspects. I did not attempt a bypass of any live
   challenge, and the evidence says it would not work.
6. **Jina and browser-use pricing was not verified first-hand**; I relied on the
   parallel research for their numbers and verified Cloudflare's myself, since
   Cloudflare's figures are the ones the cost model depends on.
7. **The upstream timeout's wall-clock behaviour in production is untested.** Its
   resolution and clamping are proven, and the local Worker's timers are accurate,
   but the harness cannot simulate a peer slower than ~1 s, so no end-to-end
   deadline was observed against a genuinely slow origin.

## A note on how this was reviewed

Ten independent reviews were run over this document and the code, each with a
different lens: worker correctness, security adversary, test-suite quality,
harness fidelity, factual audit, pricing recomputation, overclaim audit,
regression hunt against v1, deployability, and public-repo readiness.

They found four genuine blockers, all now fixed and all confirmed by execution
rather than by reading:

1. **Every browser caller was broken.** The `OPTIONS` branch returned without
   `Access-Control-Allow-Origin`, so preflight always failed. The suite's
   preflight assertion checked only the status code and methods, so it passed.
   That is v1's original defect reintroduced under a different shape.
2. **The proxy leaked its own credential.** `wrangler secret put AUTH_TOKEN` was a
   no-op (the Worker read a module constant, never `env`), and `authorization` was
   not in any strip list, so the token would have gone to every third-party origin.
3. **The SSRF guard was bypassable.** WHATWG URL serialises IPv6 hosts bracketed
   and in hex, so `[::1]` and `[::ffff:a9fe:a9fe]` never matched the blocklist, and
   `localhost.` evaded the suffix check. Fifteen forms are now covered.
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
  a real allowlist bypass passed a green suite.
- Section 8.6's central claim was **measured with a buggy client** and has been
  corrected in place rather than quietly deleted.

Where a reviewer asserted something I could check, I checked it; a few did not
hold up. The `byte-for-byte` claim on `v1-baseline.js` is now stated as the
exception it always was (a 2-line provenance header), and the upstream sha256 and
101-line count are confirmed correct against the downloaded original.

## Files I read, and what came of it

| Path | Used for |
|---|---|
| `pkgforge-dev/reverse-proxies/.../worker.js` | v1 baseline, sections 1-2 |
| `cloudflare/workers/platform/pricing` | 7.1, 7.2 |
| `cloudflare/browser-run/pricing`, `/limits` | 5, 7.4 |
| `cloudflare/bots/concepts/bot-score`, `/bot-management-variables` | 3.2 |
| `cloudflare/turnstile/get-started/server-side-validation`, `/troubleshooting/testing` | 3.1 |
| `cloudflare/workers/runtime-apis/web-standards` | 3.2 |
| `cloudflare/workers/platform/limits` | 3.2, 8 |
| `cloudflare/workers/changelog/rss/index.xml` | 4.4 |
| `jina-ai/reader` (`src/services/curl.ts`, `crawler-options.ts`) | 4.1 |
| `browser-use/browser-use` (`pyproject.toml` history, `profile.py`) | 4.2 |
| `Azathothas/b-ids` (`lib.rs`, `configs.rs`, `README.md`) | 4.3 |
| `cloudflare/workerd` releases + `workerd.capnp` | 8.3 |