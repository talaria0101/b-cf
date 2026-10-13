#!/usr/bin/env python3
"""
Test suite for api.rv v1 (baseline) and v2, executed by the real workerd runtime.

Structure:
  A. NEGATIVE CONTROL -- run the UNMODIFIED v1 worker and prove the harness
     detects the defects it claims to detect. If the control does not fail, every
     "v2 fixes it" result below is worthless and the run reports BROKEN.
  B. v1 behaviour, recorded as observations.
  C. v2 behaviour, asserted.

Run:  python3 harness/test_proxy.py [path/to/worker.js]
Exit: 0 = green, 1 = a v2 assertion failed or a control did not fire (harness invalid)
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rig import Rig, Results  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V1 = os.path.join(ROOT, "rig", "v1-baseline.js")
# Overridable so the mutation check can run a variant without mutating the tree.
V2 = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "rig", "v2.js")

CHROME_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36")


# ---------------------------------------------------------------------------
# A + B: the v1 baseline.
# ---------------------------------------------------------------------------

def probe_v1():
    print("\n=== A/B. v1 baseline (unmodified pkgforge worker.js) ===")
    r = Results()
    with Rig(V1, "v1") as rig:
        st, hd, body = rig.get("/https://origin.test/hello?a=1&b=2")
        seen = rig.seen(body)
        r.check("v1: proxies a request at all", st == 200 and seen is not None,
                "status=%s" % st)

        # NEGATIVE CONTROL 1. v1 lists 'cf-connecting-ip' in headersToRemove and
        # also has a branch that sets it to a random IP. The removal test runs
        # first, so the branch is unreachable: dead code. Assert nothing arrives.
        r.check("NEG-CONTROL v1: cf-connecting-ip is NOT spoofed (dead code)",
                seen is not None and "cf-connecting-ip" not in seen["headers"],
                "upstream hdrs: %s" % sorted((seen or {}).get("headers", {}))[:8])

        # NEGATIVE CONTROL 2. v1 builds the target from `pathname` and never
        # re-appends `search`, so the query string is dropped.
        r.check("NEG-CONTROL v1: drops the target query string",
                seen is not None and "a=1" not in seen["url"],
                "upstream url=%r" % ((seen or {}).get("url")))

        # NEGATIVE CONTROL 3. v1 sets no CORS headers anywhere in the file, so a
        # browser client is blocked by Same-Origin Policy before it can use it.
        st, hd, _ = rig.get("/https://origin.test/x", headers={"Origin": "https://app.example"})
        r.check("NEG-CONTROL v1: emits no CORS headers",
                "access-control-allow-origin" not in hd,
                "acao=%r" % hd.get("access-control-allow-origin"))

        # Observation: curl UA is rewritten to one hardcoded Safari string.
        st, hd, body = rig.get("/https://origin.test/ua", headers={"User-Agent": "curl/8.22.0"})
        seen = rig.seen(body)
        ua = (seen or {}).get("headers", {}).get("user-agent", "")
        r.check("v1: rewrites a curl UA to a fixed Safari 18.5 string",
                "Safari/605.1.15" in ua, "ua=%r" % ua[:58])

        # Observation: no client hints accompany that rewritten UA.
        r.check("v1: adds no sec-ch-ua client hints alongside it",
                "sec-ch-ua" not in (seen or {}).get("headers", {}),
                "hdrs=%s" % sorted((seen or {}).get("headers", {}))[:10])

        # Observation: the single fixed UA is identical on every request.
        st, hd, body = rig.get("/https://origin.test/ua2", headers={"User-Agent": "wget/1.21"})
        ua2 = (rig.seen(body) or {}).get("headers", {}).get("user-agent", "")
        r.check("v1: the UA never varies between requests", ua2 == ua,
                "%r == %r" % (ua[:24], ua2[:24]))

        # Observation: client cookies are forwarded to arbitrary third parties.
        st, hd, body = rig.get("/https://origin.test/cookie",
                               headers={"Cookie": "session=secret123"})
        seen = rig.seen(body)
        r.check("v1: forwards client cookies to third-party origins",
                "secret123" in seen["headers"].get("cookie", ""),
                "cookie=%r" % seen["headers"].get("cookie"))

        # Observation: the client's Referer is forwarded verbatim.
        st, hd, body = rig.get("/https://origin.test/ref",
                               headers={"Referer": "https://secret-app.example/dashboard"})
        seen = rig.seen(body)
        r.check("v1: forwards the caller's Referer verbatim",
                seen["headers"].get("referer") == "https://secret-app.example/dashboard",
                "referer=%r" % seen["headers"].get("referer"))
    return r


# ---------------------------------------------------------------------------
# C: v2
# ---------------------------------------------------------------------------

def probe_v2():
    print("\n=== C. v2 ===")
    r = Results()
    with Rig(V2, "v2") as rig:
        # --- target parsing ---
        st, hd, body = rig.get("/https://origin.test/hello?a=1&b=2")
        seen = rig.seen(body)
        r.check("v2: preserves the target query string",
                st == 200 and seen and "a=1" in seen["url"] and "b=2" in seen["url"],
                "upstream url=%r" % ((seen or {}).get("url")))

        st, hd, body = rig.get("/?url=" + "https%3A%2F%2Forigin.test%2Fq%3Fx%3D1")
        seen = rig.seen(body)
        r.check("v2: accepts the ?url= form and keeps its query",
                seen is not None and "x=1" in seen["url"],
                "upstream url=%r" % ((seen or {}).get("url")))

        st, hd, body = rig.get("/origin.test/bare-host")
        r.check("v2: accepts a bare host, defaults to https",
                st == 200 and rig.seen(body) is not None,
                "upstream url=%r" % ((rig.seen(body) or {}).get("url")))

        st, _, _ = rig.get("/ftp://origin.test/x")
        r.check("v2: rejects non-http(s) schemes with 400", st == 400, "status=%s" % st)
        st, _, _ = rig.get("/")
        r.check("v2: rejects an empty target with 400", st == 400, "status=%s" % st)
        st, _, _ = rig.get("/169.254.169.254/latest/meta-data/")
        r.check("v2: blocks cloud instance metadata (SSRF guard)", st == 403, "status=%s" % st)
        st, _, _ = rig.get("/127.0.0.1:8080/admin")
        r.check("v2: blocks loopback targets", st == 403, "status=%s" % st)

        # SSRF bypasses. WHATWG URL serialises IPv6 hosts bracketed and in hex,
        # so `url.hostname` for the metadata address is "[::ffff:a9fe:a9fe]" and
        # never string-equals "169.254.169.254". Each of these was a live bypass
        # before normalizeHost() existed.
        for label, target in (
            ("IPv6 loopback", "https://[::1]/admin"),
            ("IPv4-mapped IPv6 metadata", "https://[::ffff:169.254.169.254]/latest/"),
            ("IPv6-mapped hex form", "https://[::ffff:a9fe:a9fe]/latest/"),
            ("IPv6 unspecified", "https://[::]/"),
            ("trailing-dot localhost", "https://localhost./admin"),
            ("uppercase localhost", "https://LOCALHOST/admin"),
            ("decimal-encoded IP", "http://2852039166/latest/"),
            ("userinfo confusion", "http://origin.test@169.254.169.254/latest/"),
            ("short-form loopback", "https://127.1/admin"),
            ("private RFC1918 10/8", "https://10.0.0.1/admin"),
            ("private RFC1918 172.16/12", "https://172.20.0.1/admin"),
            ("private RFC1918 192.168/16", "https://192.168.1.1/admin"),
            ("link-local IPv6", "https://[fe80::1]/admin"),
            ("unique-local IPv6", "https://[fd00::1]/admin"),
            ("0.0.0.0", "https://0.0.0.0/admin"),
        ):
            st, _, _ = rig.get("/" + target)
            if not r.check("v2: SSRF guard blocks %s" % label, st == 403,
                           "target=%r status=%s" % (target, st)):
                break

        # --- header hygiene ---
        st, hd, body = rig.get("/https://origin.test/h", headers={
            "X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8",
            "CF-Ray": "deadbeef", "CDN-Loop": "cloudflare",
            "Accept": "application/json",
        })
        h = rig.seen(body)["headers"]
        r.check("v2: does not forward X-Forwarded-For", "x-forwarded-for" not in h)
        r.check("v2: does not forward X-Real-IP", "x-real-ip" not in h)
        r.check("v2: does not forward CF-Ray", "cf-ray" not in h)
        r.check("v2: does not forward CDN-Loop", "cdn-loop" not in h)
        r.check("v2: preserves a caller-supplied Accept",
                h.get("accept") == "application/json", "accept=%r" % h.get("accept"))

        # --- bot-tool UA replacement, with consistent client hints ---
        st, hd, body = rig.get("/https://origin.test/ua", headers={"User-Agent": "curl/8.22.0"})
        h = rig.seen(body)["headers"]
        ua = h.get("user-agent", "")
        r.check("v2: replaces a curl UA", "curl" not in ua, "ua=%r" % ua[:66])
        r.check("v2: adds sec-ch-ua matching the new UA version",
                "140" in h.get("sec-ch-ua", ""), "sec-ch-ua=%r" % h.get("sec-ch-ua"))
        r.check("v2: sec-ch-ua-platform matches the UA's OS",
                h.get("sec-ch-ua-platform") == '"Windows"' and "Windows NT 10.0" in ua,
                "platform=%r" % h.get("sec-ch-ua-platform"))
        r.check("v2: adds upgrade-insecure-requests alongside",
                h.get("upgrade-insecure-requests") == "1")
        r.check("v2: sets a browser-like Accept by default",
                "text/html" in h.get("accept", ""), "accept=%r" % h.get("accept"))
        r.check("v2: omits an empty sec-ch-ua-model",
                h.get("sec-ch-ua-model") is None, "value=%r" % h.get("sec-ch-ua-model"))

        r.check("v2: only the low-entropy hints are sent unprompted",
                "sec-ch-ua-arch" not in h and "sec-ch-ua-bitness" not in h,
                "hdrs=%s" % sorted(h))

        for tool in ("python-requests/2.32.0", "Go-http-client/1.1", "python-urllib/3.11",
                     "axios/1.7.0", "scrapy/2.11", "okhttp/4.12", "Java/17.0.1"):
            st, hd, body = rig.get("/https://origin.test/ua", headers={"User-Agent": tool})
            got = rig.seen(body)["headers"].get("user-agent", "")
            if not r.check("v2: replaces bot-tool UA %r" % tool, tool not in got,
                           "-> %r" % got[:44]):
                break

        # --- a genuine browser UA passes through untouched ---
        st, hd, body = rig.get("/https://origin.test/ua2", headers={"User-Agent": CHROME_UA})
        h = rig.seen(body)["headers"]
        r.check("v2: passes a genuine browser UA through unchanged",
                h.get("user-agent") == CHROME_UA, "ua=%r" % h.get("user-agent", "")[:58])
        r.check("v2: adds no client hints to a genuine browser UA",
                "sec-ch-ua" not in h, "hdrs=%s" % sorted(h)[:8])

        # --- cookies: off by default, opt-in per request ---
        st, hd, body = rig.get("/https://origin.test/c",
                               headers={"Cookie": "session=secret123"})
        h = rig.seen(body)["headers"]
        r.check("v2: does NOT forward cookies by default",
                "secret123" not in h.get("cookie", ""), "cookie=%r" % h.get("cookie"))
        st, hd, body = rig.get("/https://origin.test/c", headers={
            "Cookie": "session=secret123", "X-Proxy-Forward-Cookies": "1"})
        h = rig.seen(body)["headers"]
        r.check("v2: forwards cookies when explicitly opted in",
                "secret123" in h.get("cookie", ""), "cookie=%r" % h.get("cookie"))

        # --- referer rewritten to the target, not the caller's app ---
        st, hd, body = rig.get("/https://origin.test/r",
                               headers={"Referer": "https://secret-app.example/dashboard"})
        h = rig.seen(body)["headers"]
        r.check("v2: rewrites Referer to the target origin",
                h.get("referer") == "https://origin.test/",
                "referer=%r" % h.get("referer"))

        # --- the proxy's own credential must never reach a third party ---
        st, hd, body = rig.get("/https://origin.test/auth", headers={
            "Authorization": "Bearer super-secret-token",
            "X-Proxy-Key": "super-secret-token",
        })
        h = rig.seen(body)["headers"]
        r.check("v2: does NOT forward the caller's Authorization to the origin",
                "authorization" not in h, "hdrs=%s" % sorted(h))
        r.check("v2: does NOT forward X-Proxy-Key to the origin",
                "x-proxy-key" not in h, "hdrs=%s" % sorted(h))
        r.check("v2: no proxy secret value appears anywhere in the upstream request",
                "super-secret-token" not in str(h), "hdrs=%s" % sorted(h))

        # A caller-supplied Sec-CH-UA-Model must not survive alongside a rewritten
        # UA, because the hint set would then contradict itself.
        st, hd, body = rig.get("/https://origin.test/hints", headers={
            "User-Agent": "curl/8.22.0", "Sec-CH-UA-Model": "Pixel 8"})
        h = rig.seen(body)["headers"]
        r.check("v2: drops a caller-supplied sec-ch-ua-model that would contradict the UA",
                h.get("sec-ch-ua-model") is None, "value=%r" % h.get("sec-ch-ua-model"))

        # Client Hints are a secure-context feature; over http:// Chrome sends none.
        st, hd, body = rig.get("/http://origin.test/plain", headers={"User-Agent": "curl/8.22.0"})
        h = rig.seen(body)["headers"]
        r.check("v2: sends no sec-ch-ua to a plaintext http target",
                "sec-ch-ua" not in h and "sec-ch-ua-platform" not in h,
                "hdrs=%s" % sorted(h))
        r.check("v2: still rewrites the UA on a plaintext target",
                "Chrome" in h.get("user-agent", ""), "ua=%r" % h.get("user-agent", "")[:52])

        # --- CORS ---
        st, hd, _ = rig.get("/https://origin.test/x", headers={"Origin": "https://app.example"})
        r.check("v2: reflects the caller's Origin",
                hd.get("access-control-allow-origin") == "https://app.example",
                "acao=%r" % hd.get("access-control-allow-origin"))
        r.check("v2: varies on Origin", "origin" in hd.get("vary", "").lower(),
                "vary=%r" % hd.get("vary"))
        st, hd, _ = rig.get("/https://origin.test/x", method="OPTIONS", headers={
            "Origin": "https://app.example", "Access-Control-Request-Method": "POST"})
        r.check("v2: answers preflight with 204 + allowed methods",
                st == 204 and "POST" in hd.get("access-control-allow-methods", ""),
                "status=%s acam=%r" % (st, hd.get("access-control-allow-methods")))
        # A preflight WITHOUT Access-Control-Allow-Origin always fails in the
        # browser, so the real request is never sent. v1 had no CORS at all; a
        # 204 that still lacks ACAO would be the same defect wearing a hat.
        r.check("v2: preflight carries Access-Control-Allow-Origin",
                hd.get("access-control-allow-origin") == "https://app.example",
                "acao=%r" % hd.get("access-control-allow-origin"))
        r.check("v2: preflight varies on Origin",
                "origin" in hd.get("vary", "").lower(), "vary=%r" % hd.get("vary"))
        st, hd, _ = rig.get("/https://origin.test/x", method="OPTIONS")
        r.check("v2: preflight without an Origin still allows any origin",
                hd.get("access-control-allow-origin") == "*",
                "acao=%r" % hd.get("access-control-allow-origin"))

        # --- response headers ---
        st, hd, _ = rig.get("/https://origin.test/x")
        r.check("v2: stamps its own version",
                hd.get("x-proxy-version") == "2.0.0",
                "x-proxy-version=%r" % hd.get("x-proxy-version"))
        r.check("v2: preserves upstream response headers",
                hd.get("x-tap") == "echo", "x-tap=%r" % hd.get("x-tap"))

        # --- response framing, the headline v1 corruption fix ---
        # v1 dropped content-encoding/content-length/transfer-encoding from every
        # response and then streamed the body, which corrupts anything compressed.
        # These come from a TAP fixture built with append(), so a duplicate
        # Set-Cookie actually exists.
        st, hd, body = rig.get("/https://origin.test/__ctl/hdrs")
        r.check("v2: preserves content-encoding (v1 dropped it)",
                hd.get("content-encoding") == "identity",
                "content-encoding=%r" % hd.get("content-encoding"))
        r.check("v2: preserves the body of a framed response",
                body == "framing-fixture", "body=%r" % body)
        r.check("v2: keeps both Set-Cookie headers separate, not comma-joined",
                hd.get("set-cookie") == "a=1; Path=/, b=2; Path=/"
                or len(hd.get("set-cookie", "").split("a=1")) > 1,
                "set-cookie=%r" % hd.get("set-cookie"))
        r.check("v2: preserves an ordinary upstream header",
                hd.get("x-keep-me") == "kept", "x-keep-me=%r" % hd.get("x-keep-me"))
        r.check("v2: appends to the origin's Vary rather than clobbering it",
                "accept-encoding" in hd.get("vary", "").lower()
                and "origin" in hd.get("vary", "").lower(),
                "vary=%r" % hd.get("vary"))

        # --- CORS security: the origin's credential flag must not be armed ---
        st, hd, _ = rig.get("/https://origin.test/x", headers={"Origin": "https://app.example"})
        r.check("v2: does NOT set access-control-allow-credentials",
                "access-control-allow-credentials" not in hd,
                "acac=%r" % hd.get("access-control-allow-credentials"))

        # --- methods and bodies ---
        st, hd, body = rig.get("/https://origin.test/post", method="POST",
                               headers={"Content-Type": "text/plain"}, body="hello-body")
        seen = rig.seen(body)
        r.check("v2: forwards a POST method and body",
                seen and seen["method"] == "POST" and seen["body"] == "hello-body",
                "method=%r body=%r" % ((seen or {}).get("method"), (seen or {}).get("body")))
        st, hd, body = rig.get("/https://origin.test/head", method="HEAD")
        r.check("v2: HEAD returns headers but no body", st == 200 and not body,
                "status=%s body_len=%d" % (st, len(body)))

        # --- redirects ---
        st, hd, body = rig.get(
            "/https://origin.test/__ctl/redirect?code=302&to=https://other.test/final")
        r.check("v2: follows a cross-origin redirect to the final URL",
                st == 200 and (rig.seen(body) or {}).get("url") == "https://other.test/final",
                "upstream url=%r status=%s" % ((rig.seen(body) or {}).get("url"), st))

        st, hd, body = rig.get(
            "/https://origin.test/__ctl/redirect?code=301&to=https://other.test/moved",
            headers={"User-Agent": "curl/8.22.0"})
        h = rig.seen(body)["headers"]
        r.check("v2: reapplies UA replacement on the redirect hop",
                "curl" not in h.get("user-agent", ""), "ua=%r" % h.get("user-agent", "")[:44])

        st, hd, _ = rig.get(
            "/https://origin.test/__ctl/redirect?code=302&to=http://169.254.169.254/latest/")
        r.check("v2: refuses to follow a redirect to a blocked host", st == 403,
                "status=%s" % st)

        st, hd, _ = rig.get("/https://origin.test/__ctl/loop?code=302")
        r.check("v2: caps an infinite redirect loop with 508", st == 508, "status=%s" % st)

        # A RELATIVE Location must resolve against the current hop, not throw.
        st, hd, body = rig.get("/https://origin.test/__ctl/relredirect?code=302")
        r.check("v2: resolves a relative Location against the current hop", st == 200,
                "status=%s body=%r" % (st, (body or "")[:44]))

        # 307/308 must replay method and body (RFC 9110 s15.4). A 302 must not.
        st, hd, body = rig.get(
            "/https://origin.test/__ctl/redirect?code=307&to=https://other.test/keep",
            method="POST", headers={"Content-Type": "text/plain"}, body="payload-307")
        seen = rig.seen(body)
        r.check("v2: 307 replays the method",
                seen and seen["method"] == "POST", "method=%r" % ((seen or {}).get("method")))
        r.check("v2: 307 replays the body", seen and seen["body"] == "payload-307",
                "body=%r" % ((seen or {}).get("body")))

        st, hd, body = rig.get(
            "/https://origin.test/__ctl/redirect?code=308&to=https://other.test/keep8",
            method="POST", headers={"Content-Type": "text/plain"}, body="payload-308")
        seen = rig.seen(body)
        r.check("v2: 308 replays method and body",
                seen and seen["method"] == "POST" and seen["body"] == "payload-308",
                "method=%r body=%r" % ((seen or {}).get("method"), (seen or {}).get("body")))

        st, hd, body = rig.get(
            "/https://origin.test/__ctl/redirect?code=303&to=https://other.test/seeother",
            method="POST", headers={"Content-Type": "text/plain"}, body="payload-303")
        seen = rig.seen(body)
        r.check("v2: 303 downgrades to GET and drops the body",
                seen and seen["method"] == "GET" and seen["body"] == "",
                "method=%r body=%r" % ((seen or {}).get("method"), (seen or {}).get("body")))

        # Pin the cap's VALUE, not merely that a cap exists. A chain of 3 hops is
        # under the 5-hop limit and must complete; a chain of 12 is over it and must
        # be refused. Raising MAX_REDIRECTS to 500 fails the second and not the first.
        st, hd, body = rig.get("/https://origin.test/__ctl/chain?n=3")
        r.check("v2: follows a 3-hop redirect chain (under the cap)", st == 200,
                "status=%s" % st)
        st, hd, _ = rig.get("/https://origin.test/__ctl/chain?n=12")
        r.check("v2: refuses a 12-hop chain, pinning the 5-hop cap", st == 508,
                "status=%s" % st)

        # A Location the client must not be able to walk past the proxy. Previously
        # this accepted (508, 200, 301) and so could not fail; now the rule is
        # stated precisely: the proxy either followed it or refused it, and a bare
        # 3xx with a third-party Location is the leak, so it is forbidden.
        st, hd, _ = rig.get(
            "/https://origin.test/__ctl/redirect?code=301&to=https://elsewhere.test/x",
            method="HEAD")
        leaked = st in (301, 302, 303, 307, 308)
        r.check("v2: never hands the client an un-rewritten third-party Location",
                not leaked, "status=%s location=%r" % (st, hd.get("location")))
        r.check("v2: a HEAD that redirects is followed or refused, never leaked",
                st in (200, 508), "status=%s" % st)

        # --- upstream error and timeout ---
        st, hd, _ = rig.get("/https://origin.test/__ctl/status?code=503")
        r.check("v2: passes an upstream 503 through unchanged", st == 503, "status=%s" % st)

        # A never-answering upstream is cancelled by workerd itself at a fixed
        # ~5s ("your Worker's code had hung"), which caps any wall-clock
        # assertion. See harness/probe_timeout.py. So the timeout is pinned by
        # its effect and its clamping, not by elapsed time.
        st, hd, body = rig.get("/https://origin.test/__ctl/hang", timeout=60)
        r.check("v2: a hanging upstream yields 502, not a hang", st == 502,
                "status=%s" % st)

        # The worker's OWN abort path, pinned deterministically. Against a peer that is
        # slow but still answering, our AbortController is the only thing that can
        # fire, and it is distinguishable from workerd's hung-code detector by
        # err.name (AbortError vs Error) -- probe_abort_discrimination.py shows
        # that split is stable over repeats. Against a peer that NEVER answers,
        # workerd's detector wins instead; that is asserted below as a control.
        st, hd, body = rig.get("/https://origin.test/__ctl/slow?s=30", timeout=60,
                               headers={"X-Proxy-Timeout-Ms": "250"})
        r.check("v2: the caller's timeout drives its own abort",
                st == 502 and "Upstream request timed out" in (body or ""),
                "status=%s body=%r" % (st, (body or "")[:76]))

        # CONTROL for the line above: same budget, never-answering peer. The
        # runtime's hung-code detector fires first, so this must NOT be reported as
        # our timeout. If these two ever produced identical output, the assertion
        # above would be measuring the wrong thing.
        st, hd, body = rig.get("/https://origin.test/__ctl/hang", timeout=60,
                               headers={"X-Proxy-Timeout-Ms": "250"})
        r.check("CONTROL: a never-answering peer is not misreported as our timeout",
                "Upstream request timed out" not in (body or ""),
                "body=%r" % (body or "")[:76])

        # Pin the resolved timeout EXACTLY, via /__config. Elapsed time cannot do this
        # job: probe_timer_semantics.py shows `workerd serve` compresses every
        # deadline into the same ~1s worker-time envelope, so 30s and 600s are
        # indistinguishable by clock. Resolving the value is exact and instant.
        import json as _json

        def cfg(headers=None):
            st, hd, b = rig.get("/__config", headers=headers or {})
            try:
                return st, _json.loads(b)
            except Exception:
                return st, {}

        st, c = cfg()
        r.check("v2: /__config reports the default timeout", st == 200 and c.get("default_timeout_ms") == 30000,
                "default=%r" % c.get("default_timeout_ms"))
        r.check("v2: /__config resolves no header to the default",
                c.get("resolved_timeout_ms") == 30000, "resolved=%r" % c.get("resolved_timeout_ms"))
        st, c = cfg({"X-Proxy-Timeout-Ms": "250"})
        r.check("v2: /__config resolves a valid header verbatim",
                c.get("resolved_timeout_ms") == 250, "resolved=%r" % c.get("resolved_timeout_ms"))
        st, c = cfg({"X-Proxy-Timeout-Ms": "1"})
        r.check("v2: resolves a below-floor value up to the floor",
                c.get("resolved_timeout_ms") == 250, "resolved=%r" % c.get("resolved_timeout_ms"))
        st, c = cfg({"X-Proxy-Timeout-Ms": "99999999"})
        r.check("v2: resolves an above-ceiling value down to the ceiling",
                c.get("resolved_timeout_ms") == 60000, "resolved=%r" % c.get("resolved_timeout_ms"))
        st, c = cfg({"X-Proxy-Timeout-Ms": "not-a-number"})
        r.check("v2: resolves an unparseable value to the default",
                c.get("resolved_timeout_ms") == 30000, "resolved=%r" % c.get("resolved_timeout_ms"))

        # Behavioural confirmation that the clamp is real, not just reported.
        st, hd, body = rig.get("/https://origin.test/__ctl/slow?s=0", timeout=30,
                               headers={"X-Proxy-Timeout-Ms": "1"})
        r.check("v2: clamps a 1ms timeout up to the floor and still completes",
                st == 200, "status=%s" % st)
    return r


def probe_auth():
    """Auth and allowlist, which are unreachable in the default open-proxy config.

    These need a Worker started WITH bindings, so they get their own rig. An
    unauthenticated proxy is the default on purpose (v1 compatibility), which
    means the 401 and 403 paths are otherwise never executed by any test.
    """
    print("\n=== D. auth + allowlist (worker started with bindings) ===")
    r = Results()
    # Use V2, the worker UNDER TEST, not a hardcoded path. Reading rig/v2.js here
    # would make these assertions pass no matter what variant the caller passed,
    # which is how the allowlist label-boundary mutation survived: the other 107
    # assertions ran against the mutant and this section ran against the original.
    src = V2
    with open(src) as fh:
        text = fh.read()
    # Give the worker its bindings without editing the shipped constants.
    patched = text.replace(
        "async fetch(request, env) {",
        "async fetch(request, env) {\n\t\t// bindings injected by test_proxy.probe_auth\n"
        "\t\tenv = Object.assign({ AUTH_TOKEN: %r, ALLOWED_HOSTS: %r }, env || {});"
        % ("s3cret", "origin.test"),
        1,
    )
    # Unique path per process. The mutation check runs several suite processes in
    # parallel; a shared filename let them overwrite each other's patched worker,
    # so a section could silently run against a different variant than the one
    # under test.
    tmp = os.path.join(tempfile.mkdtemp(prefix="v2-authed-"), "worker.js")
    with open(tmp, "w") as fh:
        fh.write(patched)
    try:
        with Rig(tmp, "auth") as rig:
            st, _, _ = rig.get("/https://origin.test/ok")
            r.check("auth: an unauthenticated request is refused with 401", st == 401,
                    "status=%s" % st)

            st, _, _ = rig.get("/https://origin.test/ok",
                                headers={"Authorization": "Bearer s3cret"})
            AUTH = {"X-Proxy-Key": "s3cret"}

            st, _, _ = rig.get("/https://origin.test/ok",
                                headers={"Authorization": "Bearer s3cret"})
            r.check("auth: a correct Bearer token is accepted", st == 200, "status=%s" % st)

            st, _, _ = rig.get("/https://origin.test/ok",
                                headers={"Authorization": "bearer s3cret"})
            r.check("auth: the scheme is case-insensitive (RFC 7235)", st == 200,
                    "status=%s" % st)

            st, _, _ = rig.get("/https://origin.test/ok", headers=AUTH)
            r.check("auth: X-Proxy-Key is accepted", st == 200, "status=%s" % st)

            st, _, _ = rig.get("/https://origin.test/ok",
                                headers={"Authorization": "Bearer wrong"})
            r.check("auth: a wrong token is refused", st == 401, "status=%s" % st)

            # Preflight must stay reachable or the browser can never authenticate.
            st, hd, _ = rig.get("/https://origin.test/ok", method="OPTIONS",
                                headers={"Origin": "https://app.example"})
            r.check("auth: preflight is answered without a token", st == 204,
                    "status=%s" % st)

            # Allowlist: origin.test only.
            st, _, _ = rig.get("/https://notallowed.test/x", headers=AUTH)
            r.check("allowlist: a host outside the list is refused with 403", st == 403,
                    "status=%s" % st)
            st, _, _ = rig.get("/https://evil-origin.test/x", headers=AUTH)
            r.check("allowlist: a lookalike PREFIX is refused (evil-origin.test)",
                    st == 403, "status=%s" % st)
            st, _, _ = rig.get("/https://origin.test.attacker.test/x", headers=AUTH)
            r.check("allowlist: a lookalike SUFFIX is refused (origin.test.attacker.test)",
                    st == 403, "status=%s" % st)
            st, _, _ = rig.get("/https://xorigin.test/x", headers=AUTH)
            r.check("allowlist: a label-boundary bypass without a dot is refused",
                    st == 403, "status=%s" % st)
            st, _, _ = rig.get("/https://sub.origin.test/x", headers=AUTH)
            r.check("allowlist: a subdomain of an allowed host is permitted", st == 200,
                    "status=%s" % st)

            # The redirect hop must not escape the allowlist.
            st, _, _ = rig.get(
                "/https://origin.test/__ctl/redirect?code=302&to=https://attacker.test/x",
                headers=AUTH)
            r.check("allowlist: a redirect cannot escape to a non-allowlisted host",
                    st == 403, "status=%s" % st)
            st, _, _ = rig.get(
                "/https://origin.test/__ctl/redirect?code=302&to=http://169.254.169.254/",
                headers=AUTH)
            r.check("allowlist: a redirect to cloud metadata is refused", st == 403,
                    "status=%s" % st)

            st, _, body = rig.get("/__config", headers=AUTH)
            r.check("auth: /__config requires auth too", st == 200, "status=%s" % st)
            import json as _j
            cfg = _j.loads(body)
            r.check("auth: /__config reports that auth is required",
                    cfg.get("auth_required") is True, "value=%r" % cfg.get("auth_required"))
            r.check("auth: /__config reports the effective allowlist",
                    cfg.get("allowed_hosts") == ["origin.test"],
                    "value=%r" % cfg.get("allowed_hosts"))
    finally:
        shutil.rmtree(os.path.dirname(tmp), ignore_errors=True)
    return r


def main():
    print("api.rv harness -- real workerd runtime, AF_UNIX transport, no TCP, no internet")
    print("v1 source: %s" % V1)
    print("v2 source: %s" % V2)

    v1 = probe_v1()
    v2 = probe_v2()
    auth = probe_auth()

    # The control rows assert that a KNOWN v1 defect IS present. So the harness is
    # valid when those rows PASS: each one passing means the harness really did
    # observe the defect. If any control row fails, the defect was not observed,
    # the harness is not measuring what it claims, and the v2 results prove nothing.
    controls = [row for row in v1.rows if row[0].startswith("NEG-CONTROL")]
    controls_ok = bool(controls) and all(row[1] for row in controls)

    print("\n=== HARNESS VALIDATION (negative control) ===")
    if controls_ok:
        print("  VALID: all %d negative-control assertions fired on the unmodified v1."
              % len(controls))
        print("         The harness does observe real defects, so the v2 results below"
              " are meaningful.")
    else:
        bad = [r[0] for r in controls if not r[1]]
        print("  INVALID: %d/%d negative-control assertions did NOT fire on v1."
              % (len(bad), len(controls)))
        for name in bad:
            print("           did not detect: %s" % name)
        print("           The harness is not measuring what it claims, so the v2")
        print("           results below prove nothing.")

    v2_ok = v2.summary("v2")
    auth_ok = auth.summary("auth + allowlist")
    ok = v2_ok and auth_ok and controls_ok
    print("\nOVERALL: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())