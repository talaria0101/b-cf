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

import json
import os
import re
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
    print("\n=== A/B. v1 baseline (reformatted pkgforge worker.js) ===")
    r = Results()
    with Rig(V1, "v1") as rig:
        st, hd, body = rig.get("/https://origin.test/hello?a=1&b=2")
        seen = rig.seen(body)
        r.check("v1: proxies a request at all", st == 200 and seen is not None,
                "status=%s" % st)

        # NEGATIVE CONTROL 1. v1 lists 'cf-connecting-ip' in headersToRemove and
        # also has a branch that sets it to a random IP. The removal test runs
        # first, so the branch is unreachable: dead code. Assert nothing arrives.
        r.check("NEG-CONTROL v1: cf-connecting-ip is never set (dead code)",
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
        # Public addresses that must NOT be blocked. A blocklist that fails closed
        # too eagerly is not a safe default, it is a broken proxy: an earlier
        # version of the v4 rules matched all of 192.0.0.0/16, which is 65534
        # addresses of routable public space. Each row sits just outside a boundary
        # this function tests, so widening a boundary by one is caught here.
        for label, target in (
            ("192.0.1.0/24 beside 192.0.0.0/24", "https://192.0.1.1/x"),
            ("192.0.3.0/24 beside TEST-NET-1", "https://192.0.3.1/x"),
            ("172.32.0.0/16 beside 172.16/12", "https://172.32.0.1/x"),
            ("100.63.0.0 below CGNAT", "https://100.63.0.1/x"),
            ("100.128.0.0 above CGNAT", "https://100.128.0.1/x"),
            ("198.20.0.0 above benchmark", "https://198.20.0.1/x"),
            ("198.50.0.0 below TEST-NET-2", "https://198.50.0.1/x"),
            ("203.1.0.0 above TEST-NET-3", "https://203.1.0.1/x"),
            ("223.255.255.255 last unicast", "https://223.255.255.255/x"),
            ("192.89.0.0 beside 6to4 relay", "https://192.89.0.1/x"),
            ("6to4 of a public address", "https://[2002:0808:0808::]/x"),
            ("2001:200:: beyond 2001::/23", "https://[2001:200::1]/x"),
            ("2001:4860 public resolver", "https://[2001:4860:4860::8888]/x"),
            ("2606:4700 public v6", "https://[2606:4700::1111]/x"),
            ("a normal name", "https://example.com/x"),
        ):
            st, _, _ = rig.get("/" + target)
            if not r.check("v2: SSRF guard does NOT over-block %s" % label, st == 200,
                           "target=%r status=%s" % (target, st)):
                break

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

        # Address-normalisation cases. WHATWG URL serialises IPv6 hosts bracketed
        # and in hex, so `url.hostname` for the metadata address is
        # "[::ffff:a9fe:a9fe]" and never string-equals "169.254.169.254". Each of
        # these was a confirmed gap before normalizeHost() existed.
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
            # RFC 6598 shared address space. Carrier NAT equipment and some
            # metadata endpoints live here, and the comment above claims "any
            # reserved range", so an unlisted reserved block is a gap in both.
            ("CGNAT 100.64/10", "https://100.100.100.200/latest/meta-data/"),
            ("CGNAT low edge", "https://100.64.0.1/admin"),
            ("IETF protocol assignments 192.0.0/24", "https://192.0.0.1/admin"),
            ("documentation 192.0.2/24", "https://192.0.2.1/admin"),
            ("benchmark 198.18/15", "https://198.18.0.1/admin"),
            # RFC 6052 NAT64 embeds a v4 address in a v6 host, so a blocked v4
            # target stays reachable through the prefix unless it is blocked too.
            ("NAT64 64:ff9b::/96", "https://[64:ff9b::7f00:1]/admin"),
            ("NAT64 leading-zero spelling", "https://[0064:ff9b::7f00:1]/admin"),
            ("NAT64 local-use 64:ff9b:1::/48", "https://[64:ff9b:1::a9fe:a9fe]/admin"),
            # 6to4 (RFC 3056) puts an IPv4 address in groups 1 and 2 of the v6
            # address, so 2002:a9fe:a9fe:: IS 169.254.169.254 and 2002:7f00:1:: is
            # 127.0.0.1. Blocking only the v4 spelling leaves a direct route to
            # both, which is what an earlier version of the guard did.
            ("6to4 of the metadata address", "https://[2002:a9fe:a9fe::]/latest/"),
            ("6to4 of loopback", "https://[2002:7f00:1::]/admin"),
            ("6to4 of RFC1918", "https://[2002:c0a8:1::]/admin"),
            ("6to4 with explicit tail", "https://[2002:a9fe:a9fe:0:0:0:0:0]/latest/"),
            ("documentation 2001:db8::/32", "https://[2001:db8::1]/admin"),
            ("IETF assignments 2001::/23", "https://[2001::1]/admin"),
            ("multicast ff02::/16", "https://[ff02::1]/admin"),
            ("multicast ff00::/8", "https://[ff00::]/admin"),
            ("site-local fec0::/10", "https://[fec0::1]/admin"),
            ("documentation 3fff::/20", "https://[3fff::1]/admin"),
            ("TEST-NET-2", "https://198.51.100.1/admin"),
            ("TEST-NET-3", "https://203.0.113.1/admin"),
            ("6to4 relay anycast", "https://192.88.99.1/admin"),
            ("bare IPv6 loopback literal", "https://[0:0:0:0:0:0:0:1]/admin"),
        ):
            st, _, _ = rig.get("/" + target)
            if not r.check("v2: SSRF guard blocks %s" % label, st == 403,
                           "target=%r status=%s" % (target, st)):
                break

        # A control byte defeats the scheme check rather than the blocklist: a NUL
        # makes `new URL(candidate)` throw, and the bare-host fallback then builds
        # "https://ftp://x" with host "ftp", turning a rejected scheme into a
        # request for a different host than the caller named.
        st, _, _ = rig.get("/ftp%3A%2F%2Fevil.test%00/x")
        r.check("v2: rejects a target containing a NUL byte with 400", st == 400,
                "status=%s" % st)

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

        # The caller's Origin and sec-fetch-* describe the caller's PAGE, not the
        # request being made on the caller's behalf. Forwarding them tells a third
        # party which internal app relayed the request. v1 leaked Referer and
        # cookies; Origin was the remaining one, and the CORS response headers this
        # proxy adds made it look like a deliberate first-party request.
        st, hd, body = rig.get("/https://origin.test/h", headers={
            "Origin": "https://secret-internal.corp.example",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-User": "?1",
        })
        h = rig.seen(body)["headers"]
        for hdr in ("origin", "sec-fetch-site", "sec-fetch-mode",
                    "sec-fetch-dest", "sec-fetch-user"):
            r.check("v2: does not forward the caller's %s" % hdr, hdr not in h,
                    "value=%r" % h.get(hdr))

        # --- bot-tool UA replacement, with consistent client hints ---
        # --- persona: the default must NOT claim a browser ---
        # A browser UA over workerd's own TLS 1.2 handshake is a louder signal
        # than an honest one, because the mismatch is the tell. proofs/01 measures
        # the incumbent doing exactly that. The default therefore describes the
        # transport rather than imitating Chrome.
        st, hd, body = rig.get("/https://origin.test/ua", headers={"User-Agent": "curl/8.22.0"})
        h = rig.seen(body)["headers"]
        r.check("v2: does NOT claim Chrome by default",
                "Chrome" not in h.get("user-agent", "") and "Safari" not in h.get("user-agent", ""),
                "ua=%r" % h.get("user-agent", ""))
        r.check("v2: sends no sec-ch-ua on the honest persona",
                "sec-ch-ua" not in h and "sec-ch-ua-platform" not in h,
                "hdrs=%s" % sorted(h))

        st, hd, body = rig.get("/http://origin.test/plain", headers={"User-Agent": "curl/8.22.0"})
        h = rig.seen(body)["headers"]
        r.check("v2: honest persona sends no client hints over plaintext either",
                "sec-ch-ua" not in h, "hdrs=%s" % sorted(h))
        r.check("v2: still replaces a bot-tool UA on a plaintext target",
                "curl" not in h.get("user-agent", ""),
                "ua=%r" % h.get("user-agent", ""))

        # persona=pass must forward the caller's UA untouched.
        st, hd, body = rig.get("/https://origin.test/p", headers={
            "User-Agent": "curl/8.22.0", "X-Proxy-Persona": "pass"})
        h = rig.seen(body)["headers"]
        r.check("v2: persona=pass forwards the caller's UA verbatim",
                h.get("user-agent") == "curl/8.22.0", "ua=%r" % h.get("user-agent", ""))

        # persona=chrome over the DEFAULT engine must be refused, not honoured.
        st, hd, body = rig.get("/https://origin.test/c", headers={
            "User-Agent": "curl/8.22.0", "X-Proxy-Persona": "chrome"})
        h = rig.seen(body) or {}
        r.check("v2: persona=chrome is refused without a TLS transport, not silently downgraded",
                "Chrome" not in str(h.get("headers", {}).get("user-agent", "")),
                "upstream ua=%r" % h.get("headers", {}).get("user-agent"))

        # engine=tls with no transport bound must be a clear 501.
        st, hd, body501 = rig.get("/https://origin.test/t", headers={"X-Proxy-Engine": "tls"})
        r.check("v2: engine=tls without a bound transport returns 501, not a silent fallback",
                st == 501, "status=%s" % st)
        r.check("v2: the 501 names the missing binding",
                "TLS_TRANSPORT" in (body501 or ""), "body=%r" % (body501 or "")[:70])

        # The engine header must not be forwarded to the origin.
        st, hd, body = rig.get("/https://origin.test/e", headers={
            "X-Proxy-Engine": "fetch", "X-Proxy-Persona": "edge"})
        h = rig.seen(body)["headers"]
        r.check("v2: does not forward x-proxy-engine to the origin",
                "x-proxy-engine" not in h, "hdrs=%s" % sorted(h))
        r.check("v2: does not forward x-proxy-persona to the origin",
                "x-proxy-persona" not in h, "hdrs=%s" % sorted(h))

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

        # EVERY hint must go when the proxy replaces the UA. Stripping only the
        # high-entropy ones left the origin holding a caller-supplied
        # `sec-ch-ua-platform: "macOS"` beside the proxy's own User-Agent, which is
        # precisely the incoherent identity this proxy exists to avoid, and it
        # contradicted the claim that the honest persona sends no hints at all.
        st, hd, body = rig.get("/https://origin.test/hints", headers={
            "User-Agent": "curl/8.22.0",
            "Sec-CH-UA": '"Chromium";v="140"',
            "Sec-CH-UA-Mobile": "?1",
            "Sec-CH-UA-Platform": '"macOS"',
            "Sec-CH-UA-Arch": '"arm"',
            "Sec-CH-UA-Platform-Version": '"15.0.0"',
        })
        h = rig.seen(body)["headers"]
        leftovers = sorted(k for k in h if k.startswith("sec-ch-"))
        r.check("v2: drops EVERY caller Client Hint when it replaces the UA",
                leftovers == [], "left over: %r" % leftovers)
        r.check("v2: the honest UA stands alone, with no hint contradicting it",
                h.get("user-agent") == "Cloudflare-Workers",
                "ua=%r" % h.get("user-agent"))

        # The mirror case: a caller's OWN coherent identity keeps its hints,
        # because there is nothing left to contradict. persona=pass is the same.
        st, hd, body = rig.get("/https://origin.test/keep", headers={
            "User-Agent": CHROME_UA,
            "Sec-CH-UA": '"Chromium";v="139"',
            "Sec-CH-UA-Platform": '"macOS"',
        })
        h = rig.seen(body)["headers"]
        r.check("v2: a genuine browser keeps its own matching hints",
                h.get("sec-ch-ua") == '"Chromium";v="139"'
                and h.get("sec-ch-ua-platform") == '"macOS"'
                and h.get("user-agent") == CHROME_UA,
                "hdrs=%s" % sorted(h))
        st, hd, body = rig.get("/https://origin.test/keep2", headers={
            "User-Agent": "curl/8.22.0", "X-Proxy-Persona": "pass",
            "Sec-CH-UA-Platform": '"macOS"'})
        h = rig.seen(body)["headers"]
        r.check("v2: persona=pass keeps the caller's hints, since it keeps their UA",
                h.get("sec-ch-ua-platform") == '"macOS"',
                "value=%r" % h.get("sec-ch-ua-platform"))

        # Client Hints are a secure-context feature; over http:// Chrome sends none.
        st, hd, body = rig.get("/http://origin.test/plain", headers={"User-Agent": "curl/8.22.0"})
        h = rig.seen(body)["headers"]
        r.check("v2: sends no sec-ch-ua to a plaintext http target",
                "sec-ch-ua" not in h and "sec-ch-ua-platform" not in h,
                "hdrs=%s" % sorted(h))

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
        # A preflight passes only if the header the browser is ABOUT to send is
        # listed in allow-headers. An omission does not degrade, it disables: the
        # browser never sends the real request. X-Proxy-Engine, X-Proxy-Persona
        # and X-Proxy-Timeout-Ms were missing, which silently made the persona
        # model, engine selection and the timeout unreachable from every browser
        # caller while the plain assertions above all passed.
        acah = hd.get("access-control-allow-headers", "").lower()
        for needed in ("x-proxy-engine", "x-proxy-persona", "x-proxy-timeout-ms",
                       "x-proxy-key", "x-proxy-forward-cookies",
                       "x-proxy-accept-language", "authorization", "content-type"):
            r.check("v2: preflight allows %s, so browsers can use it" % needed,
                    needed in acah, "acah=%r" % acah)
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
        # Two Set-Cookie header LINES, not one line whose value happens to contain the
        # same text. Asserted on the raw response head because a joined header
        # string cannot distinguish the two, which is why an earlier version of
        # this assertion could not fail: it read the joined value and accepted the
        # comma-joined corruption as one of its alternatives. The client's
        # hdrs.setdefault() also kept only the first line, so the second cookie was
        # invisible to any assertion at all.
        st, hd, body, head = rig.get("/https://origin.test/__ctl/hdrs", raw_head=True)
        sc_lines = [ln.split(":", 1)[1].strip()
                    for ln in head.split("\r\n")
                    if ln.lower().startswith("set-cookie:")]
        r.check("v2: keeps both Set-Cookie headers as separate header lines",
                len(sc_lines) == 2
                and sc_lines[0] == "a=1; Path=/"
                and sc_lines[1] == "b=2; Path=/",
                "lines=%r" % sc_lines)
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
        # The origin's OWN ACAC must be dropped, not merely never set by us.
        # Copying it through while reflecting the caller's Origin produces exactly
        # the combination the CORS comment says this proxy refuses: any site could
        # read a user's authenticated response through an open target list.
        st, hd, _ = rig.get("/https://origin.test/__ctl/hdrs",
                            headers={"Origin": "https://app.example"})
        r.check("v2: strips an upstream access-control-allow-credentials",
                "access-control-allow-credentials" not in hd,
                "acac=%r" % hd.get("access-control-allow-credentials"))
        r.check("v2: overrides an upstream access-control-allow-origin with its own",
                hd.get("access-control-allow-origin") == "https://app.example",
                "acao=%r" % hd.get("access-control-allow-origin"))

        # --- Location rewriting on a NON-3xx ---
        # The redirect loop consumes every 3xx-with-Location, so this is the only
        # shape that reaches rewriteLocation. The assertion below used to check
        # only the status code, which the follow-everything path satisfies for
        # free, so a mutant that removed the rewrite passed the whole suite.
        st, hd, _ = rig.get("/https://origin.test/__ctl/location201")
        r.check("v2: rewrites a Location on a non-3xx into proxy space",
                st == 201
                and hd.get("location", "").endswith("/https://thirdparty.test/thing")
                and "proxy" in hd.get("location", ""),
                "status=%s location=%r" % (st, hd.get("location")))

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
            st, _, _ = rig.get("/https://origin.test.outside.test/x", headers=AUTH)
            r.check("allowlist: a lookalike SUFFIX is refused (origin.test.outside.test)",
                    st == 403, "status=%s" % st)
            st, _, _ = rig.get("/https://xorigin.test/x", headers=AUTH)
            r.check("allowlist: a label-boundary match without a dot is refused",
                    st == 403, "status=%s" % st)
            st, _, _ = rig.get("/https://sub.origin.test/x", headers=AUTH)
            r.check("allowlist: a subdomain of an allowed host is permitted", st == 200,
                    "status=%s" % st)

            # The redirect hop must not escape the allowlist.
            st, _, _ = rig.get(
                "/https://origin.test/__ctl/redirect?code=302&to=https://outside.test/x",
                headers=AUTH)
            r.check("allowlist: a redirect cannot escape to a non-allowlisted host",
                    st == 403, "status=%s" % st)
            st, _, _ = rig.get(
                "/https://origin.test/__ctl/redirect?code=302&to=http://169.254.169.254/",
                headers=AUTH)
            r.check("allowlist: a redirect to cloud metadata is refused", st == 403,
                    "status=%s" % st)

            st, _, body = rig.get("/__config", headers=AUTH)
            r.check("auth: /__config is reachable with auth", st == 200, "status=%s" % st)
            import json as _j
            cfg = _j.loads(body)
            r.check("auth: /__config reports that auth is required",
                    cfg.get("auth_required") is True, "value=%r" % cfg.get("auth_required"))
            r.check("auth: /__config reports the effective allowlist",
                    cfg.get("allowed_hosts") == ["origin.test"],
                    "value=%r" % cfg.get("allowed_hosts"))

            # The unauthenticated case, which is the one the previous assertion
            # was named for but never ran. "Requires auth" is a claim about the
            # request WITHOUT a credential, not about the request with one.
            st, _, _ = rig.get("/__config")
            r.check("auth: /__config is REFUSED without a credential", st == 401,
                    "status=%s" % st)
    finally:
        shutil.rmtree(os.path.dirname(tmp), ignore_errors=True)
    return r


def probe_tls_engine():
    """The engine=tls path and the Chrome persona.

    Nothing else in the suite reaches `persona=chrome && engine=tls`: probe_auth
    binds no transport, so that branch is 501 there, and probe_v2 runs the default
    engine, so the chrome branch is false. Left alone this whole branch would be
    unexecuted code whose only "coverage" is an assertion about a 501.

    So bind a STUB transport that records what it was handed and answers. A stub
    proves the plumbing: which branch runs, what the transport receives, and what
    the claim looks like once there is a handshake behind it. It does not prove the
    ClientHello, because a stub has none. RESEARCH.md Layer 1 says so.
    """
    print("\n=== E. engine=tls + chrome persona (stub transport bound) ===")
    r = Results()
    with open(V2) as fh:
        text = fh.read()

    stub = (
        "\t\t// TLS transport stub injected by test_proxy.probe_tls_engine\n"
        "\t\tenv = Object.assign({ TLS_TRANSPORT: {\n"
        "\t\t\tfetch(url, init) {\n"
        "\t\t\t\tconst h = {};\n"
        "\t\t\t\tfor (const [k, v] of init.headers.entries()) h[k.toLowerCase()] = v;\n"
        "\t\t\t\tconst payload = {\n"
        "\t\t\t\t\ttransport: true,\n"
        "\t\t\t\t\turl: String(url),\n"
        "\t\t\t\t\theaders: h,\n"
        "\t\t\t\t\tinit_keys: Object.keys(init || {}),\n"
        "\t\t\t\t\thas_signal: !!(init && init.signal),\n"
        "\t\t\t\t};\n"
        "\t\t\t\treturn Promise.resolve(new Response(JSON.stringify(payload), {\n"
        "\t\t\t\t\tstatus: 200,\n"
        "\t\t\t\t\theaders: { 'content-type': 'application/json', 'x-tap': 'tls-transport' },\n"
        "\t\t\t\t}));\n"
        "\t\t\t},\n"
        "\t\t} }, env || {});\n"
    )
    patched = text.replace(
        "async fetch(request, env) {",
        "async fetch(request, env) {\n" + stub,
        1,
    )
    if patched == text:
        r.check("tls: the fetch() signature is still patchable", False,
                "worker.js no longer matches 'async fetch(request, env) {'")
        return r
    tmp = os.path.join(tempfile.mkdtemp(prefix="v2-tls-"), "worker.js")
    with open(tmp, "w") as fh:
        fh.write(patched)

    def sent(body):
        try:
            return json.loads(body)
        except Exception:
            return None

    try:
        with Rig(tmp, "tls") as rig:
            # 1. The transport branch is reachable and owns the request.
            st, hd, body = rig.get("/https://origin.test/deep?a=1&b=2",
                                   headers={"X-Proxy-Engine": "tls"})
            got = sent(body) or {}
            r.check("tls: engine=tls routes the request to the bound transport",
                    st == 200 and got.get("transport") is True
                    and hd.get("x-tap") == "tls-transport",
                    "status=%s x-tap=%r" % (st, hd.get("x-tap")))
            r.check("tls: the transport receives the full target URL, query included",
                    got.get("url") == "https://origin.test/deep?a=1&b=2",
                    "transport url=%r" % got.get("url"))
            # The transport gets the target plus the headers and the abort signal,
            # NOT a fetch()-shaped init: method/body/redirect/cf belong to the
            # runtime path only, because a userland transport owns its own framing.
            #
            # The signal is part of the contract rather than an optional extra. An
            # earlier version of this assertion asserted init_keys == ["headers"],
            # which pinned the absence of the signal and therefore pinned
            # X-Proxy-Timeout-Ms being a no-op on this engine: the AbortController
            # had nothing to abort. /__config reported the timeout as resolved, so
            # the caller was told 250 ms and received none.
            r.check("tls: the transport receives the signal, and method and body",
                    sorted(got.get("init_keys") or []) == ["body", "headers", "method", "signal"],
                    "init_keys=%r" % got.get("init_keys"))

            # An earlier version asserted init_keys == ["headers", "signal"], which
            # pinned the ABSENCE of method and body. That is what let a POST on
            # engine=tls reach the origin with no payload at all while the origin
            # answered 200 and the proxy reported success: a write reported done
            # that had not happened. init.keys() is a `module` namespace object in
            # workerd, so this must be read as an explicit whitelist of what the
            # proxy is allowed to pass, not as an assertion of everything present.
            r.check("tls: the transport is NOT handed the runtime-only init keys",
                    not ({"redirect", "cf"} & set(got.get("init_keys") or [])),
                    "init_keys=%r" % got.get("init_keys"))

            # CONTROL for all three above: the transport is used because the engine
            # said so, not because it is bound. With the stub present and the engine
            # left at its default, the runtime fetch() path must still run and the
            # TAP must be the thing that answers. If these two ever agreed, rows
            # 1-3 would be measuring the wrong branch.
            st, hd, body = rig.get("/https://origin.test/deep?a=1")
            got = sent(body) or {}
            r.check("CONTROL: a bound transport is NOT used when engine=fetch",
                    st == 200 and got.get("tap") is True and "transport" not in got,
                    "x-tap=%r keys=%s" % (hd.get("x-tap"), sorted(got)))

            # 2. /__config must report the binding, so a deployment cannot claim a
            # TLS tier it does not have.
            st, _, body = rig.get("/__config")
            c = sent(body) or {}
            r.check("tls: /__config reports the transport as bound",
                    c.get("tls_transport_bound") is True,
                    "tls_transport_bound=%r" % c.get("tls_transport_bound"))

            # 3. persona=chrome + engine=tls: the full claim, coherently.
            st, hd, body = rig.get("/https://origin.test/chrome",
                                   headers={"X-Proxy-Engine": "tls",
                                            "X-Proxy-Persona": "chrome",
                                            "User-Agent": "curl/8.22.0"})
            h = (sent(body) or {}).get("headers", {})
            ua = h.get("user-agent", "")
            major = ua.split("Chrome/", 1)[1].split(".", 1)[0] if "Chrome/" in ua else ""
            r.check("tls: persona=chrome with engine=tls claims Chrome to the origin",
                    "Chrome/" in ua and "curl" not in ua, "ua=%r" % ua[:56])
            r.check("tls: the chrome persona emits low-entropy client hints over https",
                    h.get("sec-ch-ua") is not None
                    and h.get("sec-ch-ua-platform") is not None,
                    "hdrs=%s" % sorted(h))
            # The one invariant that makes a claim useful: every number and every OS
            # in the set must agree. A UA saying Windows 10 beside a platform hint
            # saying macOS is a stronger tell than saying nothing at all.
            r.check("tls: sec-ch-ua major matches the UA's Chrome major",
                    major != "" and ('v="%s"' % major) in h.get("sec-ch-ua", ""),
                    "ua_major=%r sec-ch-ua=%r" % (major, h.get("sec-ch-ua", "")[:40]))
            r.check("tls: sec-ch-ua-platform matches the OS claimed in the UA",
                    "Windows" in ua and h.get("sec-ch-ua-platform") == '"Windows"',
                    "ua=%r platform=%r" % (ua[:40], h.get("sec-ch-ua-platform")))

            # 4. The secure-context gate, which the hints obey and which
            # upgrade-insecure-requests must obey too.
            st, hd, body = rig.get("/http://origin.test/plain",
                                   headers={"X-Proxy-Engine": "tls",
                                            "X-Proxy-Persona": "chrome",
                                            "User-Agent": "curl/8.22.0"})
            h = (sent(body) or {}).get("headers", {})
            r.check("tls: the chrome persona claims Chrome on a plaintext target too",
                    "Chrome/" in h.get("user-agent", ""),
                    "ua=%r" % h.get("user-agent", "")[:52])
            r.check("tls: NO client hints on a plaintext target (secure-context only)",
                    "sec-ch-ua" not in h and "sec-ch-ua-platform" not in h,
                    "hdrs=%s" % sorted(h))
            r.check("tls: NO upgrade-insecure-requests on a plaintext target",
                    "upgrade-insecure-requests" not in h, "hdrs=%s" % sorted(h))
            st, hd, body = rig.get("/https://origin.test/sec",
                                   headers={"X-Proxy-Engine": "tls",
                                            "X-Proxy-Persona": "chrome"})
            h = (sent(body) or {}).get("headers", {})
            r.check("tls: upgrade-insecure-requests IS sent on an https target",
                    h.get("upgrade-insecure-requests") == "1",
                    "value=%r" % h.get("upgrade-insecure-requests"))

            # 5. A bound transport does NOT by itself switch the persona on. The
            # claim stays opt-in, so flipping the persona to always-chrome fails here.
            st, hd, body = rig.get("/https://origin.test/edge",
                                   headers={"X-Proxy-Engine": "tls",
                                            "User-Agent": "curl/8.22.0"})
            h = (sent(body) or {}).get("headers", {})
            r.check("tls: engine=tls alone still uses the honest edge persona",
                    h.get("user-agent") == "Cloudflare-Workers" and "sec-ch-ua" not in h,
                    "ua=%r" % h.get("user-agent", ""))

            # 6. And the persona is gated on the ENGINE, not on transport
            # availability: with a transport bound but engine=fetch, the chrome
            # claim must not fire and the request must go down the runtime path.
            st, hd, body = rig.get("/https://origin.test/gated",
                                   headers={"X-Proxy-Persona": "chrome",
                                            "User-Agent": "curl/8.22.0"})
            seen = rig.seen(body) or {}
            h = seen.get("headers", {})
            r.check("tls: persona=chrome is ignored without engine=tls",
                    "Chrome" not in h.get("user-agent", ""),
                    "ua=%r" % h.get("user-agent", ""))
            r.check("tls: that ignored request went down the runtime fetch() path",
                    seen.get("url") == "https://origin.test/gated",
                    "tap url=%r" % seen.get("url"))

            # 7. persona=pass still works under the tls engine, unchanged.
            st, hd, body = rig.get("/https://origin.test/pass",
                                   headers={"X-Proxy-Engine": "tls",
                                            "X-Proxy-Persona": "pass",
                                            "User-Agent": "curl/8.22.0"})
            h = (sent(body) or {}).get("headers", {})
            r.check("tls: persona=pass under engine=tls forwards the caller's UA verbatim",
                    h.get("user-agent") == "curl/8.22.0",
                    "ua=%r" % h.get("user-agent", ""))

            # 8. The body contract. A POST on engine=tls reached the origin with no
            # payload at all while the origin answered 200, and the proxy reported
            # success. With supportsBody unset the request must be REFUSED, because
            # silently sending an empty POST is the failure and refusing is not.
            st, _, body = rig.post("/https://origin.test/write",
                                   headers={"X-Proxy-Engine": "tls"},
                                   body="payload=1")
            r.check("tls: a bodied request is REFUSED when the transport cannot send a body",
                    st == 501 and "supportsBody" in body,
                    "status=%s body=%r" % (st, body[:90]))

            # 9. A GET has no body, so the refusal above must not fire for it. If the
            # guard were written on method rather than on hasBody, this would 501
            # every GET and the engine would be unusable for the common case.
            st, _, body = rig.get("/https://origin.test/read",
                                  headers={"X-Proxy-Engine": "tls"})
            r.check("tls: a GET is NOT refused by the body guard",
                    st == 200 and (sent(body) or {}).get("transport") is True,
                    "status=%s" % st)

            # 10. /__config must report supportsBody separately from bound, so an
            # operator can tell a transport that cannot POST from one that can.
            st, _, body = rig.get("/__config")
            c = sent(body) or {}
            r.check("tls: /__config reports tls_transport_supports_body",
                    c.get("tls_transport_supports_body") is False,
                    "value=%r" % c.get("tls_transport_supports_body"))
    finally:
        shutil.rmtree(os.path.dirname(tmp), ignore_errors=True)
    return r


def probe_tls_body():
    """engine=tls WITH supportsBody: the body actually reaches the transport.

    probe_tls_engine proves the refusal. This proves the other half, and a guard
    that has only been seen to refuse is indistinguishable from one that refuses
    everything: the two cases together are what make supportsBody mean something.
    """
    print("\n=== E2. engine=tls with a body-capable transport ===")
    r = Results()
    with open(V2) as fh:
        text = fh.read()

    stub = (
        "\t\tenv = Object.assign({ TLS_TRANSPORT: {\n"
        "\t\t\tsupportsBody: true,\n"
        "\t\t\tasync fetch(url, init) {\n"
        "\t\t\t\tconst h = {};\n"
        "\t\t\t\tfor (const [k, v] of init.headers.entries()) h[k.toLowerCase()] = v;\n"
        "\t\t\t\tlet body = null;\n"
        "\t\t\t\tif (init.body != null) {\n"
        "\t\t\t\t\tbody = typeof init.body === 'string'\n"
        "\t\t\t\t\t\t? init.body\n"
        "\t\t\t\t\t\t: new TextDecoder().decode(init.body);\n"
        "\t\t\t\t}\n"
        "\t\t\t\tconst payload = { transport: true, url: String(url),\n"
        "\t\t\t\t\theaders: h, method: init.method, body: body,\n"
        "\t\t\t\t\tbody_len: body == null ? null : body.length,\n"
        "\t\t\t\t\thas_signal: !!(init && init.signal) };\n"
        "\t\t\t\treturn Promise.resolve(new Response(JSON.stringify(payload), {\n"
        "\t\t\t\t\tstatus: 200,\n"
        "\t\t\t\t\theaders: { 'content-type': 'application/json', 'x-tap': 'tls-body' },\n"
        "\t\t\t\t}));\n"
        "\t\t\t},\n"
        "\t\t} }, env || {});\n"
    )
    patched = text.replace(
        "async fetch(request, env) {", "async fetch(request, env) {\n" + stub, 1)
    if patched == text:
        r.check("tls-body: the fetch() signature is still patchable", False,
                "worker.js no longer matches 'async fetch(request, env) {'")
        return r
    tmp = os.path.join(tempfile.mkdtemp(prefix="v2-tlsbody-"), "worker.js")
    with open(tmp, "w") as fh:
        fh.write(patched)

    def sent(body):
        try:
            return json.loads(body)
        except Exception:
            return None

    try:
        with Rig(tmp, "tlsbody") as rig:
            st, hd, body = rig.post("/https://origin.test/write",
                                    headers={"X-Proxy-Engine": "tls"},
                                    body="key=value&n=2")
            got = sent(body) or {}
            r.check("tls-body: a POST is no longer refused when supportsBody is true",
                    st == 200 and got.get("transport") is True,
                    "status=%s x-tap=%r" % (st, hd.get("x-tap")))
            r.check("tls-body: the transport receives the method",
                    got.get("method") == "POST", "method=%r" % got.get("method"))
            r.check("tls-body: the transport receives the body bytes",
                    got.get("body") == "key=value&n=2",
                    "body=%r" % got.get("body"))
            r.check("tls-body: the body length is the full payload, not truncated",
                    got.get("body_len") == len("key=value&n=2"),
                    "len=%r" % got.get("body_len"))

            # A bodied GET is not possible, but a GET must not acquire a body.
            st, _, body = rig.get("/https://origin.test/read",
                                  headers={"X-Proxy-Engine": "tls"})
            got = sent(body) or {}
            r.check("tls-body: a GET carries no body to the transport",
                    got.get("method") == "GET" and got.get("body") is None,
                    "method=%r body=%r" % (got.get("method"), got.get("body")))

            # 307 must replay method AND body through the transport. hopBody is
            # derived from the buffer taken before hop 0, so a mutation that reads
            # the one-shot stream here would deliver nothing on the second hop.
            st, _, body = rig.post("/https://origin.test/replay",
                                   headers={"X-Proxy-Engine": "tls"},
                                   body="replay=yes")
            got = sent(body) or {}
            r.check("tls-body: the body survives to a 307 replay hop",
                    got.get("body") == "replay=yes" and got.get("method") == "POST",
                    "method=%r body=%r" % (got.get("method"), got.get("body")))
    finally:
        shutil.rmtree(os.path.dirname(tmp), ignore_errors=True)

    # CONTROL, and the negative half of the pair above. The same worker, the same
    # POST, with the flag explicitly FALSE rather than absent. Without this row a
    # proxy that always passed the body to the transport would pass every
    # assertion in this section, because the flag would never be read.
    neg = stub.replace("supportsBody: true", "supportsBody: false")
    if neg == stub:
        r.check("tls-body CONTROL: the supportsBody flag is still patchable", False,
                "stub text no longer contains 'supportsBody: true'")
        return r
    tmp2 = os.path.join(tempfile.mkdtemp(prefix="v2-tlsneg-"), "worker.js")
    with open(tmp2, "w") as fh:
        fh.write(text.replace("async fetch(request, env) {",
                              "async fetch(request, env) {\n" + neg, 1))
    try:
        with Rig(tmp2, "tlsneg") as rig:
            st, hd, body = rig.post("/https://origin.test/write",
                                    headers={"X-Proxy-Engine": "tls"},
                                    body="key=value&n=2")
            r.check("CONTROL: supportsBody=false REFUSES the POST that true delivered",
                    st == 501 and hd.get("x-tap") != "tls-body",
                    "status=%s x-tap=%r" % (st, hd.get("x-tap")))
            # The flag must decide on the body alone: the same GET still goes
            # through, so the guard is not simply refusing this transport.
            st, hd, body = rig.get("/https://origin.test/read",
                                   headers={"X-Proxy-Engine": "tls"})
            r.check("CONTROL: supportsBody=false still allows a GET on that transport",
                    st == 200 and hd.get("x-tap") == "tls-body",
                    "status=%s x-tap=%r" % (st, hd.get("x-tap")))
    finally:
        shutil.rmtree(os.path.dirname(tmp2), ignore_errors=True)
    return r


def probe_header_coverage():
    """Every constant in the header policy, driven by the request side.

    An earlier review found HOP_BY_HOP unpinned at 10/10 mutations and
    EDGE_IDENTITY at 13/16: every entry could be deleted and the whole suite
    stayed green. A list that nothing tests is a list that drifts. Each entry here
    is sent by the caller and must be absent from what the origin sees, and each
    one has a CONTROL proving the header reached the proxy at all, because a
    header the client failed to send would make its own absence meaningless.
    """
    print("\n=== J. header policy coverage: every entry pinned ===")
    r = Results()
    with Rig(V2, "cover") as rig:
        # RFC 9110 s7.6.1 connection-specific headers, plus host and
        # content-length, which the runtime derives from the URL.
        for name in ("connection", "keep-alive", "proxy-authenticate",
                     "proxy-authorization", "te", "trailer",
                     "upgrade", "host", "content-length"):
            st, _, body = rig.get("/https://origin.test/hdr", headers={name: "x"})
            seen = rig.seen(body) or {}
            h = seen.get("headers") or {}
            r.check("cover: hop-by-hop %s is not forwarded" % name,
                    st == 200 and name not in h,
                    "status=%s hdrs=%s" % (st, sorted(h)))

        # transfer-encoding needs its own case, because the generic loop above
        # sends the value "x" and workerd rejects THAT during HTTP parsing with a
        # 500 before the Worker is dispatched. A first pass at this section read
        # that 500 as proof the header could never reach the worker, and wrote a
        # row asserting the refusal instead of the drop. That was wrong: the
        # rejection is specific to a malformed value, `chunked` parses fine and
        # dispatches, and removing the entry from HOP_BY_HOP then forwards it.
        # Measured: original forwards None, mutant forwards 'chunked'.
        st, _, body = rig.get("/https://origin.test/hdr",
                              headers={"Transfer-Encoding": "chunked"})
        seen = rig.seen(body) or {}
        h = seen.get("headers") or {}
        r.check("cover: a well-formed transfer-encoding is not forwarded",
                st == 200 and "transfer-encoding" not in h,
                "status=%s hdrs=%s" % (st, sorted(h)))

        # The CONTROL that makes the row above mean what it claims. A worker whose
        # only defence was workerd's parser would also show nothing forwarded, so
        # this pins that the PROXY's own list is what drops it: without the entry
        # the value reaches the origin.
        with open(V2) as fh:
            src = fh.read()
        mutant = src.replace('\t"transfer-encoding",\n', "", 1)
        if mutant != src:
            d = tempfile.mkdtemp(prefix="v2-temut-")
            p2 = os.path.join(d, "worker.js")
            with open(p2, "w") as fh:
                fh.write(mutant)
            try:
                with Rig(p2, "temut") as rig2:
                    st, _, body = rig2.get("/https://origin.test/hdr",
                                           headers={"Transfer-Encoding": "chunked"})
                    seen = rig2.seen(body) or {}
                    h = seen.get("headers") or {}
                    r.check("CONTROL: without the HOP_BY_HOP entry, transfer-encoding IS forwarded",
                            st == 200 and h.get("transfer-encoding") == "chunked",
                            "forwarded=%r" % h.get("transfer-encoding"))
            finally:
                shutil.rmtree(d, ignore_errors=True)
        else:
            r.check("CONTROL: the HOP_BY_HOP transfer-encoding entry is patchable",
                    False, "could not remove '\\t\"transfer-encoding\",\\n' from v2.js")

        # Headers that identify the request as having come through a proxy or a
        # CDN edge. Also the control headers the proxy owns and must not let a
        # caller set.
        for name in ("x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
                     "x-forwarded-server", "x-real-ip", "cf-connecting-ip",
                     "cf-ipcountry", "cf-ray", "cf-visitor", "cf-worker",
                     "cf-ew-via", "cf-ew-preview-server", "cdn-loop",
                     "x-cors-headers", "x-proxy-key", "x-proxy-forward-cookies",
                     "x-proxy-accept-language", "x-proxy-timeout-ms",
                     "x-proxy-engine", "x-proxy-persona"):
            st, _, body = rig.get("/https://origin.test/hdr", headers={name: "x"})
            seen = rig.seen(body) or {}
            h = seen.get("headers") or {}
            r.check("cover: edge identity %s is not forwarded" % name,
                    st == 200 and name not in h,
                    "status=%s hdrs=%s" % (st, sorted(h)))

        # The caller's Origin and every sec-fetch-* describe the caller's page,
        # not the request being made on its behalf. Forwarding them tells the
        # origin something about a browser navigation that never happened.
        for name in ("origin", "sec-fetch-site", "sec-fetch-mode",
                     "sec-fetch-dest", "sec-fetch-user"):
            st, _, body = rig.get("/https://origin.test/hdr",
                                  headers={name: "https://caller.test/page"})
            seen = rig.seen(body) or {}
            h = seen.get("headers") or {}
            r.check("cover: caller context %s is not forwarded" % name,
                    st == 200 and name not in h,
                    "status=%s hdrs=%s" % (st, sorted(h)))

        # authorization is the proxy's OWN credential. Forwarding it hands
        # AUTH_TOKEN to every third-party origin.
        st, _, body = rig.get("/https://origin.test/hdr",
                              headers={"Authorization": "Bearer s3cret"})
        seen = rig.seen(body) or {}
        h = seen.get("headers") or {}
        r.check("cover: the caller's Authorization is not forwarded upstream",
                st == 200 and "authorization" not in h and "Bearer" not in json.dumps(h),
                "hdrs=%s" % sorted(h))

        # CONTROL for the Authorization row above, and for the whole OWNED_HEADERS
        # idea: a header that is NOT in the list does reach the origin. Without
        # this, a proxy that stripped every header would pass all of section J.
        st, _, body = rig.get("/https://origin.test/hdr",
                              headers={"X-Custom-Thing": "kept"})
        seen = rig.seen(body) or {}
        h = seen.get("headers") or {}
        r.check("CONTROL: an ordinary custom header IS forwarded",
                st == 200 and h.get("x-custom-thing") == "kept",
                "hdrs=%s" % sorted(h))

        # Every looksLikeBotTool substring, each with a UA that must be replaced.
        for label, ua in (
            ("curl", "curl/8.22.0"),
            ("wget", "Wget/1.21"),
            ("python-requests", "python-requests/2.32.0"),
            ("python-urllib", "Python-urllib/3.11"),
            ("go-http-client", "Go-http-client/2.0"),
            ("java", "Java/21.0.1"),
            ("okhttp", "okhttp/4.12.0"),
            ("axios", "axios/1.7.0"),
            ("node-fetch", "node-fetch/1.0"),
            ("httpie", "HTTPie/3.2"),
            ("libwww-perl", "libwww-perl/6.72"),
            ("scrapy", "Scrapy/2.11"),
            ("under ten characters", "abc"),
            ("empty", ""),
        ):
            st, _, body = rig.get("/https://origin.test/ua",
                                  headers={"User-Agent": ua})
            seen = rig.seen(body) or {}
            got = (seen.get("headers") or {}).get("user-agent", "")
            r.check("cover: a %s user-agent is replaced with the edge identity" % label,
                    st == 200 and got == "Cloudflare-Workers",
                    "ua=%r -> %r" % (ua[:24], got[:40]))

        # A real browser UA is NOT a bot tool and must survive verbatim. This is
        # the CONTROL that makes the twelve rows above mean anything.
        REAL = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
        st, _, body = rig.get("/https://origin.test/ua",
                              headers={"User-Agent": REAL})
        seen = rig.seen(body) or {}
        got = (seen.get("headers") or {}).get("user-agent", "")
        r.check("CONTROL: a real browser user-agent is forwarded verbatim",
                st == 200 and got == REAL, "ua=%r" % got[:60])

        # The coherence invariant: when the proxy REPLACES the UA it must also
        # drop the caller's Client Hints, or the origin sees a rewritten identity
        # beside hints that contradict it. Every hint in CLIENT_HINTS, and the
        # CONTROL that a caller's hints DO survive when its own UA is forwarded.
        for name in ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                     "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model",
                     "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
                     "sec-ch-ua-platform-version", "sec-ch-ua-wow64"):
            st, _, body = rig.get("/https://origin.test/hints",
                                  headers={"User-Agent": "curl/8.22.0",
                                           name: '"something"'})
            seen = rig.seen(body) or {}
            h = seen.get("headers") or {}
            r.check("cover: %s is dropped when the proxy rewrites the identity" % name,
                    st == 200 and name not in h,
                    "hdrs=%s" % sorted(h))

        st, _, body = rig.get("/https://origin.test/hints",
                              headers={"User-Agent": REAL,
                                       "sec-ch-ua-platform": '"macOS"'})
        seen = rig.seen(body) or {}
        h = seen.get("headers") or {}
        r.check("CONTROL: the caller's hints survive when its own identity is forwarded",
                st == 200 and h.get("sec-ch-ua-platform") == '"macOS"'
                and h.get("user-agent") == REAL,
                "hdrs=%s" % sorted(h))

        # persona=chrome WITHOUT engine=tls. The chrome branch cannot fire, so the
        # UA falls through to the edge identity. The caller's hints must go with
        # it: an earlier version computed overridesIdentity as
        # `persona === "edge" && looksLikeBotTool(ua)`, which is false here, so a
        # rewritten UA sat beside the caller's Client Hints.
        st, _, body = rig.get("/https://origin.test/coherence",
                              headers={"X-Proxy-Persona": "chrome",
                                       "User-Agent": "curl/8.22.0",
                                       "sec-ch-ua-platform": '"macOS"'})
        seen = rig.seen(body) or {}
        h = seen.get("headers") or {}
        r.check("cover: persona=chrome without engine=tls stays coherent",
                st == 200 and h.get("user-agent") == "Cloudflare-Workers"
                and "sec-ch-ua-platform" not in h,
                "hdrs=%s" % sorted(h))
    return r


def probe_cors_static():
    """The CORS preflight contract, header by header.

    A preflight passes only if the header the browser is about to send is listed
    in access-control-allow-headers. An omission there does not degrade
    gracefully: it makes the feature unreachable from a browser caller, which is
    the entire reason a CORS proxy exists.
    """
    print("\n=== K. CORS preflight contract ===")
    r = Results()
    with Rig(V2, "cors") as rig:
        st, hd, _ = rig.get("/", method="OPTIONS",
                            headers={"Origin": "https://caller.test"})
        r.check("cors: a preflight is answered with 204", st == 204, "status=%s" % st)
        r.check("cors: a preflight reflects the caller's Origin",
                hd.get("access-control-allow-origin") == "https://caller.test",
                "acao=%r" % hd.get("access-control-allow-origin"))
        for m in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            r.check("cors: allow-methods includes %s" % m,
                    m in (hd.get("access-control-allow-methods") or ""),
                    "value=%r" % hd.get("access-control-allow-methods"))
        allowed = (hd.get("access-control-allow-headers") or "").lower()
        for hname in ("authorization", "content-type", "accept",
                      "accept-language", "user-agent", "x-proxy-key",
                      "x-proxy-accept-language", "x-proxy-forward-cookies",
                      "x-proxy-engine", "x-proxy-persona", "x-proxy-timeout-ms"):
            r.check("cors: allow-headers includes %s" % hname,
                    hname in allowed, "value=%r" % hd.get("access-control-allow-headers"))
        r.check("cors: max-age is advertised",
                (hd.get("access-control-max-age") or "") == "86400",
                "value=%r" % hd.get("access-control-max-age"))
        # The header set the proxy actually READS, pinned against the advertised
        # list. This is the row that would have caught X-Proxy-Engine,
        # X-Proxy-Persona and X-Proxy-Timeout-Ms all being absent.
        with open(V2) as fh:
            src = fh.read()
        read = set()
        for m in re.finditer(r'(?:request|incoming)\.headers\.get\("([^"]+)"\)', src):
            read.add(m.group(1).lower())
        read.discard("__cfg")
        missing = sorted(n for n in read
                         if n.startswith("x-proxy") and n not in allowed)
        r.check("cors: every X-Proxy-* header the worker reads is advertised",
                missing == [], "read but not advertised: %r" % missing)
        # The proxy never advertises credentialed CORS, because it reflects
        # Origin against an open target list. A future edit adding ACAC here would
        # turn any site into a reader of a user's authenticated responses.
        r.check("cors: credentials are NOT enabled on a reflected origin",
                hd.get("access-control-allow-credentials") is None,
                "value=%r" % hd.get("access-control-allow-credentials"))
    return r


def probe_hostlist():
    """The ALLOWED_HOSTS comma-split contract, with realistic spacing.

    README.md and RESEARCH.md section 9 both tell an operator to write
    `ALLOWED_HOSTS = "example.com,githubusercontent.com"`. Every other test
    injects a single clean host, so the split was never exercised: replacing
    `raw.split(",").map(s => s.trim())` with `[raw]` passed the whole suite, and a
    deployment following the documented config would get an allowlist containing
    the literal string "example.com,githubusercontent.com", which matches nothing
    and 403s everything.
    """
    print("\n=== F. ALLOWED_HOSTS parsing (comma-separated, as documented) ===")
    r = Results()
    with open(V2) as fh:
        text = fh.read()

    def build(value, token=None):
        injected = ("AUTH_TOKEN: %r, ALLOWED_HOSTS: %r" % (token, value)) if token \
            else ("ALLOWED_HOSTS: %r" % value)
        patched = text.replace(
            "async fetch(request, env) {",
            "async fetch(request, env) {\n\t\t// injected by test_proxy.probe_hostlist\n"
            "\t\tenv = Object.assign({ %s }, env || {});" % injected,
            1,
        )
        d = tempfile.mkdtemp(prefix="v2-hosts-")
        path = os.path.join(d, "worker.js")
        with open(path, "w") as fh:
            fh.write(patched)
        return d, path

    # Spaces after the commas, exactly as a human types it.
    d, path = build("origin.test, other.test", token="s3cret")
    AUTH = {"X-Proxy-Key": "s3cret"}
    try:
        with Rig(path, "hosts") as rig:
            st, _, body = rig.get("/__config", headers=AUTH)
            hosts = json.loads(body).get("allowed_hosts")
            r.check("hosts: splits ALLOWED_HOSTS on commas",
                    hosts == ["origin.test", "other.test"], "value=%r" % hosts)
            # The behavioural consequence, which is what a wrong parser causes.
            st, _, _ = rig.get("/https://origin.test/a", headers=AUTH)
            r.check("hosts: the FIRST host in the list is reachable", st == 200,
                    "status=%s" % st)
            st, _, _ = rig.get("/https://other.test/b", headers=AUTH)
            r.check("hosts: the SECOND host in the list is reachable", st == 200,
                    "status=%s" % st)
            st, _, _ = rig.get("/https://notlisted.test/c", headers=AUTH)
            r.check("hosts: a host in neither position is still refused", st == 403,
                    "status=%s" % st)
            # A subdomain of the SECOND entry proves the trailing element was
            # trimmed and not left as " other.test".
            st, _, _ = rig.get("/https://sub.other.test/d", headers=AUTH)
            r.check("hosts: a subdomain of the second host is permitted", st == 200,
                    "status=%s" % st)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # The empty and whitespace-only forms mean "no allowlist", which is the
    # open-proxy default and the reason /__config reports the effective list.
    for label, value in (("empty", ""), ("whitespace only", "   "),
                         ("bare commas", " , , ")):
        d, path = build(value)
        try:
            with Rig(path, "hosts2") as rig:
                st, _, body = rig.get("/__config")
                hosts = json.loads(body or "{}").get("allowed_hosts")
                r.check("hosts: an %s ALLOWED_HOSTS means no allowlist" % label,
                        hosts == [], "value=%r" % hosts)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # An entry carrying a port. `url.hostname` never contains one, so an entry
    # that keeps its port matches nothing at all: a deployment that wrote
    # `origin.test:8443` got an allowlist that permitted nothing and 403ed every
    # request including the one it named. The entry's port is ignored, which is
    # a stated limit rather than a silent ban.
    d, path = build("origin.test:8443")
    try:
        with Rig(path, "hosts3") as rig:
            st, _, _ = rig.get("/https://origin.test/a")
            r.check("hosts: a port in an ALLOWED_HOSTS entry does not ban that host",
                    st == 200, "status=%s" % st)
            st, _, _ = rig.get("/https://sub.origin.test/b")
            r.check("hosts: subdomain matching works with a port in the entry",
                    st == 200, "status=%s" % st)
            st, _, _ = rig.get("/https://notlisted.test/c")
            r.check("hosts: a port in an entry does not widen the list",
                    st == 403, "status=%s" % st)
            # The listed form of the limit, so an operator can see it rather than
            # infer it: port restriction is not available on this path.
            st, _, body = rig.get("/__config")
            note = json.loads(body or "{}").get("allowed_hosts_match") or ""
            r.check("hosts: /__config states that matching ignores ports",
                    "port" in note.lower(), "value=%r" % note)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return r


def probe_redirect_scope():
    """Cookie consent across a redirect, and the Location rewrite.

    Two defects the earlier suite could not see, both in the same hop.

    Cookie consent is per request and a request names one host. It was checked
    once, against the first hop, so a 302 to a different host carried the
    caller's Cookie header with it: a session token delivered to whatever host an
    origin chose to name. That is the leak the opt-in exists to bound, so the
    opt-in was not bounding it.

    `rewriteLocation` had no base URL. A relative or protocol-relative Location
    could not be resolved, so it was returned verbatim and the client left the
    proxy. A 201 carrying a relative Location is ordinary REST behaviour.
    """
    print("\n=== G. redirect scoping: cookies and Location ===")
    r = Results()
    with Rig(V2, "redir") as rig:
        COOK = {"X-Proxy-Forward-Cookies": "1", "Cookie": "session=SUPERSECRET"}

        # 1. Consent is scoped to the host the caller named. The redirect target
        # is a different host, so the cookie must not follow.
        #
        # rig.seen() reports the LAST hop, so this row cannot observe hop 0
        # directly. The positive half is the same-host redirect below, which lands
        # on origin.test and does show the cookie. Both halves are needed: the
        # negative alone is also what a proxy that never forwards cookies at all
        # would produce.
        st, _, body = rig.get(
            "/https://origin.test/__ctl/crosshost?to=https%3A%2F%2Fother.test%2F__ctl%2Fecho",
            headers=COOK)
        hop = rig.seen(body) or {}
        got = json.dumps(hop.get("headers") or {})
        r.check("redirect: the request reached the OTHER host (the redirect was followed)",
                (hop.get("url") or "").startswith("https://other.test/"),
                "hop url=%r" % hop.get("url"))
        r.check("redirect: the cookie does NOT follow a redirect to another host",
                "SUPERSECRET" not in got, "cookie present=%r" % ("SUPERSECRET" in got))
        # CONTROL for the row above: the same request WITHOUT consent never sends
        # the cookie at all. Without this pair a proxy that dropped cookies
        # everywhere would pass the scoping row with the opt-in dead.
        st, _, body = rig.get(
            "/https://origin.test/__ctl/crosshost?to=https%3A%2F%2Fother.test%2F__ctl%2Fecho")
        hop = rig.seen(body) or {}
        got = json.dumps(hop.get("headers") or {})
        r.check("CONTROL: no consent means no cookie on the FINAL hop either",
                "SUPERSECRET" not in got, "cookie present=%r" % ("SUPERSECRET" in got))

        # 2. Consent SURVIVES a same-host redirect, and this is also the positive
        # half of row 1: it shows consent forwards the cookie when it applies.
        st, _, body = rig.get(
            "/https://origin.test/__ctl/samehost?to=%2F__ctl%2Fecho", headers=COOK)
        hop = rig.seen(body) or {}
        r.check("redirect: the cookie IS forwarded when consent applies (same host)",
                "SUPERSECRET" in json.dumps(hop.get("headers") or {}),
                "hdrs=%s" % sorted((hop.get("headers") or {})))

        # 3. A redirect back to the host the caller named: consent applies again,
        # because the chain is back inside the consented scope.
        st, _, body = rig.get(
            "/https://origin.test/__ctl/crosshost?to=https%3A%2F%2Forigin.test%2F__ctl%2Fecho",
            headers=COOK)
        hop = rig.seen(body) or {}
        r.check("redirect: consent returns on a redirect back to the named host",
                "SUPERSECRET" in json.dumps(hop.get("headers") or {}),
                "hdrs=%s" % sorted((hop.get("headers") or {})))

        # 4. A 304 is not a redirect. Its Location names the selected
        # representation for a conditional request (RFC 9110 s15.4.5) and 304 has
        # no body, so consuming it as a hop discarded the client's conditional
        # headers and answered with a bodyless 200.
        st, hd, _ = rig.get("/https://origin.test/__ctl/notmodified")
        r.check("redirect: a 304 is returned to the client, not followed",
                st == 304, "status=%s" % st)
        r.check("redirect: the 304 keeps its Location, resolved into proxy space",
                (hd.get("location") or "").startswith("http://proxy.local/https://origin.test/"),
                "location=%r" % hd.get("location"))

        # 5. A relative Location on a NON-3xx. The redirect loop never sees this,
        # so rewriteLocation is the only thing that can handle it.
        st, hd, _ = rig.get("/https://origin.test/__ctl/location201")
        r.check("redirect: a Location on a 201 is rewritten into proxy space",
                (hd.get("location") or "").startswith("http://proxy.local/https://thirdparty.test/"),
                "location=%r" % hd.get("location"))
        r.check("redirect: the 201 status itself is preserved", st == 201,
                "status=%s" % st)

        # 6. A relative Location on a 3xx is resolved against the base for the
        # hop, so the follow lands on the origin's own relative target.
        st, hd, body = rig.get(
            "/https://origin.test/__ctl/relredirect?to=%2F__ctl%2Frelative-target")
        r.check("redirect: a relative Location is followed to the origin's target",
                st == 200 and hd.get("x-tap") == "rel-target",
                "status=%s x-tap=%r" % (st, hd.get("x-tap")))

        # 7. A protocol-relative Location, `//host/path`. `new URL(x)` reads the
        # host out of this shape, so a rewrite without a base hands the client a
        # URL that bypasses the proxy entirely.
        st, _, body = rig.get(
            "/https://origin.test/__ctl/redirect?code=302&to=%2F%2Fother.test%2F__ctl%2Fecho")
        hop = rig.seen(body) or {}
        r.check("redirect: a protocol-relative Location resolves against the hop",
                (hop.get("url") or "").startswith("https://other.test/"),
                "hop url=%r" % hop.get("url"))
    return r


def probe_response_edges():
    """Vary and WWW-Authenticate.

    Two smaller gaps, both found by reading rather than by a failing test.
    """
    print("\n=== I. response header edges ===")
    r = Results()
    with Rig(V2, "edges") as rig:
        # Vary: * is not a list. Appending produces "*, Origin", which
        # RFC 9110 s5.2.2 does not define and caches cannot parse.
        st, hd, _ = rig.get("/https://origin.test/__ctl/varystar")
        r.check("vary: an upstream Vary: * is left alone, not turned into '*, Origin'",
                hd.get("vary") == "*", "vary=%r" % hd.get("vary"))

        # A normal Vary still gets Origin appended, which is the reason the code
        # appends rather than clobbers. CONTROL for the row above.
        st, hd, _ = rig.get("/https://origin.test/__ctl/hdrs")
        r.check("CONTROL: a normal upstream Vary DOES get Origin appended",
                hd.get("vary") == "Accept-Encoding, Origin",
                "vary=%r" % hd.get("vary"))

        # RFC 9110 s15.5.2 makes WWW-Authenticate REQUIRED on a 401.
        d = tempfile.mkdtemp(prefix="v2-401-")
        path = os.path.join(d, "worker.js")
        with open(V2) as fh:
            text = fh.read()
        with open(path, "w") as fh:
            fh.write(text.replace(
                "async fetch(request, env) {",
                "async fetch(request, env) {\n\t\tenv = Object.assign({ AUTH_TOKEN: 'k' }, env || {});",
                1))
        try:
            with Rig(path, "auth401") as rig:
                st, hd, _ = rig.get("/https://origin.test/x")
                r.check("401: a refusal carries WWW-Authenticate (RFC 9110 s15.5.2)",
                        st == 401 and "bearer" in (hd.get("www-authenticate") or "").lower(),
                        "status=%s hdr=%r" % (st, hd.get("www-authenticate")))
                # CONTROL: an authenticated request must NOT carry the challenge,
                # or the proxy advertises a credential it did not ask for.
                st, hd, _ = rig.get("/https://origin.test/x",
                                    headers={"X-Proxy-Key": "k"})
                r.check("CONTROL: an authenticated 200 carries no WWW-Authenticate",
                        st == 200 and hd.get("www-authenticate") is None,
                        "status=%s hdr=%r" % (st, hd.get("www-authenticate")))
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return r


def main():
    print("api.rv harness -- real workerd runtime, AF_UNIX transport, no TCP, no internet")
    print("v1 source: %s" % V1)
    print("v2 source: %s" % V2)

    v1 = probe_v1()
    v2 = probe_v2()
    auth = probe_auth()
    tls = probe_tls_engine()
    tlsb = probe_tls_body()
    hosts = probe_hostlist()
    redir = probe_redirect_scope()
    edges = probe_response_edges()
    cover = probe_header_coverage()
    cors = probe_cors_static()

    # Every control row in the suite, wherever it lives. A control row asserts
    # that a KNOWN defect or a KNOWN branch-selector IS present, so it is valid
    # when it PASSES. Scoping this to one section's results (as an earlier
    # revision did) let a failing control elsewhere print VALID.
    controls = (
        [row for row in v1.rows if row[0].startswith("NEG-CONTROL")]
        + [row for row in v2.rows if row[0].startswith("CONTROL")]
        + [row for row in tls.rows if row[0].startswith("CONTROL")]
        + [row for row in tlsb.rows if row[0].startswith("CONTROL")]
        + [row for row in redir.rows if row[0].startswith("CONTROL")]
        + [row for row in edges.rows if row[0].startswith("CONTROL")]
        + [row for row in cover.rows if row[0].startswith("CONTROL")]
        + [row for row in cors.rows if row[0].startswith("CONTROL")]
    )
    controls_ok = bool(controls) and all(row[1] for row in controls)

    print("\n=== HARNESS VALIDATION (negative control) ===")
    if controls_ok:
        print("  VALID: all %d control assertions fired." % len(controls))
        print("         The harness does observe real defects, so the v2 results below"
              " are meaningful.")
    else:
        bad = [r[0] for r in controls if not r[1]]
        print("  INVALID: %d/%d control assertions did NOT fire."
              % (len(bad), len(controls)))
        for name in bad:
            print("           did not detect: %s" % name)
        print("           The harness is not measuring what it claims, so the v2")
        print("           results below prove nothing.")

    v2_ok = v2.summary("v2")
    auth_ok = auth.summary("auth + allowlist")
    tls_ok = tls.summary("engine=tls + chrome persona")
    tlsb_ok = tlsb.summary("engine=tls body contract")
    hosts_ok = hosts.summary("ALLOWED_HOSTS parsing")
    redir_ok = redir.summary("redirect scoping: cookies and Location")
    edges_ok = edges.summary("response header edges")
    cover_ok = cover.summary("header policy coverage")
    cors_ok = cors.summary("CORS preflight contract")
    ok = (v2_ok and auth_ok and tls_ok and tlsb_ok and hosts_ok
          and redir_ok and edges_ok and cover_ok and cors_ok and controls_ok)
    print("\nOVERALL: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())