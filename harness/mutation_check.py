#!/usr/bin/env python3
"""
Mutation check: deliberately break one invariant in v2 and confirm the suite
catches it.

The negative control in test_proxy.py proves the harness detects defects that
already exist in v1. That does NOT prove it would detect a regression introduced
into v2. This script closes that gap: it applies a single textual mutation to
v2.js, runs the full suite against the variant, and requires the suite to FAIL.

A mutation that survives means an assertion is not pinning the invariant it
claims to. Each mutation below removes exactly one behaviour.

Run: python3 harness/mutation_check.py
Exit: 0 = every mutation caught, 1 = at least one survived or a pattern is stale
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
V2 = os.path.join(ROOT, "rig", "v2.js")
SUITE = os.path.join(HERE, "test_proxy.py")

with open(V2) as fh:
    ORIGINAL = fh.read()

# (name, pattern, replacement, invariant it removes)
MUTATIONS = [
    (
        "cookie privacy",
        r'\t\tif \(lower === "cookie" && !forwardCookies\) continue;',
        '\t\tif (lower === "cookie") continue;',
        "cookie forwarding even when explicitly opted in",
    ),
    (
        "query string preservation",
        r'return validateTarget\(decoded \+ incoming\.search, allowedHosts\);',
        'return validateTarget(decoded, allowedHosts);',
        "the target query string (the v1 defect)",
    ),
    (
        "SSRF guard",
        r'\tif \(isBlockedHost\(url\.hostname\)\) \{\n\t\treturn \{ ok: false, status: 403, message: "Target host is blocked" \};\n\t\}',
        '',
        "the cloud-metadata / loopback target block",
    ),
    (
        "CORS",
        r'\theaders\.set\("access-control-allow-origin", request\.headers\.get\("origin"\) \|\| "\*"\);',
        '',
        "Access-Control-Allow-Origin (the v1 defect)",
    ),
    (
        "client hint consistency",
        r'\t\t\theaders\.set\("sec-ch-ua-platform", SEC_CH_UA_PLATFORM\);\n',
        '',
        "sec-ch-ua-platform, leaving it inconsistent with the UA OS",
    ),
    (
        "edge header stripping",
        r'\t\tif \(HOP_BY_HOP\.has\(lower\) \|\| EDGE_IDENTITY\.has\(lower\) \|\| OWNED_HEADERS\.has\(lower\)\) continue;',
        '\t\tif (HOP_BY_HOP.has(lower) || OWNED_HEADERS.has(lower)) continue;',
        "stripping X-Forwarded-For and the other edge identity headers",
    ),
    (
        "referer rewrite",
        r'\tif \(incoming\.has\("referer"\)\) \{\n\t\theaders\.set\("referer", target\.origin \+ "/"\);\n\t\}',
        '',
        "rewriting the caller's Referer to the target origin",
    ),
    (
        # NOTE: anchored to the CALL SITE, not the function name. A bare
        # `looksLikeBotTool(ua)` substitution also rewrites the declaration
        # `function looksLikeBotTool(ua)`, yielding `function true {`, a syntax
        # error. The suite then fails for the wrong reason and the mutation looks
        # "caught" while pinning nothing. Same trap for `if (transport)`: the word
        # appears in comments and in the /__config dump.
        #
        # Re-anchored twice, once when the call site stopped being an `if` and
        # again when the persona rewrite moved it into a condition chain. It is
        # written against the current shape and re-checked on every run rather
        # than trusted; a stale pattern here shows up as a SURVIVOR, not a silent
        # pass, because prepare() reports PATTERN DID NOT MATCH separately.
        "genuine UA passthrough",
        r'\} else if \(persona === "pass" \|\| !looksLikeBotTool\(ua\)\) \{',
        '} else if (persona === "pass") {',
        "passing a genuine browser UA through unchanged (always overrides)",
    ),
    (
        "preflight CORS",
        r'\t\t\treturn new Response\(null, \{ status: 204, headers: preflight \}\);',
        '\t\t\treturn new Response(null, { status: 204, headers: CORS_STATIC });',
        "Access-Control-Allow-Origin on the preflight, which is v1's defect again",
    ),
    (
        "credential stripping",
        r'const OWNED_HEADERS = new Set\(\["user-agent", "authorization", "proxy-authorization"\]\);',
        'const OWNED_HEADERS = new Set(["user-agent"]);',
        "forwarding the caller's Authorization header to third-party origins",
    ),
    (
        "IPv6 host normalisation",
        r'\tif \(s\.startsWith\("\["\) && s\.endsWith\("\]"\)\) \{',
        '\tif (false) {',
        "the IPv6 bracket/hex normalisation that blocks ::ffff: metadata",
    ),
    (
        "private-range blocking",
        r'\t\ta === 0 \|\|                                   // 0\.0\.0\.0/8, "this network"\n'
        r'\t\ta === 10 \|\|                                  // RFC 1918\n'
        r'\t\ta === 127 \|\|                                 // loopback\n',
        '\t\tfalse ||\n',
        "blocking RFC1918 and loopback IPv4 ranges",
    ),
    (
        "307/308 replay",
        r'\t\t\t\tresponse\.status === 307 \|\|\n\t\t\t\tresponse\.status === 308;',
        '\t\t\tfalse;',
        "replaying method and body across a 307/308",
    ),
    (
        "Set-Cookie integrity",
        r'\tif \(typeof upstream\.getSetCookie === "function"\) \{',
        '\tif (false) {',
        "keeping repeated Set-Cookie headers separate instead of comma-joined",
    ),
    (
        # Anchored to the LIST CONTENTS, not the Set constructor's shape. The set
        # became multi-line when ACAC was added to it, so a pattern matching
        # `new Set(["transfer-encoding"])` silently stopped matching and this
        # mutation reported as a survivor rather than as a stale pattern.
        "content-encoding preservation",
        r'\t"transfer-encoding",\n',
        '\t"transfer-encoding", "content-encoding", "content-length",\n',
        "preserving content-encoding, the v1 response-corruption fix",
    ),
    (
        "Vary append",
        r'headers\.set\("vary", existing \? `\$\{existing\}, Origin` : "Origin"\);',
        'headers.set("vary", "Origin");',
        "appending to the origin's Vary instead of clobbering it",
    ),
    (
        "plaintext client hints",
        r'\t\tif \(target\.protocol === "https:"\) \{',
        '\t\tif (true) {',
        "withholding Client Hints, and Upgrade-Insecure-Requests, from plaintext http targets",
    ),
    # --- engine=tls and the persona model (added with the Layer 1 correction) ---
    (
        # The honest default. Setting EDGE_UA to the Chrome string makes the
        # default persona claim a browser over workerd's own handshake, which is
        # the incumbent's loudest tell (proofs/01 measures it).
        "edge persona honesty",
        r'const EDGE_UA = "Cloudflare-Workers";',
        'const EDGE_UA = CHROME_UA;',
        "the default UA describing the transport instead of claiming Chrome",
    ),
    (
        # Routing, not just gating: with the branch disabled, engine=tls silently
        # serves the runtime fetch() path, which is exactly the silent fallback the
        # 501 exists to prevent.
        "tls engine routing",
        r'\t\t\t\tif \(transport\) \{',
        '\t\t\t\tif (false) {',
        "sending engine=tls requests through the bound transport",
    ),
    (
        "engine=tls 501",
        r'\t\tif \(engine === ENGINE_TLS && \(!transport \|\| typeof transport\.fetch !== "function"\)\) \{',
        '\t\tif (false) {',
        "the 501 when engine=tls is asked for with no transport bound",
    ),
    (
        # The persona is gated on the ENGINE. Ungating it makes any caller able to
        # claim Chrome over the runtime handshake, with no transport involved.
        "chrome persona gating",
        r'const chromePersona = persona === "chrome" && requestedEngine\(request\) === ENGINE_TLS;',
        'const chromePersona = persona === "chrome";',
        "requiring engine=tls before the Chrome persona may claim Chrome",
    ),
    (
        "secure-context upgrade header",
        r'\t\t\theaders\.set\("upgrade-insecure-requests", "1"\);\n',
        '',
        "Upgrade-Insecure-Requests on an https target, which a real Chrome sends",
    ),
    (
        # x-proxy-engine and x-proxy-persona are ours. Forwarding them hands the
        # origin a control channel back through the proxy.
        "engine header not forwarded",
        r'\t"x-proxy-engine",\n\t"x-proxy-persona",\n',
        '',
        "stripping the X-Proxy-Engine and X-Proxy-Persona headers from the caller",
    ),
    (
        "allowlist label boundary",
        r'return host === want \|\| host\.endsWith\("\." \+ want\);',
        'return host === want || host.endsWith(want);',
        "the label boundary that stops evil-example.com matching example.com",
    ),
    # --- round 2: ten defects the review rounds found, one invariant each ---
    # Each of these survived the suite before its assertion existed. They are here
    # so the next person does not have to rediscover that a passing suite says
    # nothing about an invariant nothing asserts.
    (
        # v1 leaked Referer and cookies; Origin was the remaining one, and the CORS
        # headers this proxy adds made a relayed request look first-party.
        "caller Origin not forwarded",
        r'\t"origin",\n\t"sec-fetch-site",',
        '\t"sec-fetch-site",',
        "not forwarding the caller's Origin and sec-fetch-* to a third party",
    ),
    (
        # Only the high-entropy hints were stripped, leaving the origin holding the
        # caller's `sec-ch-ua-platform: "macOS"` beside this proxy's own UA.
        "caller Client Hints not forwarded",
        r'if \(overridesIdentity && CLIENT_HINTS\.includes\(lower\)\) continue;',
        '',
        "dropping every caller Client Hint when the User-Agent is replaced",
    ),
    (
        # The v4 rules moved into isBlockedV4() when the 6to4 path needed to ask
        # them the same question about an address unpacked out of an IPv6 one.
        "CGNAT and reserved ranges",
        r'\t\t\(a === 100 && b >= 64 && b <= 127\) \|\|        // RFC 6598 CGNAT\n',
        '',
        "blocking RFC 6598 100.64/10, which is not publicly routable either",
    ),
    (
        # 2002:a9fe:a9fe:: is 169.254.169.254 and 2002:7f00:1:: is 127.0.0.1.
        # With the v4 rules consulted only on the dotted-quad form, a 6to4 address
        # reached the metadata endpoint and loopback with the guard switched off,
        # which is the whole reason the v4 rules were factored out.
        "6to4 embedded IPv4",
        r'\tif \(g0 === 0x2002 && isBlockedV4\(g1 >> 8, g1 & 255, g2 >> 8, g2 & 255\)\) return true;',
        '\tif (false) return true;',
        "blocking a 6to4 address whose embedded IPv4 is a blocked target",
    ),
    (
        # Without this the ::/8 rule is absent, so ::1 and :: normalise past every
        # check. It also covers the deprecated IPv4-compatible form, which
        # normalizeHost no longer folds to a dotted quad.
        "IPv6 ::/8 reserved",
        r'\tif \(g\.slice\(0, 5\)\.every\(\(n\) => n === 0\) && g\[5\] === 0\) return true;',
        '',
        "blocking the IPv6 unspecified and loopback addresses",
    ),
    (
        "NUL byte in target",
        r'if \(/\[\\u0000-\\u001f\\u007f\]/\.test\(candidate\)\) \{',
        'if (false) {',
        "refusing a target containing a NUL, which defeats the scheme check",
    ),
    (
        # The only shape that reaches rewriteLocation at all, since the redirect
        # loop consumes every 3xx-with-Location.
        "Location rewrite on non-3xx",
        r'\treturn proxyOrigin \+ "/" \+ resolved\.href;',
        '\treturn location;',
        "rewriting a Location on a non-3xx into proxy space",
    ),
    (
        # Resolving against the base is what makes a relative or protocol-relative
        # Location safe. With no base, `new URL("/next")` throws and
        # `new URL("//evil.test/x")` reads evil.test as the host, so both shapes
        # were handed to the client verbatim and the client left the proxy.
        "Location resolved against its base",
        r'\t\tresolved = base \? new URL\(location, base\) : new URL\(location\);',
        '\t\tresolved = new URL(location);',
        "resolving a relative or protocol-relative Location against the hop it came from",
    ),
    (
        # 304 carries a Location naming the selected representation, not a
        # redirect. Treating it as one discarded the client's conditional headers
        # and answered with a bodyless 200 instead of the 304.
        "304 is not a redirect",
        r'\t\t\t\tstatus === 307 \|\| status === 308;',
        '\t\t\t\tstatus === 307 || status === 308 || status === 304;',
        "returning a 304 to the client instead of consuming it as a redirect hop",
    ),
    (
        # X-Proxy-Timeout-Ms was a no-op on engine=tls: the AbortController had
        # nothing to abort, while /__config reported the timeout as resolved.
        "abort signal reaches the transport",
        r'\t\t\t\t\t\tsignal: init\.signal,\n',
        '',
        "passing the abort signal to a bound TLS_TRANSPORT",
    ),
    (
        # README and section 9 both document a comma-separated ALLOWED_HOSTS.
        "allowlist comma split",
        r'const parts = raw\.split\(","\)\.map\(\(s\) => s\.trim\(\)\)\.filter\(Boolean\);',
        'const parts = [raw];',
        "splitting and trimming the documented ALLOWED_HOSTS list",
    ),
    (
        # A preflight passes only if the header the browser is about to send is
        # listed, so an omission disables the feature for every browser caller.
        "CORS allow-headers completeness",
        r'"X-Proxy-Engine, X-Proxy-Persona, X-Proxy-Timeout-Ms",',
        '"",',
        "allowing the control headers, so browsers can actually use the features",
    ),
    (
        # Reflecting ACAO while passing the origin's ACAC through is the exact
        # combination the CORS comment claims this proxy refuses to produce.
        "upstream ACAC not forwarded",
        r'\t"access-control-allow-credentials",\n',
        '',
        "stripping an upstream Access-Control-Allow-Credentials",
    ),
    (
        # "/__config requires auth" is a claim about the request WITHOUT a
        # credential; the old assertion checked the authenticated one.
        "/__config requires auth",
        r'\t\tconst authToken = authTokenFor\(env\);',
        '\t\tconst authToken = authTokenFor(env);\n'
        '\t\tif (new URL(request.url).pathname === "/__config") {\n'
        '\t\t\treturn new Response("{}", { headers: { "content-type": "application/json" } });\n'
        '\t\t}',
        "refusing /__config when no credential is presented",
    ),
    (
        # Two Set-Cookie LINES must survive as two lines. The old assertion read a
        # joined header value and accepted the comma-joined corruption, so a mutant
        # that folded the cookies together passed the whole suite.
        "Set-Cookie kept as separate lines",
        r'\t\t\tfor \(const c of cookies\) out\.append\("set-cookie", c\);',
        '\t\t\tout.set("set-cookie", cookies.join(", "));',
        "keeping repeated Set-Cookie headers as separate header lines",
    ),
    # --- round 3: the ten review lenses. Same shape: one invariant per entry. ---
    (
        # Consent is per request, and a request names ONE host. Checked once
        # against hop 0, it rode a 302 to whatever host the origin chose, which is
        # the leak the opt-in exists to bound.
        "cookie consent is host-scoped",
        r'\treturn normalizeHost\(targetHost\) === normalizeHost\(initialHost\);',
        '\treturn true;',
        "scoping cookie consent to the host the caller named",
    ),
    (
        # `Vary: *` is the value that means "do not key on anything", not a list
        # of names. Appending produces "*, Origin", which RFC 9110 s5.2.2 does not
        # define and caches cannot parse.
        "Vary star not appended to",
        r'\tif \(existing === "\*"\) \{\n\t\theaders\.set\("vary", "\*"\);',
        '\tif (false) {\n\t\theaders.set("vary", "*");',
        "leaving an upstream Vary: * alone instead of producing '*, Origin'",
    ),
    (
        # RFC 9110 s15.5.2 makes WWW-Authenticate REQUIRED on a 401, and this proxy
        # accepts two schemes, so a client has nothing to read without it.
        "401 carries a challenge",
        r'\t\t\th\.set\("www-authenticate", \'Bearer realm="proxy", charset="UTF-8"\'\);',
        '',
        "the WWW-Authenticate challenge on an unauthenticated request",
    ),
    (
        # url.hostname never carries a port, so an entry that keeps its port matches
        # nothing: a deployment that wrote `origin.test:8443` had an allowlist that
        # permitted nothing and 403ed every request.
        "allowlist entry port is stripped",
        r'\t\t\tconst want = normalizeHost\(stripPort\(s\)\);',
        '\t\t\tconst want = normalizeHost(s);',
        "tolerating a port in an ALLOWED_HOSTS entry instead of matching nothing",
    ),
    (
        # The flag decides whether the caller's hints survive. It was
        # `persona === "edge" && looksLikeBotTool(ua)`, false for persona=chrome
        # arriving without engine=tls, which then fell through to the edge UA with
        # the caller's Client Hints still attached.
        "identity override covers every rewrite",
        r'\t\tchromePersona \|\| \(persona !== "pass" && looksLikeBotTool\(ua\)\);',
        '\t\tchromePersona || (persona === "edge" && looksLikeBotTool(ua));',
        "dropping the caller's Client Hints whenever the User-Agent is replaced",
    ),
    (
        # A POST on engine=tls reached the origin with no payload and the origin's
        # 200 came back as success. Without the refusal, the guard is off and the
        # write is silently dropped.
        "engine=tls refuses a bodied request",
        r'\t\tif \(transport && hasBody && transport\.supportsBody !== true\) \{',
        '\t\tif (false) {',
        "refusing a bodied request when the transport cannot send a body",
    ),
    (
        # The other half of that pair: the method and body must actually reach a
        # transport that says it can send them.
        "engine=tls forwards method and body",
        r'\t\t\t\t\t\tmethod: hopMethod,\n\t\t\t\t\t\theaders: init\.headers,\n\t\t\t\t\t\tbody: hopBody,\n\t\t\t\t\t\tsignal: init\.signal,',
        '\t\t\t\t\t\theaders: init.headers,\n\t\t\t\t\t\tsignal: init.signal,',
        "passing method and body to a body-capable TLS_TRANSPORT",
    ),
]

# Cost guards. A survivor here means the suite lacks a cost assertion, not that a
# security invariant is unpinned, so they are reported separately.
SLOW = [
    (
        "redirect cap",
        r'const MAX_REDIRECTS = 5;',
        'const MAX_REDIRECTS = 500;',
        "the 5-hop redirect cap",
    ),
    (
        "upstream timeout",
        r'const UPSTREAM_TIMEOUT_MS = 30000;',
        'const UPSTREAM_TIMEOUT_MS = 600000;',
        "the 30s default upstream timeout",
    ),
    (
        "timeout clamping",
        r'\tif \(n > MAX_TIMEOUT_MS\) return MAX_TIMEOUT_MS;',
        '',
        "the upper clamp on a caller-supplied timeout",
    ),
    (
        "timeout floor",
        r'\tif \(n < MIN_TIMEOUT_MS\) return MIN_TIMEOUT_MS;',
        '',
        "the lower clamp, so a 1ms budget no longer aborts immediately",
    ),
    (
        "redirect policy on hops",
        r'\t\t\t\tconst check = validateTarget\(next\.href, allowedHosts\);',
        '\t\t\t\tconst check = { ok: true };',
        "re-applying the allowlist and SSRF guard to every redirect hop",
    ),
]


def run_suite(path_to_v2, timeout=420):
    proc = subprocess.run(
        [sys.executable, SUITE, path_to_v2],
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout + proc.stderr


def prepare(item, tmp):
    name, pattern, replacement = item[0], item[1], item[2]
    mutated, n = re.subn(pattern, replacement, ORIGINAL, flags=re.M)
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    path = os.path.join(tmp, "v2-%s.js" % slug)
    if n == 0 or mutated == ORIGINAL:
        return (name, None, item[3], "PATTERN DID NOT MATCH" if n == 0 else "NO-OP MUTATION")
    with open(path, "w") as fh:
        fh.write(mutated)
    return (name, path, item[3], None)


def main():
    tmp = tempfile.mkdtemp(prefix="apirv-mut-")
    print("mutation check -- each mutation must be CAUGHT by the suite\n")

    code, out = run_suite(V2)
    if code != 0:
        print("  BASELINE NOT GREEN (exit %d). Tail:\n%s" % (code, out[-1500:]))
        shutil.rmtree(tmp, ignore_errors=True)
        return 1
    npass = len(re.findall(r"^  PASS  v2:", out, re.M))
    nctl = len(re.findall(r"^  PASS  NEG-CONTROL", out, re.M))
    print("  BASELINE green: %d v2 assertions, %d negative controls\n" % (npass, nctl))

    all_muts = MUTATIONS + SLOW
    with ThreadPoolExecutor(max_workers=6) as pool:
        prepared = list(pool.map(lambda m: prepare(m, tmp), all_muts))

    def check(t):
        name, path, inv, err = t
        if err:
            return (name, inv, False, [], err)
        code, out = run_suite(path)
        return (name, inv, code != 0, re.findall(r"^  FAILED: (.+?)(?:   |$)", out, re.M), None)

    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(check, prepared))

    slow_names = {s[0] for s in SLOW}
    survivors, caught = [], 0
    for name, inv, was_caught, fails, err in outcomes:
        suffix = "  (cost guard)" if name in slow_names else ""
        if err:
            print("  ERROR    %-26s %s" % (name, err))
            survivors.append(name)
            continue
        if was_caught:
            caught += 1
            print("  CAUGHT   %-26s removes: %s%s" % (name, inv, suffix))
            for f in fails[:2]:
                print("           detected by: %s" % f)
        else:
            print("  SURVIVED %-26s removes: %s%s" % (name, inv, suffix))
            print("           the suite still passed with this invariant removed")
            survivors.append(name)

    shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d/%d mutations caught" % (caught, len(all_muts)))
    if survivors:
        print("SURVIVORS: %s" % ", ".join(survivors))
        return 1
    print("OK: every mutation was detected, so the v2 assertions have teeth.")
    return 0


if __name__ == "__main__":
    sys.exit(main())