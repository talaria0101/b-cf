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
        # "caught" while pinning nothing.
        "genuine UA passthrough",
        r'\tif \(looksLikeBotTool\(ua\)\) \{',
        '\tif (false) {',
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
        r'\t\tif \(\n\t\t\ta === 0 \|\| a === 10 \|\| a === 127 \|\|',
        '\t\tif (\n\t\t\tfalse ||',
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
        "content-encoding preservation",
        r'const DROP_FROM_RESPONSE = new Set\(\["transfer-encoding"\]\);',
        'const DROP_FROM_RESPONSE = new Set(["transfer-encoding", "content-encoding", "content-length"]);',
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
        "withholding Client Hints from plaintext http targets",
    ),
    (
        "allowlist label boundary",
        r'return host === want \|\| host\.endsWith\("\." \+ want\);',
        'return host === want || host.endsWith(want);',
        "the label boundary that stops evil-example.com matching example.com",
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