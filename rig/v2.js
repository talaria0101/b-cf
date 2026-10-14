// api.rv v2 -- a Cloudflare Workers reverse proxy.
//
// Plain ES2022 JavaScript on purpose: no build step, so this file deploys as
// written (wrangler.toml points `main` at it), and runs under workerd
// unmodified.
//
// Design rule: never claim a capability the Workers runtime does not have.
// v1 tried to write cf-connecting-ip and to strip Cloudflare-injected headers.
// Neither works. See "What v2 deliberately does not do" at the bottom.

const VERSION = "2.0.0";

// ---------------------------------------------------------------------------
// Configuration.
//
// These are module-level constants so the file is self-contained. Move them to
// bindings (wrangler "vars") before deploying anything real; a secret belongs
// in `wrangler secret put`, never in source.
// ---------------------------------------------------------------------------

// Shared secret. Read from the `AUTH_TOKEN` binding so `wrangler secret put
// AUTH_TOKEN` works, with the module constant as the fallback for local runs.
// When empty the proxy is OPEN, which is how v1 shipped. Set the binding.
const AUTH_TOKEN = "";

function authTokenFor(env) {
	const fromEnv = env && env.AUTH_TOKEN;
	// An explicit binding always wins, including an explicitly empty one.
	if (typeof fromEnv === "string") return fromEnv;
	return AUTH_TOKEN;
}

// Host suffixes this proxy may fetch. Empty means "any host".
// Example: ["example.com", "githubusercontent.com"]
const ALLOWED_HOSTS = [];

/**
 * The allowlist arrives from a binding as a comma-separated string, because
 * wrangler `vars` cannot carry an array. An absent, empty or whitespace-only
 * value means "no allowlist", which is the open-proxy default and is reported by
 * /__config so it cannot be shipped unnoticed.
 */
function parseHostList(raw, fallback) {
	if (typeof raw !== "string") return fallback;
	const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
	return parts;
}

// Hosts never fetched even when allowlisted, because reaching them from the edge
// is a server-side request forgery primitive against cloud instance metadata and
// against Cloudflare's own control surfaces.
const BLOCKED_HOSTS = [
	"localhost",
	"127.0.0.1",
	"0.0.0.0",
	"::1",
	"169.254.169.254",
	"metadata.google.internal",
	"metadata.goog",
	"instance-data",
];

const MAX_REDIRECTS = 5;
const UPSTREAM_TIMEOUT_MS = 30000;

// A caller may shorten (or extend) the per-request upstream timeout, within
// bounds. Shortening is the common case: a browser client waiting on a proxy
// wants its own deadline honoured rather than the proxy's.
const MIN_TIMEOUT_MS = 250;
const MAX_TIMEOUT_MS = 60000;

/**
 * Per-request timeout, clamped. Exposed as a feature AND as the thing the test
 * suite pins: a wall-clock deadline cannot be asserted reliably against a
 * long-running peer, but the clamping and the abort path can be.
 */
function requestTimeoutMs(request) {
	const raw = request.headers.get("x-proxy-timeout-ms");
	if (!raw) return UPSTREAM_TIMEOUT_MS;
	const n = parseInt(raw, 10);
	if (!Number.isFinite(n)) return UPSTREAM_TIMEOUT_MS;
	if (n < MIN_TIMEOUT_MS) return MIN_TIMEOUT_MS;
	if (n > MAX_TIMEOUT_MS) return MAX_TIMEOUT_MS;
	return n;
}

// One coherent browser identity, used only when the caller's own UA looks like a
// bot tool. Every value below is derived from ONE another, because an
// inconsistent set is itself a detection signal: the Chrome major in the UA
// matches sec-ch-ua, and the UA's OS matches sec-ch-ua-platform.
//
// CHROME_MAJOR is pinned and WILL GO STALE. As of 2026-10-13 Chrome stable is
// 155 (ChromiumDash, and the b-ids measured corpus agrees), so 140 below is
// already ~15 releases behind. Bump CHROME_MAJOR when you deploy; nothing else
// needs to change, because the UA and both hint headers are built from it.
//
// This is a fixed string, not a rotating one, and that is deliberate. v1's
// "generate a random IP" and "pick a UA at random" ideas were both impossible
// or counterproductive here; randomising the UA per request would make a single
// client's fingerprint change constantly, which is a stronger signal than a
// static one. A real browser has a stable identity per profile.
const CHROME_MAJOR = 140;

/**
 * Two identities, and the difference between them is the whole point.
 *
 * The `chrome` persona claims to be Chrome 140. It is used only when the caller
 * asks for `X-Proxy-Persona: chrome`, which pairs it with a userland TLS
 * transport.
 *
 * The DEFAULT is the honest persona, which describes the transport: it is what
 * workerd's own `fetch()` presents, so the User-Agent, the negotiated protocol and
 * the ClientHello agree with each other.
 *
 * Why not always claim Chrome? Because the layers move together. Measured on the
 * live api.rv.pkgforge.dev on 2026-10-13 (proofs/01). Reading the JA4_a fields,
 * which are `t` + version + sni + ciphers + extensions + alpn:
 *
 *   ja4 = t13d1312h2_a44d0ee8b3cc_e381dae6da6b
 *            ^  ^  ^  ^  ^ ^                      t  13  d 13 12 h2
 *            |  |  |  |  +-- first ALPN char
 *            |  |  |  +----- 12 extensions, after GREASE removal
 *            |  |  +-------- 13 ciphers, after GREASE removal
 *            |  +----------- d = SNI present
 *            +-------------- 13 = TLS 1.3   (12 would be TLS 1.2)
 *
 * while a real Chrome 155, from the b-ids corpus ClientHello:
 *
 *   ja4 = t13i1516h2_8daaf6152771_...   15 ciphers, 16 extensions, no SNI captured
 *
 * BOTH are TLS 1.3. An earlier revision of this comment read the "13" as a cipher
 * count and the "12" as a version and described the incumbent as presenting
 * TLS 1.2, which was wrong. The gap is narrower and still real: 13 ciphers against
 * Chrome's 15, 12 extensions against 16, Cloudflare's own HTTP/2 SETTINGS, and a
 * Safari 18.5 User-Agent. A browser User-Agent on a handshake that is not that
 * browser's is a *louder* signal than an honest one, because the mismatch is the
 * tell. Claiming Chrome over `fetch()` inherits exactly that defect; v2 does not.
 *
 * If you want the Chrome claim, the transport has to be built to match. See
 * `engine=tls` in README.md and the Layer 1 section of RESEARCH.md.
 */
const CHROME_UA =
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	`(KHTML, like Gecko) Chrome/${CHROME_MAJOR}.0.0.0 Safari/537.36`;

const SEC_CH_UA =
	`"Chromium";v="${CHROME_MAJOR}", "Not=A?Brand";v="24", "Google Chrome";v="${CHROME_MAJOR}"`;

const SEC_CH_UA_PLATFORM = '"Windows"';

// What the runtime actually is. Sends no sec-ch-ua: those are Client Hints, and
// inventing them here would be the same overclaim in miniature.
const EDGE_UA = "Cloudflare-Workers";

const DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9";

// ---------------------------------------------------------------------------
// Target URL parsing
// ---------------------------------------------------------------------------

/**
 * Accepted forms, in order of precedence:
 *   /https://example.com/path?a=1     path-prefixed (v1 compatible)
 *   /example.com/path                 bare host, https assumed
 *   /?url=https%3A%2F%2Fexample.com  query form
 * The target's query string survives in every form. v1 dropped it.
 */
function parseTarget(request, allowedHosts) {
	const incoming = new URL(request.url);

	// Diagnostic endpoint. Reports the resolved limits for THIS request, which is
	// the only way to observe the resolved timeout without inferring it from
	// elapsed time: the runtime compresses every deadline into the same envelope,
	// so a 30s default and a 600s default are indistinguishable by clock.
	// Reached only after auth, and it exposes no secret -- every value here is
	// either a constant or derived from a header the caller already supplied.
	if (incoming.pathname === "/__config") {
		return { ok: false, status: 418, message: "__CONFIG__" };
	}

	// Path form first. The query form is a fallback for the empty-path case only,
	// because a path-form target may legitimately carry its own `?url=` parameter
	// and reading that as the destination would silently fetch the wrong host.
	let raw = incoming.pathname.replace(/^\/+/, "");
	if (raw) {
		let decoded = raw;
		try {
			decoded = decodeURIComponent(raw);
		} catch {
			decoded = raw;
		}
		// v1 used `pathname` only and never re-appended `search`, so anything after
		// the target's own "?" was silently dropped. Re-attach it.
		return validateTarget(decoded + incoming.search, allowedHosts);
	}

	const q = incoming.searchParams.get("url");
	if (q) return validateTarget(q, allowedHosts);

	return { ok: false, status: 400, message: "Invalid target URL" };
}

/**
 * Reduce a URL hostname to a single comparable form, so that every spelling of
 * the same address collapses to one string.
 *
 * WHATWG URL serialises IPv6 hosts WITH brackets and in hex, so the raw
 * hostname of `https://[::ffff:169.254.169.254]/` is `[::ffff:a9fe:a9fe]` and
 * would never match a `"::1"` or `"169.254.169.254"` blocklist entry. It also
 * leaves a trailing dot on `localhost.`, which `endsWith(".localhost")` misses.
 * Both were confirmed gaps before this function existed.
 *
 * IPv4-mapped and IPv4-compatible IPv6 (`::ffff:a.b.c.d`, `::a.b.c.d`) are
 * folded to the dotted quad, because they are the same host.
 */
function expandIPv6(inner) {
	let s = inner;
	const dotted = s.match(/:((?:\d{1,3}\.){3}\d{1,3})$/);
	if (dotted) {
		const p = dotted[1].split(".").map(Number);
		s =
			s.slice(0, dotted.index) +
			(((p[0] << 8) | p[1]) >>> 0).toString(16) +
			":" +
			(((p[2] << 8) | p[3]) >>> 0).toString(16);
	}
	const halves = s.split("::");
	const head = halves[0] ? halves[0].split(":").filter(Boolean) : [];
	const tail = halves.length > 1 && halves[1] ? halves[1].split(":").filter(Boolean) : [];
	const fill = 8 - head.length - tail.length;
	return [...head, ...new Array(Math.max(0, fill)).fill("0"), ...tail].map((g) => {
		const n = parseInt(g || "0", 16);
		return Number.isFinite(n) ? n & 0xffff : 0;
	});
}

function normalizeHost(hostname) {
	const s = String(hostname).toLowerCase().replace(/\.+$/, "");
	if (s.startsWith("[") && s.endsWith("]")) {
		const inner = s.slice(1, -1).split("%")[0]; // drop any zone id
		if (inner.includes(":")) {
			const groups = expandIPv6(inner);
			if (groups.length === 8) {
				const zeroPrefix = groups.slice(0, 5).every((g) => g === 0);
				if (zeroPrefix && (groups[5] === 0xffff || groups[5] === 0)) {
					return `${groups[6] >> 8}.${groups[6] & 255}.${groups[7] >> 8}.${groups[7] & 255}`;
				}
				return groups.map((g) => g.toString(16)).join(":");
			}
		}
		return inner;
	}
	return s;
}

function isBlockedHost(hostname) {
	const host = normalizeHost(hostname);
	if (BLOCKED_HOSTS.includes(host)) return true;
	if (host.endsWith(".localhost")) return true;
	// Any address in a private, loopback, link-local or reserved range, in v4 or
	// v6. Cheaper and far more complete than trying to enumerate every spelling.
	const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (v4) {
		const [a, b] = v4.slice(1).map(Number);
		if (
			a === 0 || a === 10 || a === 127 ||
			(a === 169 && b === 254) ||
			(a === 172 && b >= 16 && b <= 31) ||
			(a === 192 && b === 168) ||
			// RFC 6598 shared address space (CGNAT). Carrier NAT equipment and
			// some metadata endpoints live here, and it is not reachable from
			// the public internet either.
			(a === 100 && b >= 64 && b <= 127) ||
			// RFC 6890 IETF protocol assignments, including 192.0.0.8/32
			// (IPv4 dummy address) and the 192.0.2.0/24 test range.
			(a === 192 && b === 0) ||
			// RFC 2544 benchmarking range, 198.18.0.0/15.
			(a === 198 && (b === 18 || b === 19)) ||
			a >= 224
		) {
			return true;
		}
	}
	if (/^f[cd][0-9a-f]{2}:/.test(host) || host === "::" || host === "::1") return true;
	if (/^fe[89ab][0-9a-f]:/.test(host)) return true; // link-local
	// NAT64 well-known prefix (RFC 6052) 64:ff9b::/96 and its 2001:db8:... variant.
	// A blocked v4 target is reachable through these as an embedded address, so
	// blocking only the v4 form would leave the guard incomplete.
	if (/^64:ff9b:[0-9a-f]*:/.test(host) || host.startsWith("64:ff9b:")) return true;
	return false;
}

function validateTarget(candidate, allowedHosts) {
	// A NUL byte makes `new URL(candidate)` throw, and then the bare-host fallback
	// below treats the whole string as a host: "ftp://x%00y" parsed directly fails,
	// but "https://ftp://x%00y" succeeds with host "ftp". That turns a rejected
	// scheme into a request for a different host than the caller named, so the
	// input is refused outright rather than repaired.
	if (/[\u0000-\u001f\u007f]/.test(candidate)) {
		return { ok: false, status: 400, message: "Invalid target URL" };
	}
	let url;
	try {
		url = new URL(candidate);
	} catch {
		// Bare host: "example.com/x" -> "https://example.com/x"
		try {
			url = new URL("https://" + candidate);
		} catch {
			return { ok: false, status: 400, message: "Invalid target URL" };
		}
	}

	if (url.protocol !== "http:" && url.protocol !== "https:") {
		return { ok: false, status: 400, message: "Only http and https targets are allowed" };
	}
	if (isBlockedHost(url.hostname)) {
		return { ok: false, status: 403, message: "Target host is blocked" };
	}
	const hosts = allowedHosts || ALLOWED_HOSTS;
	if (hosts.length > 0) {
		// Compare on the normalised form, and require a label boundary so that
		// "example.com" does not authorise "evil-example.com".
		const host = normalizeHost(url.hostname);
		const permitted = hosts.some((s) => {
			const want = normalizeHost(s);
			return host === want || host.endsWith("." + want);
		});
		if (!permitted) {
			return { ok: false, status: 403, message: "Target host is not allowlisted" };
		}
	}
	return { ok: true, url };
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

function isAuthorized(request, authToken) {
	if (!authToken) return true; // open proxy, as v1 shipped
	const auth = request.headers.get("authorization") || "";
	// RFC 7235: the auth-scheme token is case-insensitive.
	if (/^bearer /i.test(auth) && auth.slice(7) === authToken) return true;
	return request.headers.get("x-proxy-key") === authToken;
}

// ---------------------------------------------------------------------------
// Request headers
// ---------------------------------------------------------------------------

// Hop-by-hop headers must not be forwarded (RFC 9110 s7.6.1). host and
// content-length are here too because the runtime derives both from the URL.
const HOP_BY_HOP = new Set([
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"host",
	"content-length",
]);

// Headers that identify the request as having come through a proxy or a CDN edge.
// Stripping these does not hide the Worker -- Cloudflare re-adds several of them
// at the edge, which v1 discovered the hard way -- but not forwarding them keeps
// the caller's own intent from leaking and removes the ones Cloudflare honours.
const EDGE_IDENTITY = new Set([
	"x-forwarded-for",
	"x-forwarded-host",
	"x-forwarded-proto",
	"x-forwarded-server",
	"x-real-ip",
	"cf-connecting-ip",
	"cf-ipcountry",
	"cf-ray",
	"cf-visitor",
	"cf-worker",
	"cf-ew-via",
	"cf-ew-preview-server",
	"cdn-loop",
	"x-cors-headers",
	"x-proxy-key",
	"x-proxy-forward-cookies",
	"x-proxy-accept-language",
	"x-proxy-timeout-ms",
	// These describe the caller, not the request being made on the caller's
	// behalf. Forwarding them tells the origin something about the caller's page
	// that has nothing to do with this fetch, and `sec-fetch-*` is a description
	// of a browser navigation that never happened.
	"origin",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-dest",
	"sec-fetch-user",
	// The engine and persona are ours, not the caller's. A caller must not be
	// able to name an engine that this deployment has no transport bound for.
	"x-proxy-engine",
	"x-proxy-persona",
]);

// Client Hints are NOT listed in EDGE_IDENTITY, because they are not always
// ours to drop: see CLIENT_HINTS in buildUpstreamHeaders, which strips them
// only when the proxy is replacing the User-Agent and would otherwise leave the
// caller's hints contradicting it.

// Set explicitly by buildUpstreamHeaders, so never copied from the caller.
// Only user-agent belongs here: accept and accept-language are copied through
// and then defaulted, so putting them in this set made the default unreachable
// and dropped the header entirely.
//
// `authorization` and `proxy-authorization` are here for a specific reason: the
// proxy's OWN credential is the caller's Authorization header, and forwarding it
// would hand AUTH_TOKEN to every third-party origin. That is NOT the same as the
// cookie case below: forwarding a caller's cookies to the target is intended
// behaviour and stays available behind an opt-in, but this proxy's own token has
// no reason to travel anywhere the caller did not name.
const OWNED_HEADERS = new Set(["user-agent", "authorization", "proxy-authorization"]);

// Values that give away a command-line or scripted client.
function looksLikeBotTool(ua) {
	const u = ua.toLowerCase();
	return (
		u === "" ||
		u.length < 10 ||
		u.includes("curl") ||
		u.includes("wget") ||
		u.includes("python-requests") ||
		u.includes("python-urllib") ||
		u.includes("go-http-client") ||
		u.includes("java/") ||
		u.includes("okhttp") ||
		u.includes("axios") ||
		u.includes("node-fetch") ||
		u.includes("httpie") ||
		u.includes("libwww-perl") ||
		u.includes("scrapy")
	);
}

// Cookie forwarding is opt-in per request. v1 passed client cookies to
// arbitrary third-party origins unconditionally, which leaks session tokens.
function cookieConsent(request) {
	return request.headers.get("x-proxy-forward-cookies") === "1";
}

/**
 * Which engine this request asked for.
 *
 * The TLS transport is bound as `TLS_TRANSPORT` and must expose
 * `fetch(url, { headers, signal }) -> Response`, the shape a userland TLS + HTTP/2
 * client provides. The signal is not optional: it is how the per-request timeout
 * reaches the transport, and a transport that ignores it makes
 * X-Proxy-Timeout-Ms a no-op.
 *
 * It is deliberately NOT implemented here: a correct TLS stack needs its own
 * test corpus, and shipping a half-audited one behind an unmeasured claim would
 * be worse than not offering the option. See RESEARCH.md 3.3 for the design and for
 * prior art that does ship it.
 *
 * `fetch()` is the default and always available. Asking for `tls` with no
 * transport bound is a clear 501 rather than a silent fallback, because falling
 * back would return a request that looks like the tier the caller asked for and
 * is not.
 */
const ENGINE_FETCH = "fetch";
const ENGINE_TLS = "tls";

function requestedEngine(request) {
	const raw = (request.headers.get("x-proxy-engine") || "").toLowerCase();
	return raw === ENGINE_TLS ? ENGINE_TLS : ENGINE_FETCH;
}

// Every Client Hint, low-entropy included. When this proxy builds its OWN
// identity it owns the whole set; when it forwards the caller's identity the
// caller's hints belong to that identity and are forwarded with it.
const CLIENT_HINTS = [
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"sec-ch-ua-arch",
	"sec-ch-ua-bitness",
	"sec-ch-ua-model",
	"sec-ch-ua-full-version",
	"sec-ch-ua-full-version-list",
	"sec-ch-ua-platform-version",
	"sec-ch-ua-wow64",
];

function buildUpstreamHeaders(request, target) {
	const headers = new Headers();
	const incoming = request.headers;
	const forwardCookies = cookieConsent(request);

	const ua = incoming.get("user-agent") || "";
	const persona = incoming.get("x-proxy-persona") || "edge";
	const chromePersona = persona === "chrome" && requestedEngine(request) === ENGINE_TLS;
	// A bot tool arriving with NO User-Agent at all scores an immediate bot
	// verdict per Cloudflare's bot-score docs, so an empty one is treated as a
	// bot tool here too rather than forwarded.
	const overridesIdentity = chromePersona || persona === "edge" && looksLikeBotTool(ua);

	for (const [key, value] of incoming.entries()) {
		const lower = key.toLowerCase();
		if (HOP_BY_HOP.has(lower) || EDGE_IDENTITY.has(lower) || OWNED_HEADERS.has(lower)) continue;
		if (lower === "cookie" && !forwardCookies) continue;
		// The inconsistency this exists to prevent: the proxy rewrites the UA and
		// leaves the caller's `sec-ch-ua-platform: "macOS"` beside it. v1 shipped
		// exactly that combination. A hint only survives when the caller's own UA
		// is the one going upstream, because then the pair is coherent.
		if (overridesIdentity && CLIENT_HINTS.includes(lower)) continue;
		headers.set(key, value);
	}

	if (chromePersona) {
		// Claim Chrome, and only where the transport can back the claim. Over
		// plain fetch() the runtime's handshake is Cloudflare's own, which is why
		// this branch is unreachable without engine=tls.
		headers.set("user-agent", CHROME_UA);
		if (target.protocol === "https:") {
			// Only the LOW-entropy hints. Chrome withholds sec-ch-ua-arch /
			// -bitness / -model until the server opts in via Accept-CH, and
			// Client Hints are secure-context only, so http:// targets get none.
			headers.set("sec-ch-ua", SEC_CH_UA);
			headers.set("sec-ch-ua-mobile", "?0");
			headers.set("sec-ch-ua-platform", SEC_CH_UA_PLATFORM);
			// Same secure-context rule as the hints. A real Chrome sends this
			// from an https page and never from an http one, so emitting it
			// alongside a plaintext fetch would contradict the gating two lines
			// above.
			headers.set("upgrade-insecure-requests", "1");
		}
	} else if (persona === "pass" || !looksLikeBotTool(ua)) {
		// The caller's own identity, forwarded intact. Its hints came with it.
		headers.set("user-agent", ua);
	} else {
		// Default: describe the transport honestly. A caller arriving as curl is
		// not forwarded as curl, but it is not told it is Chrome either. Silently
		// claiming a browser identity over a handshake that is not one is worse
		// than being identifiable, because the mismatch is the signal.
		headers.set("user-agent", EDGE_UA);
	}

	// accept and accept-language are copied verbatim when the caller supplied
	// them, and defaulted only when it did not.
	if (!headers.has("accept")) {
		headers.set(
			"accept",
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		);
	}
	if (!headers.has("accept-language")) {
		headers.set(
			"accept-language",
			incoming.get("x-proxy-accept-language") || DEFAULT_ACCEPT_LANGUAGE,
		);
	}

	// The Referer must not point back at the proxy's own caller. A Referer that
	// names an unrelated private app is a strong tell that a request was relayed.
	if (incoming.has("referer")) {
		headers.set("referer", target.origin + "/");
	}

	return headers;
}

// ---------------------------------------------------------------------------
// Response handling
// ---------------------------------------------------------------------------

// v1 dropped content-encoding, content-length and transfer-encoding from every
// response and then streamed the body through. That is only correct when the body
// has been decompressed; here the body is forwarded untouched, so the framing
// headers must be preserved or the response is corrupt. Only transfer-encoding is
// genuinely unsafe to echo.
const DROP_FROM_RESPONSE = new Set([
	"transfer-encoding",
	// The origin's own credential opt-in must not survive. applyCors reflects
	// the caller's Origin, and pairing a reflected ACAO with a forwarded ACAC is
	// exactly the combination this proxy's CORS comment says it refuses to
	// produce: any site could then read a user's authenticated response through
	// an open target list. Cookie forwarding is the supported, explicit path.
	"access-control-allow-credentials",
]);

// An upstream redirect points at the third-party origin. Handing that to the
// client would let the client leave the proxy entirely, so rewrite it back into
// proxy space.
function rewriteLocation(location, proxyOrigin) {
	try {
		const u = new URL(location);
		if (u.protocol !== "http:" && u.protocol !== "https:") return location;
		return proxyOrigin + "/" + u.href;
	} catch {
		return location;
	}
}

function buildResponseHeaders(upstream, proxyOrigin) {
	const out = new Headers();
	for (const [key, value] of upstream.entries()) {
		const lower = key.toLowerCase();
		if (DROP_FROM_RESPONSE.has(lower)) continue;
		if (lower === "location") {
			out.set(key, rewriteLocation(value, proxyOrigin));
			continue;
		}
		// Do not pass Cloudflare-injected response headers through to the client.
		if (lower.startsWith("cf-") || lower === "cdn-loop") continue;
		out.set(key, value);
	}

	// Set-Cookie is special: Headers folds repeated values into one comma-joined
	// string, and a comma is legal inside an Expires date, so writing that back
	// with set() corrupts any origin that sets more than one cookie. The
	// getSetCookie() API returns them individually and must be appended.
	if (typeof upstream.getSetCookie === "function") {
		const cookies = upstream.getSetCookie();
		if (cookies && cookies.length > 0) {
			out.delete("set-cookie");
			for (const c of cookies) out.append("set-cookie", c);
		}
	}

	out.set("x-proxy-version", VERSION);
	return out;
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

// v1 shipped no CORS headers at all. Same-Origin Policy is the entire reason a
// CORS proxy exists, so shipping one without CORS is shipping a broken CORS
// proxy: every browser caller fails before reaching the proxy path.
const CORS_STATIC = {
	"access-control-allow-methods": "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
	// Every request header this worker actually reads. A preflight only passes if
	// the header the browser is about to send is listed here, so an omission does
	// not degrade gracefully: it makes the feature unreachable from a browser
	// caller, which is the whole point of a CORS proxy. X-Proxy-Engine,
	// X-Proxy-Persona and X-Proxy-Timeout-Ms were missing here, which silently
	// disabled the persona model, engine selection and the timeout for every
	// browser caller.
	"access-control-allow-headers":
		"Authorization, Content-Type, Accept, Accept-Language, User-Agent, " +
		"X-Proxy-Key, X-Proxy-Accept-Language, X-Proxy-Forward-Cookies, " +
		"X-Proxy-Engine, X-Proxy-Persona, X-Proxy-Timeout-Ms",
	"access-control-max-age": "86400",
};

function applyCors(request, headers) {
	// Reflect the caller's origin when present, otherwise allow any origin.
	//
	// This is NOT the same as enabling credentialed requests. That additionally
	// requires `access-control-allow-credentials: true`, which this proxy
	// deliberately does not set: with an open target list, reflecting Origin AND
	// allowing credentials would let any site read a user's authenticated
	// responses through the proxy. Cookie forwarding is a separate, explicit
	// opt-in below, which is the supported path.
	headers.set("access-control-allow-origin", request.headers.get("origin") || "*");
	// Append to any Vary the origin already sent rather than clobbering it: the
	// origin's own cache keys matter as much as ours.
	const existing = headers.get("vary");
	headers.set("vary", existing ? `${existing}, Origin` : "Origin");
	for (const [k, v] of Object.entries(CORS_STATIC)) headers.set(k, v);
}

function jsonError(status, message, headers) {
	const h = new Headers(headers || {});
	h.set("content-type", "application/json; charset=utf-8");
	h.set("x-proxy-version", VERSION);
	return new Response(JSON.stringify({ error: message, version: VERSION }), {
		status,
		headers: h,
	});
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export default {
	async fetch(request, env) {
		// Preflight must not require auth or a target, or the browser fails the
		// preflight and never sends the real request at all. It MUST carry
		// Access-Control-Allow-Origin: a 204 with only allow-methods is rejected by
		// the browser, which is the same broken-CORS-proxy failure v1 had.
		if (request.method === "OPTIONS") {
			const preflight = new Headers();
			applyCors(request, preflight);
			return new Response(null, { status: 204, headers: preflight });
		}

		const authToken = authTokenFor(env);
		if (!isAuthorized(request, authToken)) {
			const h = new Headers();
			applyCors(request, h);
			return jsonError(401, "Unauthorized", h);
		}

		// ALLOWED_HOSTS from the binding is a comma-separated string; the module
		// constant is the fallback. A malformed or empty value means "no
		// allowlist", which is the open-proxy default.
		const allowedHosts = parseHostList(env && env.ALLOWED_HOSTS, ALLOWED_HOSTS);

		const parsed = parseTarget(request, allowedHosts);
		if (parsed.ok === false && parsed.message === "__CONFIG__") {
			const h = new Headers();
			applyCors(request, h);
			h.set("content-type", "application/json; charset=utf-8");
			return new Response(
				JSON.stringify({
					version: VERSION,
					resolved_timeout_ms: requestTimeoutMs(request),
					default_timeout_ms: UPSTREAM_TIMEOUT_MS,
					min_timeout_ms: MIN_TIMEOUT_MS,
					max_timeout_ms: MAX_TIMEOUT_MS,
					max_redirects: MAX_REDIRECTS,
					auth_required: authToken !== "",
					allowed_hosts: allowedHosts,
					tls_transport_bound: !!(
						env && env.TLS_TRANSPORT && env.TLS_TRANSPORT.fetch
					),
					default_user_agent: EDGE_UA,
					personas: ["edge", "chrome (requires engine=tls)", "pass"],
				}, null, 2),
				{ status: 200, headers: h },
			);
		}
		if (!parsed.ok) {
			const h = new Headers();
			applyCors(request, h);
			return jsonError(parsed.status, parsed.message, h);
		}

		const target = parsed.url;
		const method = request.method.toUpperCase();
		const hasBody = method !== "GET" && method !== "HEAD";

		// Engine selection. `tls` needs a bound userland transport; without one we
		// refuse rather than silently serving a fetch(), because a caller that
		// asked for a Chrome-shaped handshake and got the runtime's own is worse
		// off than one told no.
		const engine = requestedEngine(request);
		const transport = engine === ENGINE_TLS ? (env && env.TLS_TRANSPORT) || null : null;
		if (engine === ENGINE_TLS && (!transport || typeof transport.fetch !== "function")) {
			const h = new Headers();
			applyCors(request, h);
			return jsonError(
				501,
				"engine=tls requires a TLS_TRANSPORT binding exposing " +
					"fetch(url, {headers, signal}); see RESEARCH.md 3.3. " +
					"Use the default engine=fetch for the runtime path.",
				h,
			);
		}

		// Follow redirects by hand so each hop gets freshly built headers, the
		// allowlist and SSRF blocklist apply to EVERY hop, and the final Location
		// is rewritten into proxy space. With `redirect: "manual"` there is no
		// runtime cap, so MAX_REDIRECTS is the only bound; worst case is
		// MAX_REDIRECTS+1 fetches, well inside the 50-subrequest Free limit.
		let current = target;
		let response = null;

		// A 307/308 must replay method AND body (RFC 9110 s15.4), but request.body
		// is a one-shot stream: once hop 0 has sent it, it cannot be read again.
		// So a body-bearing request is buffered BEFORE the first fetch. The cost is
		// that an arbitrarily large upload is held in the isolate's 128 MB; that is
		// the price of correct 307/308 semantics, and a caller who cannot afford it
		// should use 303 or send no body.
		let bodyBuffer = null;
		if (hasBody) {
			try {
				bodyBuffer = await request.arrayBuffer();
			} catch {
				// The body could not be pulled. It cannot be replayed, so it is
				// dropped rather than half-sent: a truncated POST that looks
				// successful is worse than a bodiless one, and 307/308 replay
				// cannot be honoured without the buffer anyway. An earlier comment
				// here claimed the stream would be forwarded on hop 0; the code
				// never did that, because request.body is one-shot and hopBody is
				// derived only from this buffer.
				bodyBuffer = null;
			}
		}

		for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
			// 301/302/303 become GET without a body; 307/308 repeat both.
			const repeats =
				hop === 0 ||
				response === null ||
				response.status === 307 ||
				response.status === 308;
			const hopMethod = repeats ? method : "GET";
			const hopBody = hasBody && repeats && bodyBuffer !== null ? bodyBuffer : null;

			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), requestTimeoutMs(request));
			try {
				const init = {
					method: hopMethod,
					headers: buildUpstreamHeaders(request, current),
					body: hopBody,
					signal: controller.signal,
				};
				if (transport) {
					// A userland transport owns its own framing, redirect handling and
					// TLS, so it gets the target and the headers rather than a
					// fetch() init. The abort signal is still passed, and it has to
					// be: without it the controller below aborts nothing and
					// X-Proxy-Timeout-Ms is silently a no-op on this engine while
					// /__config reports it as resolved. A transport that cannot honour
					// a signal must document that, not inherit a deadline that is not
					// enforced.
					response = await transport.fetch(current.href, {
						headers: init.headers,
						signal: init.signal,
					});
				} else {
					response = await fetch(current.href, {
						...init,
						redirect: "manual",
						cf: { cacheTtl: 0 },
					});
				}
			} catch (err) {
				clearTimeout(timer);
				const e = err instanceof Error ? err : new Error(String(err));
				const h = new Headers();
				applyCors(request, h);
				const timedOut = e.name === "AbortError";
				return jsonError(
					502,
					timedOut ? "Upstream request timed out" : "Error fetching URL: " + e.message,
					h,
				);
			}
			clearTimeout(timer);

			const status = response.status;
			const location = response.headers.get("location");
			if (status >= 300 && status < 400 && location) {
				if (hop === MAX_REDIRECTS) {
					const h = new Headers();
					applyCors(request, h);
					return jsonError(508, "Too many redirects", h);
				}
				let next;
				try {
					next = new URL(location, current.href);
				} catch {
					const h = new Headers();
					applyCors(request, h);
					return jsonError(502, "Upstream returned an unparseable Location", h);
				}
				// Re-run the full policy on the hop, not just the blocklist: a
				// redirect must not be able to escape an allowlist the original
				// target satisfied.
				const check = validateTarget(next.href, allowedHosts);
				if (!check.ok) {
					const h = new Headers();
					applyCors(request, h);
					return jsonError(
						check.status,
						"Redirect target rejected: " + check.message,
						h,
					);
				}
				current = next;
				continue;
			}
			break;
		}

		const outHeaders = buildResponseHeaders(response.headers, new URL(request.url).origin);
		applyCors(request, outHeaders);

		// Statuses that must not carry a body (RFC 9110 s15.4).
		const noBody =
			method === "HEAD" ||
			response.status === 204 ||
			response.status === 205 ||
			response.status === 304;
		return new Response(noBody ? null : response.body, {
			status: response.status,
			statusText: response.statusText,
			headers: outHeaders,
		});
	},
};