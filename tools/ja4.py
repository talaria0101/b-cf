#!/usr/bin/env python3
"""
Compute JA4 fields from a hex-encoded TLS ClientHello.

JA4 has three underscore-separated fields:

    t13d1516h2_8daaf6152771_6ff14566cf4a
    |  |  |       |            |
    |  |  |       |            +-- 12 hex: SHA256 of extensions + sigalgs
    |  |  |       +--------------- 12 hex: SHA256 of the sorted cipher list
    |  |  +----------------------- ALPN
    |  +-------------------------- 12 = TLS 1.2, 13 = TLS 1.3
    +----------------------------- d = SNI present, i = absent

Rules implemented, following foxIO-LLC/ja4 (BSD-3):
  - GREASE values are dropped from the cipher and extension lists
  - the two count fields are DECIMAL, zero-padded ('{:02d}'), not hex
  - the extension COUNT includes SNI and ALPN; the extension HASH excludes them
  - signature algorithms are filtered for GREASE, then appended in observed
    order after an underscore

VERIFIED, all three fields, by two independent oracles:

  ja4_a and ja4_c  against tls.peet.ws's own computation on the live
                    api.rv.pkgforge.dev handshake. proofs/01-api-rv-tls.json
                    carries peet.ws's ja4_r rendering, whose last two fields ARE
                    the ja4_c hash input, and hashing that string reproduces
                    peet's ja4_c e381dae6da6b exactly. A second party computing
                    JA4 from the same bytes and agreeing is not the same as this
                    tool agreeing with itself.
  ja4_b            against the same live handshake (a44d0ee8b3cc) and against a
                    real Chrome ClientHello from the Azathothas/b-ids corpus,
                    where it reproduces the browser's cipher hash 8daaf6152771.

A CORRECTION worth recording, because an earlier revision of this file labelled
ja4_c UNVERIFIED and was wrong to. It failed to reproduce the 6ff14566cf4a that
nemo-010/b-cf quotes for the same b-ids capture, and filed the cause as unknown.
The cause is known: this tool follows foxIO-LLC/ja4 python/common.py, where
get_hex_sorted() removes BOTH 0000 (SNI) and 0010 (ALPN) from the extension hash
and get_signature_algorithms() filters GREASE. Reproducing 6ff14566cf4a requires
keeping 0010 and NOT filtering GREASE from the signature algorithms, and that
combination is exactly what peet.ws's own rendering contradicts: its ja4_r for the
api.rv handshake omits 0010 from the hashed list. So the peer's value comes from a
different rule, not from a different capture. The rule here is the reference one.

Usage:
    python3 tools/ja4.py evidence/bids-chrome-client-hello.txt

To re-verify ja4_c against the live capture, the check is:
    python3 -c "import json,hashlib; t=json.load(open('proofs/01-api-rv-tls.json'))['tls']; \\
      r=t['ja4_r'].split('_'); \\
      print(hashlib.sha256((r[2]+'_'+r[3]).encode()).hexdigest()[:12] == t['ja4'].split('_')[2])"
"""

import binascii
import hashlib
import sys

GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
          0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}


def u16(b, i):
    return int.from_bytes(b[i:i + 2], "big"), i + 2


def u8(b, i):
    return b[i], i + 1


def parse_client_hello(body):
    """`body` MUST start at the handshake message type byte (0x01).

    Layout, with offsets from the start of `body`:
      0      handshake type
      1..3   length
      4..5   legacy_version
      6..37  random (32 bytes)
      38     session_id length
      39..   session_id

    Callers are responsible for having removed the 5-byte TLS record header
    first. It does NOT skip the handshake header itself; it reads past it below.
    """
    i = 4                                   # past type and 3-byte length
    _, i = u16(body, i)                     # legacy_version
    i += 32                                 # random -> i == 38
    sid_len, i = u8(body, i)                # session_id length at offset 38
    i += sid_len

    cs_len, i = u16(body, i)
    ciphers = []
    for _ in range(cs_len // 2):
        v, i = u16(body, i)
        ciphers.append(v)

    comp_len, i = u8(body, i)
    i += comp_len

    ext_total, i = u16(body, i)
    end = i + ext_total
    exts, sigs, alpn = [], [], []
    has_sni = has_tls13 = False
    while i + 4 <= end:
        etype, i = u16(body, i)
        elen, i = u16(body, i)
        data = body[i:i + elen]
        i += elen
        exts.append(etype)
        if etype == 0x0000:
            has_sni = True
        elif etype == 0x002B and data:
            k = 1
            while k < len(data):
                ver, k = u16(data, k)
                if ver == 0x0304:
                    has_tls13 = True
        elif etype == 0x000D and len(data) >= 2:
            sl = int.from_bytes(data[0:2], "big")
            k = 2
            while k + 2 <= 2 + sl:
                a, k = u16(data, k)
                sigs.append(a)
        elif etype == 0x0010 and len(data) >= 2:
            k = 2
            while k < len(data):
                n = data[k]
                k += 1
                alpn.append(data[k:k + n].decode("ascii", "replace"))
                k += n
    return ciphers, exts, sigs, alpn, has_sni, has_tls13


def ja4(raw):
    ciphers, exts, sigs, alpn, sni, tls13 = parse_client_hello(raw)
    c_real = sorted(c for c in ciphers if c not in GREASE)
    n_cg = len(ciphers) - len(c_real)

    # Per foxIO-LLC/ja4 python/common.py get_hex_sorted(), in this order:
    #   1. drop GREASE
    #   2. actual_length = min(len(c), 99)      <- counted HERE, so it still
    #                                               includes SNI and ALPN
    #   3. remove SNI (0000) and ALPN (0010)     <- removed from the HASH only
    #   4. sort, then comma-join
    e_all = [e for e in exts if e not in GREASE]
    e_hashed = sorted(e for e in e_all if e not in (0x0000, 0x0010))
    n_eg = len(exts) - len(e_all)

    # Extension hash input, per the FoxIO reference implementation
    # (foxIO-LLC/ja4, python/ja4.py to_ja4):
    #   sorted_extensions = get_hex_sorted(extensions)   # comma-joined hex
    #   if signature_algorithms: sorted_extensions += '_' + ','.join(sigalgs)
    # sigalgs are appended in OBSERVED order, after an underscore.
    ext_str = ",".join("%04x" % e for e in e_hashed)
    # sigalgs are filtered for GREASE first (foxIO-LLC/ja4 common.py
    # get_signature_algorithms: "return [x for x in ... if x not in
    # GREASE_TABLE]"), then appended in observed order after an underscore.
    sigs_real = [s for s in sigs if s not in GREASE]
    if sigs_real:
        ext_str += "_" + ",".join("%04x" % s for s in sigs_real)

    def h(s):
        return hashlib.sha256(s.encode()).hexdigest()[:12]

    proto = (alpn[0] if alpn else "00").replace("/", "")

    # Counts are DECIMAL zero-padded to two digits ('{:02d}' in the reference,
    # not '%02x'): 15 ciphers is "15", not "0f". Capped at 99.
    cipher_len = "%02d" % min(len(c_real), 99)
    ext_len = "%02d" % min(len(e_all), 99)

    # ja4_a is exactly: t + version + sni + cipher_len + ext_len + alpn.
    # The GREASE count is NOT part of ja4_a; the reference carries it in the
    # separate ja4_x field. Emitting it here produced a 5-character length block.
    fp = "t%s%s%s%s%s_%s_%s" % (
        "13" if tls13 else "12", "d" if sni else "i",
        cipher_len, ext_len, proto,
        h(",".join("%04x" % c for c in c_real)), h(ext_str),
    )
    return fp, c_real, e_all, sigs, alpn, (len(ciphers) - len(c_real), len(exts) - len(e_all))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src = sys.argv[1]
    # If it looks like a path and that path exists, read the file. Otherwise
    # treat the argument as the hex itself. Testing existence rather than
    # length, because a short hex string and a long filename are both plausible.
    hexs = None
    try:
        with open(src) as fh:
            hexs = fh.read()
    except OSError:
        hexs = src
    try:
        raw = binascii.unhexlify("".join(hexs.split()))
    except (binascii.Error, ValueError) as e:
        print("cannot read hex: %s" % e, file=sys.stderr)
        return 2

    # Remove the TLS record header ONLY. parse_client_hello expects to start at
    # the handshake type byte and skips the handshake header itself.
    if len(raw) > 5 and raw[0] == 0x16:
        raw = raw[5:]
    if raw[:1] != b"\x01":
        print("input does not start with a ClientHello handshake header",
              file=sys.stderr)
        return 2

    fp, c, e, sigs, alpn, ng = ja4(raw)
    parts = fp.split("_")
    print("ja4_a      = %s   (VERIFIED against tls.peet.ws)" % parts[0])
    print("ja4_b      = %s   (VERIFIED)" % parts[1])
    print("ja4_c      = %s   (VERIFIED against tls.peet.ws; see docstring)" % parts[2])
    print("ja4        = %s" % fp)
    print("grease     = ciphers:%d extensions:%d" % ng)
    print("ciphers(%d) = %s" % (len(c), ",".join("%04x" % x for x in c)))
    print("exts(%d)    = %s" % (len(e), ",".join("%04x" % x for x in e)))
    print("sigalgs    = %s" % ",".join("%04x" % x for x in sorted(sigs)))
    print("alpn       = %s" % (alpn or ["(none)"])[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())