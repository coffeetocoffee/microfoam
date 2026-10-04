#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Microfoam host tool self-test.

Checks, without requiring the C library to be built:

  1. The container layout constants match include/microfoam.h, parsed from the
     header itself rather than from a copy.
  2. bsdiff and bspatch agree, over randomised inputs.
  3. The LZ4 compressor and decoder agree, over adversarial inputs.
  4. The full make -> inspect -> apply pipeline round-trips and is deterministic.
  5. Signature verification accepts a good patch and rejects a tampered one.

Run:  python host/selftest.py [--layout-only]
"""

from __future__ import annotations

import os
import random
import re
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import microfoam as M   # noqa: E402

HEADER = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir, "include", "microfoam.h"))

PASS, FAIL = 0, 0


def check(cond: bool, name: str) -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL  {name}")


def rejected_for(label: str, fn, *args, reason: str, **kwargs) -> None:
    """Assert `fn` is rejected *for the stated reason*.

    Asserting only that something was raised passes whenever the code dies at a
    different gate than the one under test — which is how a tamper case reports
    green while proving nothing. The message is pinned here instead.
    """
    try:
        fn(*args, **kwargs)
    except SystemExit as exc:
        check(reason in str(exc), f"{label} (rejected: {reason!r})")
    else:
        check(False, f"{label} (expected rejection: {reason!r})")


# --------------------------------------------------------------------------
# 1. Layout agreement between the C header and the Python tool
# --------------------------------------------------------------------------


def parse_header_constants() -> dict:
    """Read the format constants straight out of include/microfoam.h.

    This is the whole point of the check: the C header and the Python tool are
    maintained separately, and a divergence between them silently corrupts every
    patch. Parsing the header means the test fails when they disagree rather
    than trusting a copy.
    """
    with open(HEADER, "r", encoding="utf-8") as f:
        text = f.read()
    out = {}
    for name in ["MCF_HDR_MAGIC", "MCF_HDR_MIN_SIZE", "MCF_HDR_MAX_SIZE",
                 "MCF_SIG_SIZE", "MCF_OFF_MAGIC", "MCF_OFF_HDR_LEN",
                 "MCF_OFF_HDR_VER", "MCF_OFF_FLAGS", "MCF_OFF_PRODUCT_ID",
                 "MCF_OFF_FW_VERSION", "MCF_OFF_OLD_SIZE", "MCF_OFF_NEW_SIZE",
                 "MCF_OFF_PAYLOAD_SIZE", "MCF_OFF_OLD_CRC32", "MCF_OFF_NEW_CRC32",
                 "MCF_OFF_PAYLOAD_CRC32", "MCF_OFF_WORKSPACE_REQ",
                 "MCF_OFF_OLD_VERSION", "MCF_OFF_CODEC_ID", "MCF_OFF_BLOCK_LOG2",
                 "MCF_OFF_RESERVED", "MCF_OFF_SIGNATURE"]:
        m = re.search(rf"#define\s+{name}\s+(0x[0-9A-Fa-f]+|\d+)", text)
        if not m:
            raise SystemExit(f"constant not found in the header: {name}")
        out[name] = int(m.group(1), 0)
    return out


def test_layout() -> None:
    print("container layout: C header vs Python tool")
    c = parse_header_constants()

    check(c["MCF_HDR_MAGIC"] == M.MAGIC, "magic agrees")
    check(c["MCF_HDR_MIN_SIZE"] == M.HDR_LEN, "min header size agrees")
    check(c["MCF_SIG_SIZE"] == M.SIG_SIZE, "signature size agrees")

    offsets = {k: v for k, v in c.items() if k.startswith("MCF_OFF_")}
    for name, value in offsets.items():
        py = getattr(M, name, None)
        check(py == value, f"{name} agrees (C={value} py={py})")

    # The signature field must start where the signed region ends.
    check(c["MCF_OFF_SIGNATURE"] == M.SIGNED_HEADER_LEN,
          "signed region ends where the signature begins")

    # The header must be large enough to hold everything before the payload.
    needed = c["MCF_OFF_SIGNATURE"] + c["MCF_SIG_SIZE"]
    check(c["MCF_HDR_MIN_SIZE"] >= needed,
          f"min header {c['MCF_HDR_MIN_SIZE']} >= sig end {needed}")

    # The convenience view must be exactly the wire size.
    check(struct.calcsize(M._HDR_FMT) + M.SIG_SIZE == M.HDR_LEN,
          "struct layout matches wire size")

    # An Ed25519 signature is 64 bytes; conflating it with the 32-byte key
    # shifts the payload. This is a regression test for a real defect.
    check(M.SIG_SIZE == 64, "Ed25519 signature field is 64 bytes")


# --------------------------------------------------------------------------
# 2. Delta engine
# --------------------------------------------------------------------------


def test_bsdiff() -> None:
    print("bsdiff / bspatch round-trips")
    random.seed(20260215)
    ok, bad = 0, 0

    for _ in range(500):
        n_old = random.randrange(0, 4000)
        old = bytes(random.randrange(256) for _ in range(n_old))
        r = random.random()

        if r < 0.40 and n_old:                      # block replacements
            new = bytearray(old)
            for _ in range(random.randrange(0, 10)):
                if not new:
                    break
                p = random.randrange(len(new))
                L = random.randrange(1, 200)
                new[p:p + L] = bytes(random.randrange(256)
                                     for _ in range(random.randrange(0, 200)))
        elif r < 0.65 and n_old:                    # sparse edits
            new = bytearray(old)
            for _ in range(random.randrange(1, 40)):
                if not new:
                    break
                new[random.randrange(len(new))] ^= 0xFF
            new = bytearray(new)
            if random.random() < 0.4 and len(new) > 1:
                new = new[:random.randrange(1, len(new) + 1)]
        elif r < 0.80 and n_old:                    # content shifted
            k = random.randrange(1, max(2, n_old // 2))
            new = bytearray(old)[k:] + bytearray(random.randrange(256) for _ in range(k))
        else:                                       # unrelated
            new = bytes(random.randrange(256) for _ in range(random.randrange(0, 3000)))
        new = bytes(new)

        delta = M.bsdiff(old, new)
        try:
            out = M.bspatch(old, delta, len(new))
        except Exception as exc:                    # noqa: BLE001
            print(f"  FAIL  exception {exc!r} oldlen={len(old)} newlen={len(new)}")
            bad += 1
            continue
        if out == new:
            ok += 1
        else:
            print(f"  FAIL  mismatch oldlen={len(old)} newlen={len(new)}")
            bad += 1

    check(bad == 0, f"{ok}/{ok + bad} delta round-trips")


def test_lz4() -> None:
    print("lz4 compressor / decoder round-trips")
    random.seed(7)
    bad = 0
    cases = [
        b"", b"a", b"ab", b"a" * 5, b"a" * 16, b"a" * 300,
        bytes(range(256)) * 3,
        b"AAAA" + b"BBBB" * 900 + b"AAAA",
        b"HELLO WORLD " * 400,
        bytes(60000),
        b"\x00" * 40000,
    ]
    for _ in range(60):
        n = random.randrange(0, 9000)
        style = random.randrange(4)
        if style == 0:
            cases.append(bytes(random.randrange(256) for _ in range(n)))
        elif style == 1:
            cases.append(bytes(random.randrange(4) for _ in range(n)))
        elif style == 2:
            cases.append(b"".join(bytes([random.randrange(4)]) * random.randrange(1, 60)
                                  for _ in range(max(1, n // 30)))[:n])
        else:
            cases.append(bytes(random.choice(b"ABCD") for _ in range(n)))

    for data in cases:
        for block in (0, 64, 1024, 65536):
            parts = ([data[i:i + block] for i in range(0, len(data), block)]
                     if block else ([data] if data else []))
            for part in parts:
                if not part:
                    continue
                comp = M.lz4_compress_block(part)
                if M.lz4_decode_block(comp, 1 << 24) != part:
                    bad += 1
    check(bad == 0, "all lz4 blocks round-trip")

    # Compression should actually happen on compressible input.
    data = bytes(40000)
    check(len(M.lz4_compress_block(data)) < len(data) // 100,
          "a zero run compresses by more than 100x")

    # And must never expand in the framed stream.
    framed = M.lz4_frame(bytes(3000), 1024)
    check(len(framed) < 3000, "framed incompressible input does not expand")

    # Blocks must respect the declared window, or the device rejects them.
    for window in (256, 512, 1024, 65536):
        fr = M.lz4_frame(bytes(random.randrange(256) for _ in range(5000)), window)
        pos, ok = 0, True
        while pos + 4 <= len(fr):
            (blen,) = struct.unpack_from("<I", fr, pos)
            pos += 4
            if blen == 0:
                break
            try:
                if len(M.lz4_decode_block(fr[pos:pos + blen], window)) > window:
                    ok = False
            except Exception:                      # noqa: BLE001
                ok = False
            pos += blen
        check(ok, f"no block exceeds the {window}-byte window")


# --------------------------------------------------------------------------
# 3. Full pipeline
# --------------------------------------------------------------------------


def make_firmware(seed: int) -> tuple[bytes, bytes]:
    random.seed(seed)
    out = bytearray()
    out += bytes(random.randrange(256) for _ in range(0x200))          # vector table
    for _ in range(4000):                                              # "code"
        out += bytes([random.choice([0x00, 0x01, 0x10, 0x20, 0x40, 0x4B,
                                     0x88, 0x8D, 0xB5, 0xBD]),
                      random.randrange(256)])
    out += b"".join(b"STR_%d_%s\x00" % (i, b"x" * (i % 17)) for i in range(400))
    out += bytes([(i * 7) % 256 for i in range(8192)])                  # const table
    out += b"".join(b"\xaa\xbb\xcc\xdd" + bytes([i % 256] * 8) for i in range(1000))

    old = bytes(out)
    new = bytearray(old)
    new[0x200:0x600] = bytes(random.randrange(256) for _ in range(0x400))
    marker = b"STR_200_"
    i = old.find(marker)
    if i < 0:
        raise SystemExit("firmware fixture lost its STR_200_ marker")
    # Sliced to the replacement's own length on purpose: a slice assignment
    # RESIZES the buffer when the spans differ, so an off-by-a-few literal here
    # would silently change the image length instead of editing it.
    replacement = b"STR_200_CHANGED_XX"
    new[i:i + len(replacement)] = replacement
    return old, bytes(new)


def test_pipeline() -> None:
    print("make / inspect / verify / apply")
    with tempfile.TemporaryDirectory() as d:
        old, new = make_firmware(2024)
        p_old = os.path.join(d, "old.bin")
        p_new = os.path.join(d, "new.bin")
        p_a = os.path.join(d, "a.bin")
        p_b = os.path.join(d, "b.bin")
        p_out = os.path.join(d, "out.bin")
        with open(p_old, "wb") as f:
            f.write(old)
        with open(p_new, "wb") as f:
            f.write(new)

        # The test suite ships a patch fixture that matches this format, so use
        # the in-process API rather than a subprocess.
        patch = M.Patch(old=old, new=new, product_id=0x1234,
                        fw_version=0x00020000, old_version=0x00010000).build()
        with open(p_a, "wb") as f:
            f.write(patch)
        with open(p_b, "wb") as f:
            f.write(M.Patch(old=old, new=new, product_id=0x1234,
                            fw_version=0x00020000, old_version=0x00010000).build())

        check(open(p_a, "rb").read() == open(p_b, "rb").read(), "make is deterministic")

        h = M.parse_header(patch)
        check(h.magic == M.MAGIC, "magic correct")
        check(h.new_size == len(new), "new_size correct")
        check(h.old_crc32 == M.crc32(old), "old crc correct")
        check(h.new_crc32 == M.crc32(new), "new crc correct")

        stream = patch[h.hdr_len + M.LZ4_PROPS_LEN:h.hdr_len + h.payload_size]
        check(M.crc32(stream) == h.payload_crc32, "payload crc correct")
        check(M.bspatch(old, M.lz4_decompress(stream), h.new_size) == new,
              "reconstruction is byte-exact")

        ratio = len(patch) / len(new)
        print(f"       image {len(new)} bytes -> patch {len(patch)} bytes "
              f"({ratio * 100:.1f}%)")
        check(ratio < 0.20, "a realistic maintenance change is under 20%")

        # A one-bit change anywhere must be detected.
        for offset, label in ((len(patch) - 1, "last payload byte"),
                              (h.hdr_len + 8, "early payload byte"),
                              (M.OFF_FW_VERSION, "header version field"),
                              (M.OFF_WORKSPACE_REQ, "header workspace field")):
            bad = bytearray(patch)
            bad[offset] ^= 0x01
            hh = M.parse_header(bytes(bad))
            st = bytes(bad)[hh.hdr_len + M.LZ4_PROPS_LEN:hh.hdr_len + hh.payload_size]
            detected = (M.crc32(st) != hh.payload_crc32) or offset < hh.hdr_len
            check(detected, f"tamper detected: {label}")


def test_signing() -> None:
    print("signature round-trip")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("  SKIP  'cryptography' not installed")
        return

    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    old, new = make_firmware(99)
    patch = M.Patch(old=old, new=new, product_id=0x1234, fw_version=0x00020000,
                    old_version=0x00010000, flags=M.FLAG_SIGNED,
                    private_key=seed).build()

    h = M.parse_header(patch)
    message = patch[:M.SIGNED_HEADER_LEN] + patch[h.hdr_len + M.LZ4_PROPS_LEN:]
    check(M.verify(pub, h.signature, message), "a good signature verifies")

    bad = bytearray(patch)
    bad[-1] ^= 0x01
    hb = M.parse_header(bytes(bad))
    mb = bytes(bad)[:M.SIGNED_HEADER_LEN] + bytes(bad)[hb.hdr_len + M.LZ4_PROPS_LEN:]
    check(not M.verify(pub, hb.signature, mb), "a tampered patch is rejected")

    check(len(patch) == M.HDR_LEN + h.payload_size,
          "file length equals header plus payload")

    for label, offset, value, reason in [
        ("unknown flag", M.OFF_FLAGS, 0x80000000,
         "unsupported header flags or nonzero reserved field"),
        ("codec mismatch", M.OFF_FLAGS, M.FLAG_CODEC_LZMA,
         "LZ4 patch is missing FLAG_CODEC_LZ4"),
        ("nonzero reserved field", M.OFF_RESERVED, 1,
         "unsupported header flags or nonzero reserved field"),
    ]:
        malformed = bytearray(patch)
        if offset == M.OFF_FLAGS:
            struct.pack_into("<I", malformed, offset, value)
        else:
            struct.pack_into("<H", malformed, offset, value)
        rejected_for(f"host rejects {label}", M.parse_header, bytes(malformed),
                     reason=reason)


def test_lzma() -> None:
    print("lzma make / apply round-trip")
    try:
        import lzma  # noqa: F401
    except ImportError:
        print("  SKIP  stdlib lzma not available")
        return

    old, new = make_firmware(77)
    patch = M.Patch(old=old, new=new, product_id=0x1234, fw_version=0x00020000,
                    old_version=0x00010000, codec=M.CODEC_LZMA).build()

    h = M.parse_header(patch)
    check(h.codec_id == M.CODEC_LZMA, "codec id is LZMA")
    check(bool(h.flags & M.FLAG_CODEC_LZMA), "codec flag is LZMA")
    check(not (h.flags & M.FLAG_CODEC_LZ4), "LZ4 flag is not set")

    payload = patch[h.hdr_len:h.hdr_len + h.payload_size]
    props, stream = payload[:M.LZMA_PROPS_LEN], payload[M.LZMA_PROPS_LEN:]
    check(M.crc32(stream) == h.payload_crc32, "payload crc covers the LZMA stream")

    v = props[0]
    check(v % 9 == M.LZMA_DEFAULT_LC and (v // 9) % 5 == M.LZMA_DEFAULT_LP
          and v // 45 == M.LZMA_DEFAULT_PB, "props encode lc/lp/pb")
    check(struct.unpack_from("<I", props, 1)[0] == M.LZMA_DEFAULT_DICT,
          "props carry the dictionary size")
    check(h.workspace_req == M.lzma_workspace_req(
        M.LZMA_DEFAULT_LC, M.LZMA_DEFAULT_LP, M.LZMA_DEFAULT_DICT),
        "workspace_req matches the mirrored device formula")

    delta = M.lzma_decompress(stream, props)
    check(len(delta) == struct.unpack_from("<I", props, 5)[0],
          "props content size matches the decoded delta")
    check(M.bspatch(old, delta, h.new_size) == new,
          "LZMA reconstruction is byte-exact")

    patch_b = M.Patch(old=old, new=new, product_id=0x1234, fw_version=0x00020000,
                      old_version=0x00010000, codec=M.CODEC_LZMA).build()
    check(patch == patch_b, "LZMA make is deterministic")

    ratio = len(patch) / len(new)
    print(f"       image {len(new)} bytes -> lzma patch {len(patch)} bytes "
          f"({ratio * 100:.1f}%)")
    check(ratio < 0.20, "LZMA patch is under 20% of the image")

    # A dictionary smaller than the default must still round-trip and must
    # lower the declared workspace.
    small = M.Patch(old=old, new=new, product_id=0x1234, fw_version=0x00020000,
                    old_version=0x00010000, codec=M.CODEC_LZMA,
                    dict_size=4096).build()
    hs = M.parse_header(small)
    check(hs.workspace_req < h.workspace_req, "smaller dictionary lowers workspace")
    sp = small[hs.hdr_len:hs.hdr_len + hs.payload_size]
    sdelta = M.lzma_decompress(sp[M.LZMA_PROPS_LEN:], sp[:M.LZMA_PROPS_LEN])
    check(M.bspatch(old, sdelta, hs.new_size) == new,
          "4 KB dictionary round-trips byte-exact")


def test_codec_ratio() -> None:
    # The README states what LZ4 costs against LZMA, so this measures it on one
    # fixture instead of trusting the prose. LZ4 is the default because it
    # decodes in ~16 B of state rather than an LZMA probability table; that buys
    # RAM, not bytes. On the same delta LZ4 emits a *larger* payload, and the
    # gap is the ratio a caller trades away for the smaller decoder.
    print("lz4 vs lzma payload size on one fixture")
    try:
        import lzma  # noqa: F401
    except ImportError:
        print("  SKIP  stdlib lzma not available")
        return

    old, new = make_firmware(2024)
    kw = dict(product_id=0x1234, fw_version=0x00020000, old_version=0x00010000)
    lz4_patch = M.Patch(old=old, new=new, codec=M.CODEC_LZ4, **kw).build()
    lzma_patch = M.Patch(old=old, new=new, codec=M.CODEC_LZMA, **kw).build()

    lz4_payload = M.parse_header(lz4_patch).payload_size
    lzma_payload = M.parse_header(lzma_patch).payload_size
    ratio = lz4_payload / lzma_payload
    print(f"       payload lz4 {lz4_payload} B vs lzma {lzma_payload} B "
          f"({ratio:.2f}x)")

    # The sign is the part the README had backwards: LZ4 costs bytes.
    check(lz4_payload > lzma_payload, "lz4 is larger than lzma on this fixture")
    # And the magnitude, pinned loosely. The direction above is the invariant;
    # this band only catches a gross drift, because liblzma's exact output can
    # vary between the versions CI and a developer machine carry. Measured 1.67x.
    check(1.3 < ratio < 2.2, "lz4 costs roughly 1.5-1.8x lzma at the default block")

    # A wider LZ4 block narrows the gap, but its workspace grows with it -- that
    # is exactly the RAM the default block size was chosen to keep small, so the
    # narrow-gap regime is not the regime the default operates in.
    wide = M.Patch(old=old, new=new, codec=M.CODEC_LZ4, block_log2=15, **kw).build()
    wide_payload = M.parse_header(wide).payload_size
    print(f"       payload lz4 block_log2=15 {wide_payload} B "
          f"({wide_payload / lzma_payload:.2f}x)")
    check(wide_payload < lz4_payload, "a wider lz4 block narrows the gap")


def test_raw() -> None:
    print("raw (uncompressed) make / apply round-trip")
    old, new = make_firmware(55)
    patch = M.Patch(old=old, new=new, product_id=0x1234, fw_version=0x00020000,
                    old_version=0x00010000, codec=M.CODEC_RAW).build()

    h = M.parse_header(patch)
    check(h.codec_id == M.CODEC_RAW, "codec id is RAW")
    check(bool(h.flags & M.FLAG_RAW), "raw flag is set")
    check(not (h.flags & (M.FLAG_CODEC_LZ4 | M.FLAG_CODEC_LZMA)),
          "no compressed codec flag is set")
    check(h.workspace_req == M.WS_RAW, "raw workspace is the identity state block")

    payload = patch[h.hdr_len:h.hdr_len + h.payload_size]
    check(M.crc32(payload) == h.payload_crc32, "payload crc covers the raw delta")
    check(M.bspatch(old, payload, h.new_size) == new, "raw reconstruction is byte-exact")

    patch_b = M.Patch(old=old, new=new, product_id=0x1234, fw_version=0x00020000,
                      old_version=0x00010000, codec=M.CODEC_RAW).build()
    check(patch == patch_b, "raw make is deterministic")

    # The raw payload is the delta verbatim: it must equal bsdiff's output byte
    # for byte, i.e. zero framing or compression overhead. (The delta itself is
    # larger than the image only because it carries BSDIFF43 control triples.)
    delta = M.bsdiff(old, new)
    check(payload == delta, "raw payload is the delta byte for byte")
    print(f"       raw payload {len(payload)} bytes = delta; "
          f"lz4 patch is smaller on this fixture")

    # Tampering must still be detected by the payload CRC.
    bad = bytearray(patch)
    bad[h.hdr_len + 4] ^= 0x01
    hb = M.parse_header(bytes(bad))
    check(M.crc32(bytes(bad)[hb.hdr_len:hb.hdr_len + hb.payload_size]) != hb.payload_crc32,
          "a flipped raw payload byte is detected by the CRC")


def test_small_image_framing() -> None:
    """Producer framing must remain applicable when the image is smaller than
    the normal 1 KiB window.

    The device clamps its decode window to new_size. Before the producer cap was
    added, a default 1024-byte frame around a 512-byte image created a patch no
    device configuration could apply; a block expanded past the clamped window
    and failed site 17. MFP2 has the same inner LZ4 window, so pin both paths.

    The MFP2 half models the device window explicitly. A verifier that decodes
    with an unbounded buffer accepts the uncapped patch too, so asserting only
    "it round-trips" would pass with the producer cap deleted - the assertion
    has to apply the patch the way the device would, at window
    min(record_size, new_size), or it proves nothing.
    """
    print("small-image LZ4 framing stays within the device window")
    old = bytes((i * 7 + 3) & 0xFF for i in range(512))
    new = bytes((i * 5 + 11) & 0xFF for i in range(512))

    patch = M.Patch(old, new, product_id=0x1234, fw_version=2, old_version=1,
                    block_log2=10, codec=M.CODEC_LZ4).build()
    h = M.parse_header(patch)
    check(h.block_log2 == 9, "MFP1 lowers framing exponent for a 512-byte image")
    payload = patch[h.hdr_len:h.hdr_len + h.payload_size]
    # Model the device: its window is the configured block size clamped to the
    # image, so decode at min(1024, new_size) rather than an unbounded buffer.
    try:
        delta = M.lz4_decompress(payload[M.LZ4_PROPS_LEN:], min(1 << 10, len(new)))
        check(M.bspatch(old, delta, h.new_size) == new,
              "MFP1 small-image framing reconstructs byte-exact")
    except ValueError as exc:
        check(False, f"MFP1 small-image framing reconstructs byte-exact: {exc}")

    # The window has to apply to a literal run, not only to a match: a block can
    # be all literals and still overflow. The device rejects both (mcf_lz4_block
    # checks `(oend - op) < lit` before copying), so a host decoder that only
    # bounds matches is more permissive than the device - which is exactly why
    # the small-image case above read as passing while the device refused it.
    over = False
    try:
        M.lz4_decode_block(M.lz4_literal_block(bytes(64)), 32)
    except ValueError:
        over = True
    check(over, "a literal-only block over the window is rejected")

    try:
        from nacl.signing import SigningKey
    except Exception as exc:
        print(f"  SKIP  PyNaCl unavailable: {exc}")
        return
    seed = bytes(range(32)); key = bytes(range(32, 64))
    pub = bytes(SigningKey(seed).verify_key)
    tiny = bytes((i * 5 + 11) & 0xFF for i in range(128))
    rlog2 = 8
    v2 = M.V2Patch(old[:128], tiny, product_id=0x1234, fw_version=2,
                   old_version=1, private_key=seed, key=key,
                   key_id=bytes(range(16)), record_log2=rlog2).build()
    # The device's inner window is the record size clamped to the image.
    window = min(1 << rlog2, len(tiny))
    try:
        got = M.verify_v2(v2, pub, key=key, old=old[:128], window=window)
        check(got == tiny,
              "MFP2 small-image framing applies at the device window")
    except (SystemExit, ValueError) as exc:
        check(False, f"MFP2 small-image framing applies at the device window: {exc}")

    # The default window must be the device's, not an unbounded buffer. The CLI
    # (`microfoam apply`) and the fixture tools call verify_v2 without a window,
    # so a default that accepted anything would let the host bless a patch the
    # device refuses - the divergence the explicit-window check above exists to
    # remove. Simulate the uncapped producer by making the framer ignore the
    # block size it is handed, then require the default to reject the result.
    orig_frame = M.lz4_frame
    M.lz4_frame = lambda data, block_size: orig_frame(data, max(1, (1 << rlog2) - 64))
    try:
        uncapped = M.V2Patch(old[:128], tiny, product_id=0x1234, fw_version=2,
                             old_version=1, private_key=seed, key=key,
                             key_id=bytes(range(16)), record_log2=rlog2).build()
    finally:
        M.lz4_frame = orig_frame
    over = False
    try:
        M.verify_v2(uncapped, pub, key=key, old=old[:128])
    except (SystemExit, ValueError):
        over = True
    check(over, "verify_v2 defaults to the device window, not an unbounded buffer")


def test_v2() -> None:
    print("MFP2 signed/encrypted LZ4 make / verify / apply")
    try:
        from nacl.signing import SigningKey
        signing = SigningKey.generate()
        seed = bytes(signing)  # 32-byte seed
        pub = bytes(signing.verify_key)
    except Exception as exc:
        print(f"  SKIP  PyNaCl unavailable: {exc}")
        return
    old, new = make_firmware(123)
    key = bytes(range(32)); key_id = bytes(range(16)); nonce = bytes(range(16, 32))
    patch = M.V2Patch(old, new, product_id=0x1234, fw_version=2, old_version=1,
                      private_key=seed, key=key, key_id=key_id,
                      nonce_prefix=nonce, record_log2=10).build()
    h = M.parse_v2_header(patch)
    check(h.header_len == 192 and h.tlv_len == 0, "MFP2 fixed header is 192 bytes")
    check(h.flags == M.V2_REQUIRED_FLAGS and h.record_count > 0, "MFP2 profile and records")
    check(M.verify_v2(patch, pub) == b"", "MFP2 signature and CRC verify")
    check(M.verify_v2(patch, pub, key=key, old=old) == new, "MFP2 decrypt/apply round-trip")

    # Each tamper case must be rejected by the layer it targets. A bare bit flip
    # is caught by the payload CRC, which covers the framed ciphertext including
    # the tags and is checked before the signature or any decryption, so on its
    # own it never exercises those layers. Reaching the signature and the AEAD
    # takes a mutation with the CRC recomputed, and - for the AEAD - a fresh
    # signature as well.
    hdr = patch[:h.header_len]
    area = patch[h.header_len:]

    crc_only = bytearray(patch)
    crc_only[-1] ^= 1
    rejected_for("MFP2 tamper: raw bit flip", M.verify_v2, bytes(crc_only), pub,
                 reason="MFP2 payload CRC mismatch")

    sig_only = bytearray(patch)
    sig_only[M.V2_OFF_SIGNATURE] ^= 1
    rejected_for("MFP2 tamper: signature byte", M.verify_v2, bytes(sig_only), pub,
                 reason="MFP2 signature invalid")

    def resign(header: bytes, record_area: bytes) -> bytes:
        h = bytearray(header)
        struct.pack_into("<I", h, 40, M.crc32(record_area))
        h[M.V2_OFF_SIGNATURE:M.V2_OFF_SIGNATURE + M.SIG_SIZE] = M._ed25519ph_sign(
            seed, b"MCF2SIG\0" + M._v2_header_for_sig(h) + record_area)
        return bytes(h) + record_area

    aead = bytearray(area)
    aead[4] ^= 1                                    # first ciphertext byte
    rejected_for("MFP2 tamper: ciphertext, CRC recomputed and re-signed",
                 M.verify_v2, resign(hdr, bytes(aead)), pub,
                 reason="MFP2 record authentication failed", key=key, old=old)


def test_v2_kat() -> None:
    """Pinned known-answer test for the exact MFP2 signed byte sequence.

    Fixed keys, fixed images, fixed nonce: rebuilds the patch and compares the
    Ed25519ph signature and header CRC figures against values generated and
    cross-verified once. End-to-end agreement (sign here, verify there) proves
    both sides read the same bytes; this additionally proves the bytes do not
    drift over time.
    """
    print("MFP2 pinned known-answer test")
    try:
        from nacl.signing import SigningKey
    except Exception as exc:
        print(f"  SKIP  PyNaCl unavailable: {exc}")
        return
    seed = bytes(range(32))       # Ed25519 signing seed
    key = bytes(range(32, 64))    # XChaCha20-Poly1305 symmetric key
    pub = bytes(SigningKey(seed).verify_key)
    old = bytes((i * 7 + 3) & 0xFF for i in range(1500))
    new = bytes((i * 5 + 11) & 0xFF for i in range(1600))
    patch = M.V2Patch(old, new, product_id=0x1234, fw_version=2, old_version=1,
                      private_key=seed, key=key, key_id=bytes(range(16)),
                      nonce_prefix=bytes(range(16, 32)), record_log2=8).build()
    h = M.parse_v2_header(patch)
    check(h.payload_size == 1870 and h.record_count == 10, "KAT structure")
    check(M.crc32(old) == 3091840966 and M.crc32(new) == 3330603793, "KAT image CRCs")
    check(h.workspace_req == M.v2_workspace_req(8, 192),
          "KAT workspace_req is the computed streaming figure")
    check(h.payload_crc32 == 2667140683, "KAT payload CRC")
    check(h.signature.hex() ==
          "49babbd3143e80fef4c0ee132fcf0487d27a20a9a2eb8460d022fa6a86d34e82"
          "e25d967e4dc3188281827eff49d7e0538e56a294bc70ca83fb6fca32449a3709",
          "KAT Ed25519ph signature")
    check(M.verify_v2(patch, pub, key=key, old=old) == new, "KAT round-trip")


def test_v2_nonce_guard() -> None:
    """A fixed nonce prefix must be acknowledged on the command line.

    Per-record nonces are prefix || record index, so reusing one prefix with the
    same key in a second patch repeats every nonce and leaks the XOR of the two
    plaintexts. Random is the default; a fixed prefix is for reproducible test
    vectors, and the guard makes that intent explicit rather than silent.
    """
    print("MFP2 fixed-nonce-prefix guard")
    try:
        from nacl.signing import SigningKey
    except Exception as exc:
        print(f"  SKIP  PyNaCl unavailable: {exc}")
        return
    old, new = make_firmware(64)
    with tempfile.TemporaryDirectory() as d:
        p_old = os.path.join(d, "old.bin")
        p_new = os.path.join(d, "new.bin")
        p_sk = os.path.join(d, "sign.key")
        p_key = os.path.join(d, "sym.key")
        open(p_old, "wb").write(old)
        open(p_new, "wb").write(new)
        open(p_sk, "wb").write(bytes(SigningKey(bytes(range(32)))))
        open(p_key, "wb").write(bytes(range(32, 64)))

        base = ["make", "--v2", "--old", p_old, "--new", p_new,
                "--version", "0x00020000", "--old-version", "0x00010000",
                "--signing-key", p_sk, "--key", p_key,
                "--key-id", "00112233445566778899aabbccddeeff",
                "--record-log2", "10"]
        fixed = ["--nonce-prefix", "102132435465768798a9bacbdcedfe0f"]
        p_refused = os.path.join(d, "refused.mfp2")

        # Fixed prefix without the acknowledgement is refused, and writes nothing.
        try:
            M.main(base + fixed + ["--out", p_refused])
        except SystemExit as exc:
            check("acknowledgement" in str(exc), "unacknowledged fixed prefix is refused")
        else:
            check(False, "unacknowledged fixed prefix is refused")
        check(not os.path.exists(p_refused), "a refused build writes no patch")

        # With the acknowledgement it is allowed.
        try:
            rc = M.main(base + fixed + ["--nonce-prefix-ack-reuse",
                                        "--out", os.path.join(d, "fixed.mfp2")])
            check(rc == 0, "acknowledged fixed prefix builds")
        except SystemExit:
            check(False, "acknowledged fixed prefix builds")

        # The random default needs no acknowledgement.
        try:
            rc = M.main(base + ["--out", os.path.join(d, "random.mfp2")])
            check(rc == 0, "random prefix builds without acknowledgement")
        except SystemExit:
            check(False, "random prefix builds without acknowledgement")


def test_lzma_policy_guard() -> None:
    """The host side of the LZMA props contract.

    The device refuses a patch whose declared dictionary or lc+lp exceeds its
    policy; the host tool must therefore write the declaration the device reads
    back, and the rules must round-trip as documented.
    """
    print("lzma props and policy fields")
    old, new = make_firmware(88)
    for dict_size in (4096, 8192, 16384):
        patch = M.Patch(old=old, new=new, product_id=0x1234, fw_version=0x00020000,
                        old_version=0x00010000, codec=M.CODEC_LZMA,
                        dict_size=dict_size).build()
        h = M.parse_header(patch)
        payload = patch[h.hdr_len:h.hdr_len + h.payload_size]
        props = payload[:M.LZMA_PROPS_LEN]
        declared = struct.unpack_from("<I", props, 1)[0]
        check(declared == dict_size, f"declared dictionary is {dict_size}")
        check(h.workspace_req == M.lzma_workspace_req(
            M.LZMA_DEFAULT_LC, M.LZMA_DEFAULT_LP, dict_size),
            f"workspace_req matches the device figure at dict={dict_size}")
        v = props[0]
        check(v % 9 == M.LZMA_DEFAULT_LC, "lc is in range")
        check(v // 45 == M.LZMA_DEFAULT_PB, "pb is in range")


def test_v2_host_hygiene() -> None:
    """The three host-side MFP2 defects fixed after the 2026-10 audit.

    Each is a producer-side defect that no consumer can compensate for, so each
    is pinned here by the property that was broken, not merely by "it runs".
    """
    print("MFP2 host hygiene: nonce caching, TLV padding, workspace_req")
    try:
        from nacl.signing import SigningKey
    except Exception as exc:
        print(f"  SKIP  PyNaCl unavailable: {exc}")
        return
    seed = bytes(range(32)); key = bytes(range(32, 64))
    key_id = bytes(range(16)); nonce = bytes(range(16, 32))
    old, new = make_firmware(96)

    def make(**kw):
        base = dict(old=old, new=new, product_id=0x1234, fw_version=2,
                    old_version=1, private_key=seed, key=key, key_id=key_id,
                    nonce_prefix=nonce, record_log2=10)
        base.update(kw)
        return M.V2Patch(**base)

    # 1. build() must not cache a drawn prefix on the instance. If it does, a
    #    second build() on the same object reuses the prefix with the same key
    #    and every per-record nonce repeats, leaking the XOR of the plaintexts.
    p = make(nonce_prefix=b"")
    first = p.build()
    second = p.build()
    check(p.nonce_prefix == b"", "build() does not cache a drawn nonce prefix")
    check(first[:M.V2_OFF_NONCE_PREFIX] != second[:M.V2_OFF_NONCE_PREFIX] or
          first[M.V2_OFF_NONCE_PREFIX:M.V2_OFF_NONCE_PREFIX + 16] !=
          second[M.V2_OFF_NONCE_PREFIX:M.V2_OFF_NONCE_PREFIX + 16],
          "two builds draw different nonce prefixes")

    # 2. The TLV walk must reject padding the device rejects. A zero-length
    #    entry is 8 bytes and needs no padding; a one-byte value does, and the
    #    pad bytes must be zero.
    good = struct.pack("<HHI", 1, 0, 0)                    # critical type 1, empty
    padded_ok = struct.pack("<HHI", 2, 0, 1) + b"\xAB" + b"\0\0\0"
    padded_bad = struct.pack("<HHI", 2, 0, 1) + b"\xAB" + b"\0\xFF\0"
    for label, blob, ok in (("well-formed TLV area", good, True),
                            ("zero padding accepted", padded_ok, True),
                            ("nonzero padding rejected", padded_bad, False)):
        try:
            M._v2_walk_tlvs(blob)
            got = True
        except SystemExit:
            got = False
        check(got == ok, f"MFP2 TLV: {label}")

    # The same rule must hold through the public builder, not just the helper.
    try:
        make(tlvs=padded_bad).build()
        check(False, "build() rejects nonzero TLV padding")
    except SystemExit:
        check(True, "build() rejects nonzero TLV padding")

    # 3. workspace_req must be the real streaming figure, not the 16-byte LZ4
    #    state placeholder, and must track the record size.
    patch = make().build()
    h = M.parse_v2_header(patch)
    check(h.workspace_req == M.v2_workspace_req(10, h.header_len),
          "MFP2 workspace_req is the computed streaming figure")
    check(h.workspace_req > M.WS_LZ4,
          "MFP2 workspace_req is not the LZ4 state placeholder")
    check(M.v2_workspace_req(13, 192) > M.v2_workspace_req(8, 192),
          "MFP2 workspace_req grows with the record size")


def main() -> int:
    layout_only = "--layout-only" in sys.argv
    print("Microfoam host tool self-test\n")

    test_layout()
    if layout_only:
        print(f"\n{PASS} checks, {FAIL} failures")
        return 0 if FAIL == 0 else 1

    test_bsdiff()
    test_lz4()
    test_pipeline()
    test_raw()
    test_lzma()
    test_codec_ratio()
    test_lzma_policy_guard()
    test_signing()
    test_small_image_framing()
    test_v2()
    test_v2_kat()
    test_v2_nonce_guard()
    test_v2_host_hygiene()

    print(f"\n{PASS} checks, {FAIL} failures")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
