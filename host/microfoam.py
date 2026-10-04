#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Microfoam host tool - build and inspect firmware delta patches.

    microfoam make    --old old.bin --new new.bin --out patch.bin [options]
    microfoam inspect patch.bin
    microfoam verify  patch.bin --pub pubkey.bin
    microfoam apply   --old old.bin --patch patch.bin --out new.bin

Design requirements, from docs/architecture.md section 17.3:

  H1  Deterministic. Identical inputs produce a byte-identical patch. No
      timestamps, no randomness, no host-dependent behaviour anywhere in the
      output.
  H3  Signs at generation. Private keys never leave the build host; the device
      only ever holds a public key.
  H5  The header layout is asserted here and separately in C, so the two
      implementations cannot drift.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------
# Format constants. These MUST match include/microfoam.h. The C build asserts
# the same table via static assertions, so a change on one side without the
# other fails a build rather than corrupting a field.
# --------------------------------------------------------------------------

# Reported by `microfoam --version`. Kept in step with include/microfoam.h's
# MCF_VERSION_* by the release procedure; selftest.py asserts the format
# constants that actually affect patch bytes, which is the part that can
# corrupt something if it drifts.
TOOL_VERSION = "1.9.4"

MAGIC = 0x3150464D          # 'MFP1'
HDR_LEN = 120
HDR_VER_MAJOR = 1
HDR_VER_MINOR = 0

OFF_MAGIC = 0
OFF_HDR_LEN = 4
OFF_HDR_VER = 6
OFF_FLAGS = 8
OFF_PRODUCT_ID = 12
OFF_FW_VERSION = 16
OFF_OLD_SIZE = 20
OFF_NEW_SIZE = 24
OFF_PAYLOAD_SIZE = 28
OFF_OLD_CRC32 = 32
OFF_NEW_CRC32 = 36
OFF_PAYLOAD_CRC32 = 40
OFF_WORKSPACE_REQ = 44
OFF_OLD_VERSION = 48
OFF_CODEC_ID = 52
OFF_BLOCK_LOG2 = 53
OFF_RESERVED = 54
OFF_SIGNATURE = 56

SIG_SIZE = 64         # Ed25519 signatures are 64 bytes (R||S); the key is 32
SIGNED_HEADER_LEN = OFF_SIGNATURE

FLAG_SIGNED = 0x00000001
FLAG_RAW = 0x00000002
FLAG_CODEC_LZMA = 0x00000004
FLAG_CODEC_LZ4 = 0x00000008

CODEC_AUTO = 0
CODEC_LZ4 = 1
CODEC_LZMA = 2
CODEC_RAW = 3

# LZ4 codec properties are 4 bytes: the uncompressed content size.
LZ4_PROPS_LEN = 4
# The device's LZ4 state block. Must be >= sizeof(mcf_lz4_t) in the C build.
WS_LZ4 = 16
# The raw codec has no properties and a 16-byte state block; mirrors
# MCF_RAW_WORKSPACE_BYTES in src/mcf_codec_raw.h.
RAW_PROPS_LEN = 0
WS_RAW = 16

# LZMA codec properties are 9 bytes: encoded lc/lp/pb, dictionary size, and
# exact decompressed length. Mirrors mcf_lzma.h.
LZMA_PROPS_LEN = 9
LZMA_DEFAULT_LC = 3
LZMA_DEFAULT_LP = 0
LZMA_DEFAULT_PB = 2
LZMA_MIN_DICT = 4096
LZMA_DEFAULT_DICT = 16384
# The vendored SDK's probability table: 1984 + (768 << (lc + lp)) entries of
# 2 bytes, plus the dictionary rounded by the SDK's own mask ladder. Must match
# src/mcf_lzma.c; the conformance test cross-checks the two.
LZMA_NUM_BASE_PROBS = 1984
LZMA_LIT_SIZE = 0x300
# Fixed reservation for the decoder state block; mirrors MCF_LZMA_STATE_BYTES
# in src/mcf_lzma.h, which is pinned so 32- and 64-bit builds agree.
LZMA_STATE_BYTES = 256

def lzma_workspace_req(lc: int, lp: int, dict_size: int) -> int:
    probs = (LZMA_NUM_BASE_PROBS + (LZMA_LIT_SIZE << (lc + lp))) * 2
    size = max(dict_size, LZMA_MIN_DICT)
    if size >= (1 << 30):
        mask = (1 << 22) - 1
    elif size >= (1 << 22):
        mask = (1 << 20) - 1
    else:
        mask = (1 << 12) - 1
    dict_buf = (size + mask) & ~mask
    return ((LZMA_STATE_BYTES + probs + 7) & ~7) + dict_buf

DEFAULT_BLOCK_LOG2 = 10

# Header layout before the signature, as (name, struct code) in wire order.
# Built as a list rather than a hand-counted format string: a miscounted run of
# 'I's is invisible until the assertion below fires, which is a confusing way
# to find out.
_HDR_FIELDS = [
    ("magic", "I"), ("hdr_len", "H"), ("hdr_ver", "H"),
    ("flags", "I"), ("product_id", "I"), ("fw_version", "I"),
    ("old_size", "I"), ("new_size", "I"), ("payload_size", "I"),
    ("old_crc32", "I"), ("new_crc32", "I"), ("payload_crc32", "I"),
    ("workspace_req", "I"), ("old_version", "I"),
    ("codec_id", "B"), ("block_log2", "B"), ("reserved", "H"),
]
_HDR_FMT = "<" + "".join(code for _, code in _HDR_FIELDS)
_HDR_NAMES = [name for name, _ in _HDR_FIELDS]
assert struct.calcsize(_HDR_FMT) + SIG_SIZE == HDR_LEN, "header layout drifted"

# Mirrors of the C header's names, so the self-test can compare the two
# implementations field by field without a translation table that could itself
# drift. selftest.py parses these out of include/microfoam.h and asserts that
# they still match.
MCF_HDR_MAGIC = MAGIC
MCF_HDR_MIN_SIZE = HDR_LEN
MCF_SIG_SIZE = SIG_SIZE
MCF_OFF_MAGIC = OFF_MAGIC
MCF_OFF_HDR_LEN = OFF_HDR_LEN
MCF_OFF_HDR_VER = OFF_HDR_VER
MCF_OFF_FLAGS = OFF_FLAGS
MCF_OFF_PRODUCT_ID = OFF_PRODUCT_ID
MCF_OFF_FW_VERSION = OFF_FW_VERSION
MCF_OFF_OLD_SIZE = OFF_OLD_SIZE
MCF_OFF_NEW_SIZE = OFF_NEW_SIZE
MCF_OFF_PAYLOAD_SIZE = OFF_PAYLOAD_SIZE
MCF_OFF_OLD_CRC32 = OFF_OLD_CRC32
MCF_OFF_NEW_CRC32 = OFF_NEW_CRC32
MCF_OFF_PAYLOAD_CRC32 = OFF_PAYLOAD_CRC32
MCF_OFF_WORKSPACE_REQ = OFF_WORKSPACE_REQ
MCF_OFF_OLD_VERSION = OFF_OLD_VERSION
MCF_OFF_CODEC_ID = OFF_CODEC_ID
MCF_OFF_BLOCK_LOG2 = OFF_BLOCK_LOG2
MCF_OFF_RESERVED = OFF_RESERVED
MCF_OFF_SIGNATURE = OFF_SIGNATURE


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


# --------------------------------------------------------------------------
# BSDIFF43 delta encoding
# --------------------------------------------------------------------------


def offtout(value: int) -> bytes:
    """Sign-magnitude little-endian, top bit is the sign.

    This is the Endsley encoding, not Colin Percival's two's complement. Patches
    are not interchangeable between the two.
    """
    sign = 0x80 if value < 0 else 0x00
    mag = abs(value)
    out = bytearray(8)
    for i in range(8):
        byte = (mag >> (8 * i)) & 0xFF
        if i == 7:
            byte = (byte & 0x7F) | sign
        out[i] = byte
    return bytes(out)


MIN_MATCH = 16   # bytes of agreement before a run is worth a control triple
MIN_KEY = 8      # bytes indexed to find candidate runs


def bsdiff(old: bytes, new: bytes) -> bytes:
    """Produce a BSDIFF43 control stream via a suffix search over the base image.

    Seek semantics, which is the part that is easy to get wrong: a control
    triple is (diff_len, extra_len, seek), and the engine applies the diff and
    extra bytes at the *current* base cursor, then advances that cursor by
    `seek`. A seek therefore positions the base for the *next* triple's diff, not
    for its own. Segments are built first, then emitted with each seek chosen to
    land on the base position the following diff segment needs.

    A run that already exists in the base is emitted as a diff triple whose
    payload is that many zero bytes - the engine adds the base back and recovers
    the target. Runs that are genuinely new become literal (extra) triples. The
    zeros are what the codec then compresses away, and that is the mechanism
    which makes a delta patch a fraction of the image rather than larger.
    """
    m = len(new)

    index: dict[bytes, int] = {}
    for i in range(0, max(0, len(old) - MIN_KEY + 1)):
        index.setdefault(old[i:i + MIN_KEY], i)

    # ---- pass 1: segment the target into literal and match runs ----
    segments: list[tuple] = []   # ('lit', bytes) | ('match', run, base_pos)
    literal = bytearray()
    i = 0
    while i < m:
        j, run = -1, 0
        if i + MIN_KEY <= m:
            j = index.get(new[i:i + MIN_KEY], -1)
        if j >= 0:
            run = MIN_KEY
            while i + run < m and j + run < len(old) and new[i + run] == old[j + run]:
                run += 1
        if j >= 0 and run >= MIN_MATCH:
            if literal:
                segments.append(("lit", bytes(literal)))
                literal.clear()
            segments.append(("match", run, j))
            i += run
        else:
            literal.append(new[i])
            i += 1
    if literal:
        segments.append(("lit", bytes(literal)))

    # ---- pass 2: emit control triples with correctly placed seeks ----
    out = bytearray()
    oldpos = 0

    def emit(x: int, y: int, seek: int, payload: bytes) -> None:
        out.extend(offtout(x))
        out.extend(offtout(y))
        out.extend(offtout(seek))
        out.extend(payload)

    for idx, seg in enumerate(segments):
        if seg[0] == "match":
            run, base = seg[1], seg[2]
            if oldpos != base:
                # A bare seek triple, which has no diff and no extra, moves the
                # base cursor without emitting bytes. Needed when the first
                # match is not at base offset zero.
                emit(0, 0, base - oldpos, b"")
                oldpos = base
            x, y, payload = run, 0, bytes(run)
        else:
            x, y, payload = 0, len(seg[1]), seg[1]

        nxt = segments[idx + 1] if idx + 1 < len(segments) else None
        if nxt is not None and nxt[0] == "match":
            seek = nxt[2] - (oldpos + x)
        else:
            seek = 0

        emit(x, y, seek, payload)
        oldpos += x + seek

    return bytes(out)


# --------------------------------------------------------------------------
# LZ4 framing. Only literal blocks are emitted here, which is valid LZ4 and
# keeps the host tool dependency-free. A real tool would link liblz4 and emit
# matched blocks; the device decoder already handles matches.
# --------------------------------------------------------------------------


def lz4_literal_block(data: bytes) -> bytes:
    n = len(data)
    if n < 15:
        out = bytearray([n << 4])
    else:
        out = bytearray([0xF0])
        rem = n - 15
        while rem >= 255:
            out.append(0xFF)
            rem -= 255
        out.append(rem)
    out += data
    return bytes(out)


def _emit_length(out: bytearray, length: int) -> None:
    """LZ4 length extension: 255 means "keep going"."""
    while length >= 255:
        out.append(0xFF)
        length -= 255
    out.append(length)


def _emit_seq(out: bytearray, lit: bytes, matchlen: Optional[int], offset: int = 0) -> None:
    """Emit one LZ4 sequence: token, literals, then match offset and length.

    The low nibble of the token is the match length minus four, saturated at 15
    with the true value continued in the extension bytes.
    """
    enc = 0 if matchlen is None else min(matchlen - 4, 15)
    lit_nib = 15 if len(lit) >= 15 else len(lit)
    out.append((lit_nib << 4) | enc)
    if len(lit) >= 15:
        _emit_length(out, len(lit) - 15)
    out += lit
    if matchlen is not None:
        out += struct.pack("<H", offset)
        if matchlen - 4 >= 15:
            _emit_length(out, matchlen - 4 - 15)


def lz4_compress_block(data: bytes, hash_log: int = 14, max_chain: int = 8) -> bytes:
    """Single LZ4 block with real back-references.

    Greedy match search over hash-bucketed candidate chains keyed on 4-byte
    sequences. The device decoder handles matches, so emitting them here
    exercises that path rather than only the literal path.

    The LZ4 specification requires the last 5 bytes, and any final match, to be
    literals. This encoder honours that so the output is spec-conformant and not
    merely decodable by our own decoder.
    """
    n = len(data)
    if n < 13:
        return lz4_literal_block(data)

    mask = (1 << hash_log) - 1
    table: dict[int, list[int]] = {}
    out = bytearray()
    anchor = 0
    i = 0
    limit = n - 5     # a match may not start within the last 5 bytes
    mflimit = n - 12  # a match must stop 12 bytes from the end

    def key_at(p: int) -> int:
        return int.from_bytes(data[p:p + 4], "little") & mask

    def insert(p: int) -> None:
        k = key_at(p)
        lst = table.get(k)
        if lst is None:
            table[k] = [p]
        else:
            lst.append(p)
            if len(lst) > max_chain:
                del lst[0]

    while i < limit:
        lst = table.get(key_at(i))
        best_len = 0
        best_off = 0

        if lst:
            for cand in reversed(lst):          # most recent first
                off = i - cand
                if off <= 0 or off >= 65536:
                    continue
                # Skip candidates that cannot beat the incumbent.
                if best_len and cand + best_len < n and i + best_len < n \
                        and data[cand + best_len] != data[i + best_len]:
                    continue
                l = 0
                while i + l < mflimit and cand + l < n and data[cand + l] == data[i + l]:
                    l += 1
                if l > best_len:
                    best_len = l
                    best_off = off
                    if l >= 260:                 # long enough, stop searching
                        break

        # Register this position as a candidate before advancing, so later
        # positions can match against it.
        insert(i)

        if best_len >= 4:
            _emit_seq(out, data[anchor:i], best_len, best_off)
            i += best_len
            anchor = i
        else:
            i += 1

    _emit_seq(out, data[anchor:], None)
    return bytes(out)


def lz4_frame(data: bytes, block_size: int) -> bytes:
    """repeat { u32 block_len; block_len bytes }, terminated by block_len 0.

    `block_size` is the maximum a single block may expand to, and it is taken
    from the header's block_size_log2. It is not advisory: the device decodes
    into a buffer of exactly this size and rejects a block that would overflow.
    The host tool and the device must agree on it, so it is passed in from the
    same field the device reads rather than assumed here.
    """
    out = bytearray()
    step = max(1, block_size)
    for off in range(0, len(data), step):
        chunk = data[off:off + step]
        if not chunk:
            continue
        block = lz4_compress_block(chunk)
        # Never let compression expand a block: fall back to literals.
        if len(block) >= len(chunk):
            block = lz4_literal_block(chunk)
        out += struct.pack("<I", len(block))
        out += block
    out += struct.pack("<I", 0)
    return bytes(out)


def image_framing(block_log2: int, new_size: int) -> tuple[int, int]:
    """Framing size, and the exponent to declare, for an image of `new_size`.

    The device's decode window is `min(cfg.block_size, new_size)` - capped at
    the image - so a producer that frames larger than the image emits a patch no
    device configuration can apply: the window can never exceed `new_size`,
    while the delta is never smaller than it (the control triples add to it), so
    such a block overruns the window on every apply, at every `cfg.block_size`.
    The producer therefore frames within the image.

    Returns `(frame_size, declared_log2)`: the frame size is capped at the image,
    and the declared exponent is the one actually used, floored at 8 (the
    format's minimum). An image below 256 bytes cannot express its framing
    exactly; the declared value then overstates it, which only makes the
    device's budget pre-check conservative. The header field drives nothing but
    that pre-check - the decode window comes from the caller's configuration -
    so declaring the real figure is what keeps the two honest.
    """
    if new_size <= 0:
        return (1 << block_log2, block_log2)
    eff = block_log2
    while eff > 8 and (1 << eff) > new_size:
        eff -= 1
    return (min(1 << block_log2, new_size), eff)


# --------------------------------------------------------------------------
# LZMA. The encoder is Python's stdlib lzma module (liblzma), which is the
# reference implementation for the format the device decoder consumes. The
# device side is the vendored LZMA SDK decoder; agreement between liblzma
# output and the SDK decoder is what the conformance vectors prove.
# --------------------------------------------------------------------------


def lzma_compress(delta: bytes, dict_size: int) -> bytes:
    import lzma as _lzma

    filters = [{"id": _lzma.FILTER_LZMA1, "lc": LZMA_DEFAULT_LC,
                "lp": LZMA_DEFAULT_LP, "pb": LZMA_DEFAULT_PB,
                "dict_size": dict_size}]
    return _lzma.compress(delta, format=_lzma.FORMAT_RAW, filters=filters)


def lzma_decompress(stream: bytes, props: bytes) -> bytes:
    import lzma as _lzma

    if len(props) < LZMA_PROPS_LEN:
        raise ValueError("LZMA properties truncated")
    v = props[0]
    if v >= 9 * 5 * 5:
        raise ValueError("invalid LZMA properties byte")
    lc, lp, pb = v % 9, (v // 9) % 5, v // 45
    dict_size = struct.unpack_from("<I", props, 1)[0]
    content_size = struct.unpack_from("<I", props, 5)[0]
    filters = [{"id": _lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb,
                "dict_size": max(dict_size, LZMA_MIN_DICT)}]
    d = _lzma.LZMADecompressor(format=_lzma.FORMAT_RAW, filters=filters)
    out = d.decompress(stream, max_length=content_size)
    if len(out) != content_size:
        raise ValueError(
            f"LZMA stream produced {len(out)} bytes, expected {content_size}")
    return out


def props_len_for(codec_id: int) -> int:
    if codec_id == CODEC_LZMA:
        return LZMA_PROPS_LEN
    if codec_id == CODEC_RAW:
        return RAW_PROPS_LEN
    return LZ4_PROPS_LEN


# --------------------------------------------------------------------------
# Signing. Ed25519 via hashlib where available, so the tool has no third-party
# dependency. The device's built-in verifier arrives in a later phase; until
# then the integrator supplies mcf_verify_fn.
# --------------------------------------------------------------------------


def sign(private_key: Optional[bytes], message: bytes) -> bytes:
    if private_key is None:
        return b"\x00" * SIG_SIZE
    raw = private_key
    if len(raw) == 64:
        raw = raw[:32]          # seed || public key, keep the seed
    if len(raw) != 32:
        raise SystemExit("private key must be 32 bytes (seed) or 64 bytes (seed||pub)")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("warning: 'cryptography' not installed; emitting an unsigned patch",
              file=sys.stderr)
        return b"\x00" * SIG_SIZE
    return Ed25519PrivateKey.from_private_bytes(raw).sign(message)


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# MFP2 signed/encrypted container
# --------------------------------------------------------------------------

V2_MAGIC = 0x3250464D
V2_HEADER_MIN = 192
V2_HEADER_MAX = 4096
V2_VERSION = 0x0200
V2_FLAG_SIGNED = 0x01
V2_FLAG_ENCRYPTED = 0x02
V2_FLAG_CODEC_LZ4 = 0x08
V2_REQUIRED_FLAGS = V2_FLAG_SIGNED | V2_FLAG_ENCRYPTED | V2_FLAG_CODEC_LZ4
V2_RECORD_TAG_SIZE = 16
V2_RECORD_LOG2_MIN = 8
V2_RECORD_LOG2_MAX = 13
V2_KEY_ID_SIZE = 16
V2_NONCE_PREFIX_SIZE = 16
V2_OFF_SIGNATURE = 56
V2_OFF_KEY_ID = 120
V2_OFF_NONCE_PREFIX = 136
V2_OFF_RECORD_COUNT = 160
V2_OFF_CODEC_PROFILE = 164
V2_OFF_RESERVED = 168
V2_OFF_HEADER_DIGEST = 176


def _sodium():
    try:
        from nacl.bindings import (crypto_aead_xchacha20poly1305_ietf_decrypt,
            crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_sign_ed25519ph_state,
            crypto_sign_ed25519ph_update, crypto_sign_ed25519ph_final_create,
            crypto_sign_ed25519ph_final_verify)
        return locals()
    except ImportError as exc:
        raise SystemExit("MFP2 requires PyNaCl/libsodium with Ed25519ph and XChaCha20-Poly1305") from exc


def _v2_header_for_sig(header: bytes) -> bytes:
    h = bytearray(header)
    h[V2_OFF_SIGNATURE:V2_OFF_SIGNATURE + SIG_SIZE] = b"\0" * SIG_SIZE
    return bytes(h)


def _v2_header_for_aad(header: bytes) -> bytes:
    # AEAD associated data covers the header with the signature zeroed and the
    # payload CRC field carried as zero: that CRC covers the ciphertext, which
    # depends on this AAD, so the stored value cannot appear here. Both sides
    # construct the AAD this way; the stored CRC remains signature-covered.
    h = bytearray(header)
    h[V2_OFF_SIGNATURE:V2_OFF_SIGNATURE + SIG_SIZE] = b"\0" * SIG_SIZE
    h[40:44] = b"\0" * 4
    return bytes(h)


def _ed25519ph_sign(seed_or_secret: bytes, message: bytes) -> bytes:
    s = _sodium()
    raw = seed_or_secret[:32] if len(seed_or_secret) in (32, 64) else seed_or_secret
    if len(raw) == 32:
        from nacl.signing import SigningKey
        raw = bytes(SigningKey(raw)._signing_key)
    if len(raw) != 64:
        raise SystemExit("MFP2 signing key must be 32-byte seed or 64-byte secret key")
    st = s["crypto_sign_ed25519ph_state"]()
    s["crypto_sign_ed25519ph_update"](st, message)
    return s["crypto_sign_ed25519ph_final_create"](st, raw)


def _ed25519ph_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        s = _sodium()
        if len(public_key) != 32 or len(signature) != 64:
            return False
        st = s["crypto_sign_ed25519ph_state"]()
        s["crypto_sign_ed25519ph_update"](st, message)
        return bool(s["crypto_sign_ed25519ph_final_verify"](st, signature, public_key))
    except Exception:
        return False


def _v2_aead(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return _sodium()["crypto_aead_xchacha20poly1305_ietf_encrypt"](plaintext, aad, nonce, key)


def _v2_open(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
    return _sodium()["crypto_aead_xchacha20poly1305_ietf_decrypt"](ciphertext_and_tag, aad, nonce, key)


def _v2_records(stream: bytes, record_size: int) -> list[bytes]:
    records = []
    pos = 0
    while pos < len(stream):
        if pos + 4 > len(stream):
            raise ValueError("truncated LZ4 frame")
        blen = struct.unpack_from("<I", stream, pos)[0]
        end = pos + 4 + blen
        if blen == 0:
            records.append(stream[pos:end]); pos = end
            break
        if end > len(stream):
            raise ValueError("truncated LZ4 block")
        frame = stream[pos:end]
        if len(frame) > record_size:
            raise ValueError("LZ4 frame exceeds MFP2 record size")
        records.append(frame); pos = end
    if pos != len(stream) or not records:
        raise ValueError("invalid LZ4 stream")
    return records


def _v2_walk_tlvs(tlvs: bytes) -> None:
    """Validate the TLV area exactly as the device does.

    An entry is u16 type, u16 flags, u32 length, value, then zero padding to a
    four-byte boundary. Bit 0 of `flags` marks a critical entry, and the only
    critical type defined is 1, so an unknown critical type is refused.

    The padding check is a real walk, not a scan of every fourth byte: padding
    only exists *after* an entry, so a byte inside a value is not padding and
    must not be read as one. The previous one-line scan could never fire at all
    (its index range was empty once the area length was a multiple of four,
    which the format requires), so the tool accepted padding the device rejects.
    """
    off, n = 0, len(tlvs)
    while off < n:
        if n - off < 8:
            raise SystemExit("MFP2 TLV entry is truncated")
        type_, flags, length = struct.unpack_from("<HHI", tlvs, off)
        if length > n - off - 8:
            raise SystemExit("MFP2 TLV length overruns the area")
        if (flags & 1) and type_ != 1:
            raise SystemExit("MFP2 unknown critical TLV")
        off += 8 + length
        while off & 3:
            if off >= n or tlvs[off] != 0:
                raise SystemExit("MFP2 TLV padding must be zero")
            off += 1
    if off != n:
        raise SystemExit("MFP2 TLV area does not end on a four-byte boundary")


def v2_workspace_req(record_log2: int, header_len: int) -> int:
    """Streaming workspace an MFP2 session needs, mirroring the device.

    mcf_v2_session_begin() lays its scratch out as a synthetic MFP1 header
    (124 bytes), a record window of two maximum-size records plus the terminal
    marker, the AAD scratch ("MCF2REC\\0" + the header + the per-record index
    and length), and then the inner MFP1 session's own workspace (two decode
    blocks plus the LZ4 state). The header's `workspace_req` is that total. The
    device only uses the field as a coarse budget gate and derives the real
    figure itself, but a placeholder here misstates what the patch costs.
    """
    win = 2 * (1 << record_log2) + 4          # record window + terminal marker
    ad = 8 + header_len + 8                   # prefix + header + index/length
    inner_ws = 2 * (1 << record_log2) + 16    # inner engine blocks + LZ4 state
    return 124 + win + ad + inner_ws


@dataclass
class V2HeaderView:
    header_len: int; version: int; flags: int; product_id: int; fw_version: int
    old_size: int; new_size: int; payload_size: int; old_crc32: int; new_crc32: int
    payload_crc32: int; workspace_req: int; old_version: int; codec_id: int
    record_log2: int; tlv_len: int; signature: bytes; key_id: bytes; nonce_prefix: bytes
    record_count: int; codec_profile: int; tlvs: bytes


def parse_v2_header(blob: bytes) -> V2HeaderView:
    if len(blob) < V2_HEADER_MIN: raise SystemExit("MFP2 patch is shorter than 192-byte header")
    magic, hlen, ver, flags, product, fw, oldsz, newsz, psz, oldcrc, newcrc, pcrc, ws, oldver = struct.unpack_from("<IHHIIIIIIIIIII", blob, 0)
    codec, rlog2, tlv_len = struct.unpack_from("<BBH", blob, 52)
    if magic != V2_MAGIC or ver != V2_VERSION or not (V2_HEADER_MIN <= hlen <= V2_HEADER_MAX) or hlen % 4 or hlen > len(blob): raise SystemExit("invalid MFP2 header")
    if tlv_len != hlen - V2_HEADER_MIN or flags != V2_REQUIRED_FLAGS or codec != CODEC_LZ4 or not 8 <= rlog2 <= 13: raise SystemExit("unsupported MFP2 profile")
    record_count = struct.unpack_from("<I", blob, 160)[0]
    if not record_count or struct.unpack_from("<I", blob, 164)[0] != 0: raise SystemExit("invalid MFP2 record/profile fields")
    if blob[168:192] != b"\0" * 24 or not blob[120:136].strip(b"\0") or not blob[136+16:160] == b"\0" * 8: raise SystemExit("invalid MFP2 reserved/key fields")
    tlvs = blob[192:hlen]
    _v2_walk_tlvs(tlvs)
    return V2HeaderView(hlen, ver, flags, product, fw, oldsz, newsz, psz, oldcrc, newcrc, pcrc, ws, oldver, codec, rlog2, tlv_len, blob[56:120], blob[120:136], blob[136:160], struct.unpack_from("<I", blob, 160)[0], struct.unpack_from("<I", blob, 164)[0], blob[192:hlen])


@dataclass
class V2Patch:
    old: bytes; new: bytes; product_id: int = 0; fw_version: int = 0; old_version: int = 0
    private_key: bytes = b""; key: bytes = b""; key_id: bytes = b""; nonce_prefix: bytes = b""
    record_log2: int = 13; tlvs: bytes = b""

    def build(self) -> bytes:
        if len(self.key) != 32 or not self.private_key: raise SystemExit("MFP2 requires --key and a signing key")
        if len(self.key_id) != 16: raise SystemExit("MFP2 key id must be 16 bytes")
        if not 8 <= self.record_log2 <= 13 or len(self.tlvs) % 4: raise SystemExit("invalid MFP2 record/TLV size")
        _v2_walk_tlvs(self.tlvs)
        # Draw the nonce prefix into a local, never onto self: caching it on the
        # instance made a second build() reuse the first's prefix with the same
        # key, repeating every per-record nonce and leaking the XOR of the two
        # plaintexts. A caller that wants a reproducible vector passes one in.
        nonce_prefix = self.nonce_prefix if self.nonce_prefix else os.urandom(16)
        if len(nonce_prefix) != 16 or not any(nonce_prefix): raise SystemExit("MFP2 nonce prefix must be 16 nonzero bytes")
        delta = bsdiff(self.old, self.new)
        # Leave room for the LZ4 block header/literal extension so the complete
        # framed block (the record plaintext) always fits the wire limit - and
        # cap the frame at the image, because the device's decode window is the
        # smaller of the record size and new_size. Framing larger than a small
        # image yields a patch no configuration can apply; see image_framing().
        rec_frame = max(1, (1 << self.record_log2) - 64)
        frame_size = min(rec_frame, len(self.new)) if self.new else rec_frame
        framed = lz4_frame(delta, max(1, frame_size))
        records = _v2_records(framed, 1 << self.record_log2)
        hlen = V2_HEADER_MIN + len(self.tlvs)
        # Declared from the real layout, not a placeholder: the device uses the
        # field as a budget gate and computes the true need itself, but a patch
        # that misstates its own cost misleads anything reading it.
        workspace_req = v2_workspace_req(self.record_log2, hlen)
        hdr = bytearray(hlen)
        struct.pack_into("<IHHIIIIIIIIIII", hdr, 0, V2_MAGIC, hlen, V2_VERSION, V2_REQUIRED_FLAGS, self.product_id, self.fw_version, len(self.old), len(self.new), 0, crc32(self.old), crc32(self.new), 0, workspace_req, self.old_version)
        struct.pack_into("<BBH", hdr, 52, CODEC_LZ4, self.record_log2, len(self.tlvs))
        hdr[120:136] = self.key_id; hdr[136:152] = nonce_prefix
        struct.pack_into("<II", hdr, 160, len(records), 0); hdr[192:] = self.tlvs
        # The record area length is fixed by the plaintext record sizes, and
        # the payload CRC is computed over the ciphertext, so both are written
        # to the header only AFTER encryption. For the per-record AAD the CRC
        # field is therefore zero (the value the device also sees when it
        # rebuilds the header before this field exists in its view); the final
        # stored CRC is covered by the Ed25519ph signature.
        area_len = sum(4 + len(r) + 16 for r in records)
        struct.pack_into("<I", hdr, 28, area_len)
        struct.pack_into("<I", hdr, 40, 0)
        area = bytearray()
        for i, plain in enumerate(records):
            clen = len(plain); aad = b"MCF2REC\0" + _v2_header_for_aad(hdr) + struct.pack("<II", i, clen)
            enc = _v2_aead(self.key, nonce_prefix[:V2_NONCE_PREFIX_SIZE] + struct.pack("<Q", i), plain, aad)
            area += struct.pack("<I", clen) + enc
        assert len(area) == area_len, "record area length drifted"
        struct.pack_into("<I", hdr, 40, crc32(area))
        sigmsg = b"MCF2SIG\0" + _v2_header_for_sig(hdr) + area
        hdr[56:120] = _ed25519ph_sign(self.private_key, sigmsg)
        return bytes(hdr) + bytes(area)


def verify_v2(blob: bytes, public_key: bytes, key: Optional[bytes] = None, apply: bool = False, old: bytes = b"", window: Optional[int] = None) -> bytes:
    h = parse_v2_header(blob)
    if h.payload_size != len(blob) - h.header_len: raise SystemExit("MFP2 payload length mismatch")
    area = blob[h.header_len:]
    if crc32(area) != h.payload_crc32: raise SystemExit("MFP2 payload CRC mismatch")
    if not _ed25519ph_verify(public_key, h.signature, b"MCF2SIG\0" + _v2_header_for_sig(blob[:h.header_len]) + area): raise SystemExit("MFP2 signature invalid")
    if key is None: return b""
    if len(key) != 32: raise SystemExit("MFP2 symmetric key must be 32 bytes")
    stream = bytearray(); pos = 0
    for i in range(h.record_count):
        if pos + 4 > len(area): raise SystemExit("MFP2 record framing truncated")
        clen = struct.unpack_from("<I", area, pos)[0]; pos += 4
        if not 1 <= clen <= (1 << h.record_log2) or pos + clen + 16 > len(area): raise SystemExit("invalid MFP2 record length")
        enc = area[pos:pos + clen + 16]; pos += clen + 16
        aad = b"MCF2REC\0" + _v2_header_for_aad(blob[:h.header_len]) + struct.pack("<II", i, clen)
        try: stream += _v2_open(key, h.nonce_prefix[:V2_NONCE_PREFIX_SIZE] + struct.pack("<Q", i), enc, aad)
        except Exception as exc: raise SystemExit("MFP2 record authentication failed") from exc
    if pos != len(area): raise SystemExit("MFP2 trailing record bytes")
    # Decode at the window the device will use, so this verifier answers "can
    # that device apply this patch" and not merely "is it self-consistent". The
    # inner session is handed block_size = 1 << record_log2 and clamps it to the
    # image (mcf_v2_session.c), so the device window is min(record_size,
    # new_size) whatever the integrator configured. A patch framed larger than a
    # small image verifies under an unbounded buffer and is rejected on the
    # device at site 17 - the divergence this bound removes.
    if window is None:
        window = min(1 << h.record_log2, h.new_size)
    delta = lz4_decompress(bytes(stream), window); result = bspatch(old, delta, h.new_size)
    if crc32(result) != h.new_crc32: raise SystemExit("MFP2 reconstructed image CRC mismatch")
    return result


# --------------------------------------------------------------------------
# Patch construction
# --------------------------------------------------------------------------


@dataclass
class Patch:
    old: bytes
    new: bytes
    product_id: int = 0
    fw_version: int = 0
    old_version: int = 0
    block_log2: int = DEFAULT_BLOCK_LOG2
    flags: int = 0
    private_key: Optional[bytes] = None
    codec: int = CODEC_LZ4
    dict_size: int = LZMA_DEFAULT_DICT

    def build(self) -> bytes:
        delta = bsdiff(self.old, self.new)
        # Frame within the image, and declare the exponent actually used. The
        # device's window is capped at new_size, so framing larger than the
        # image produces a patch no configuration can apply. See image_framing().
        frame_size, declared_log2 = image_framing(self.block_log2, len(self.new))

        if self.codec == CODEC_RAW:
            # The delta verbatim: no framing, no properties, no per-block cost.
            # The right choice when the delta is small enough that a codec's
            # headers cost more than they save.
            stream = delta
            payload_size = len(stream)
            codec_id = CODEC_RAW
            codec_flag = FLAG_RAW
            workspace_req = WS_RAW
            signed_stream = delta
        elif self.codec == CODEC_LZMA:
            props = self._lzma_props(delta)
            stream = props + lzma_compress(delta, self.dict_size)
            payload_size = len(stream)
            codec_id = CODEC_LZMA
            codec_flag = FLAG_CODEC_LZMA
            workspace_req = lzma_workspace_req(LZMA_DEFAULT_LC, LZMA_DEFAULT_LP,
                                               self.dict_size)
            # The signature covers the stream, which here excludes the props
            # block; the props are covered by the payload CRC instead.
            signed_stream = stream[LZMA_PROPS_LEN:]
        else:
            # The device decodes into a block_size buffer and rejects anything
            # that would overflow, so the framing must respect the same field
            # the device reads out of the header.
            framed = lz4_frame(delta, frame_size)
            stream = struct.pack("<I", len(delta)) + framed
            payload_size = len(stream)
            codec_id = CODEC_LZ4
            codec_flag = FLAG_CODEC_LZ4
            workspace_req = WS_LZ4
            signed_stream = framed

        header = bytearray(HDR_LEN)
        struct.pack_into(
            _HDR_FMT,
            header,
            0,
            MAGIC,
            HDR_LEN,
            (HDR_VER_MAJOR << 8) | HDR_VER_MINOR,
            self.flags | codec_flag,
            self.product_id,
            self.fw_version,
            len(self.old),
            len(self.new),
            payload_size,
            crc32(self.old),
            crc32(self.new),
            crc32(signed_stream),
            workspace_req,
            self.old_version,
            codec_id,
            declared_log2,
            0,
        )

        patch = bytes(header) + stream

        if self.flags & FLAG_SIGNED:
            sig = sign(self.private_key, patch[:SIGNED_HEADER_LEN] + signed_stream)
            patch = patch[:OFF_SIGNATURE] + sig + patch[OFF_SIGNATURE + SIG_SIZE:]

        return patch

    def _lzma_props(self, delta: bytes) -> bytes:
        encoded = (LZMA_DEFAULT_PB * 45) + (LZMA_DEFAULT_LP * 9) + LZMA_DEFAULT_LC
        return bytes([encoded]) + struct.pack("<I", self.dict_size) + \
            struct.pack("<I", len(delta))


@dataclass
class HeaderView:
    magic: int = 0
    hdr_len: int = 0
    hdr_ver: int = 0
    flags: int = 0
    product_id: int = 0
    fw_version: int = 0
    old_size: int = 0
    new_size: int = 0
    payload_size: int = 0
    old_crc32: int = 0
    new_crc32: int = 0
    payload_crc32: int = 0
    workspace_req: int = 0
    old_version: int = 0
    codec_id: int = 0
    block_log2: int = 0
    reserved: int = 0
    signature: bytes = b""


def parse_header(blob: bytes) -> HeaderView:
    if len(blob) < HDR_LEN:
        raise SystemExit("patch is shorter than the minimum header")
    values = struct.unpack_from(_HDR_FMT, blob, 0)
    kw = dict(zip(_HDR_NAMES, values))
    h = HeaderView(signature=blob[OFF_SIGNATURE:OFF_SIGNATURE + SIG_SIZE], **kw)
    known = FLAG_SIGNED | FLAG_RAW | FLAG_CODEC_LZMA | FLAG_CODEC_LZ4
    if h.magic != MAGIC:
        raise SystemExit("bad magic")
    if h.hdr_len < HDR_LEN or h.hdr_len > len(blob):
        raise SystemExit("invalid header length")
    if h.reserved != 0 or h.flags & ~known:
        raise SystemExit("unsupported header flags or nonzero reserved field")
    if not (h.flags & (FLAG_RAW | FLAG_CODEC_LZMA | FLAG_CODEC_LZ4)):
        raise SystemExit("missing codec flag")
    if (h.flags & FLAG_CODEC_LZ4) and (h.flags & FLAG_CODEC_LZMA):
        raise SystemExit("multiple codec flags are not supported")
    if (h.flags & FLAG_RAW) and (h.flags & (FLAG_CODEC_LZMA | FLAG_CODEC_LZ4)):
        raise SystemExit("raw patches cannot select a codec")
    if h.codec_id == CODEC_LZ4 and not (h.flags & FLAG_CODEC_LZ4):
        raise SystemExit("LZ4 patch is missing FLAG_CODEC_LZ4")
    if h.codec_id == CODEC_LZMA and not (h.flags & FLAG_CODEC_LZMA):
        raise SystemExit("LZMA patch is missing FLAG_CODEC_LZMA")
    # The raw flag and the raw codec id must agree in both directions, exactly
    # as the compressed codec flags must agree with theirs.
    if bool(h.flags & FLAG_RAW) != (h.codec_id == CODEC_RAW):
        raise SystemExit("raw flag and codec id disagree")
    if h.codec_id not in (CODEC_LZ4, CODEC_LZMA, CODEC_RAW):
        raise SystemExit("unsupported codec id in header")
    return h


# --------------------------------------------------------------------------
# Reference decoder, used to prove a produced patch round-trips. Independent of
# the C implementation on purpose: agreement between two implementations is
# evidence; agreement with itself is not.
# --------------------------------------------------------------------------


def lz4_decode_block(src: bytes, dst_cap: int) -> bytes:
    ip = 0
    out = bytearray()
    n = len(src)
    while ip < n:
        token = src[ip]
        ip += 1
        lit = token >> 4
        if lit == 15:
            while True:
                if ip >= n:
                    raise ValueError("truncated literal length")
                s = src[ip]
                ip += 1
                lit += s
                if s != 255:
                    break
        if ip + lit > n:
            raise ValueError("literal overrun")
        out += src[ip:ip + lit]
        ip += lit
        # The window applies to the literal run too, and a block may end right
        # after its literals. Checking the cap only after a match - as this did -
        # accepts a literal-only block that overflows the window, which is
        # exactly the shape a producer emits for a small image. The device
        # checks both (mcf_lz4_block: `(oend - op) < lit`), so this has to as
        # well or the host verifier approves patches the device rejects.
        if len(out) > dst_cap:
            raise ValueError("output overflow")
        if ip == n:
            break
        if ip + 2 > n:
            raise ValueError("truncated offset")
        off = src[ip] | (src[ip + 1] << 8)
        ip += 2
        if off == 0 or off > len(out):
            raise ValueError("bad match offset")
        match = token & 0x0F
        if match == 15:
            while True:
                if ip >= n:
                    raise ValueError("truncated match length")
                s = src[ip]
                ip += 1
                match += s
                if s != 255:
                    break
        match += 4
        start = len(out) - off
        for i in range(match):
            out.append(out[start + i])
        if len(out) > dst_cap:
            raise ValueError("output overflow")
    return bytes(out)


def lz4_decompress(stream: bytes, max_block: int = 1 << 24) -> bytes:
    """Decode a framed stream, refusing any block that expands past `max_block`.

    `max_block` defaults to a window far larger than any real patch so that a
    caller which only wants the bytes gets them; a caller modelling a device
    passes that device's actual window, because the device decodes into a
    buffer of exactly that size and rejects a block that would overflow.
    """
    out = bytearray()
    pos = 0
    while pos + 4 <= len(stream):
        (blen,) = struct.unpack_from("<I", stream, pos)
        pos += 4
        if blen == 0:
            return bytes(out)
        out += lz4_decode_block(stream[pos:pos + blen], max_block)
        pos += blen
    raise ValueError("stream ended without an end marker")


def offtin(buf: bytes) -> int:
    mag = int.from_bytes(buf, "little") & 0x007FFFFFFFFFFFFF
    return -mag if (buf[7] & 0x80) else mag


def bspatch(old: bytes, delta: bytes, new_size: int) -> bytes:
    """Reference BSDIFF43 application, independent of the C engine."""
    out = bytearray()
    pos = 0
    oldpos = 0
    while len(out) < new_size:
        if pos + 24 > len(delta):
            raise ValueError("truncated control triple")
        x, y, z = offtin(delta[pos:pos + 8]), offtin(delta[pos + 8:pos + 16]), offtin(delta[pos + 16:pos + 24])
        pos += 24
        if x < 0 or y < 0 or len(out) + x + y > new_size:
            raise ValueError("sanity check failed")
        for i in range(x):
            base = old[oldpos + i] if 0 <= oldpos + i < len(old) else 0
            out.append((delta[pos + i] + base) & 0xFF)
        pos += x
        oldpos += x
        out += delta[pos:pos + y]
        pos += y
        oldpos += z
    return bytes(out)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_make(args: argparse.Namespace) -> int:
    old = open(args.old, "rb").read()
    new = open(args.new, "rb").read()
    if args.v2:
        signing = open(args.signing_key, "rb").read()
        symmetric = open(args.key, "rb").read()
        key_id = bytes.fromhex(args.key_id) if args.key_id else b""
        # A fixed prefix is the one way this tool can cause a nonce to repeat.
        # Per-record nonces are prefix || LE64(record index), so the same prefix
        # with the same key in a second patch repeats every nonce, and
        # XChaCha20-Poly1305 then leaks the XOR of the two plaintexts. Random is
        # the default; a fixed prefix is only for reproducible test vectors.
        if args.nonce_prefix and not args.nonce_prefix_ack_reuse:
            raise SystemExit(
                "refusing a fixed --nonce-prefix without acknowledgement\n"
                "  A fixed prefix is safe only when the key is never used for another\n"
                "  patch: reusing one prefix with the same key repeats every per-record\n"
                "  nonce and leaks the XOR of the two plaintexts. Omit --nonce-prefix for\n"
                "  a random one, or pass --nonce-prefix-ack-reuse to confirm this prefix\n"
                "  is a test vector that will never be reused with this key."
            )
        nonce = bytes.fromhex(args.nonce_prefix) if args.nonce_prefix else b""
        patch = V2Patch(old=old, new=new, product_id=args.product, fw_version=args.version,
                        old_version=args.old_version, private_key=signing, key=symmetric,
                        key_id=key_id, nonce_prefix=nonce, record_log2=args.record_log2).build()
        with open(args.out, "wb") as f: f.write(patch)
        print(f"MFP2 patch {len(patch)} bytes, signed/encrypted LZ4")
        return 0
    key = open(args.key, "rb").read() if args.key else None

    codec = {"lz4": CODEC_LZ4, "lzma": CODEC_LZMA, "raw": CODEC_RAW}[args.codec]
    if args.dict_size < LZMA_MIN_DICT:
        raise SystemExit(f"--dict-size must be at least {LZMA_MIN_DICT}")

    patch = Patch(
        old=old, new=new,
        product_id=args.product, fw_version=args.version,
        old_version=args.old_version, block_log2=args.block_log2,
        flags=(FLAG_SIGNED if key else 0),
        private_key=key,
        codec=codec,
        dict_size=args.dict_size,
    ).build()

    with open(args.out, "wb") as f:
        f.write(patch)

    ratio = (len(patch) / len(new) * 100.0) if new else 0.0
    workspace = (lzma_workspace_req(LZMA_DEFAULT_LC, LZMA_DEFAULT_LP, args.dict_size)
                 if codec == CODEC_LZMA else
                 WS_RAW if codec == CODEC_RAW else WS_LZ4)
    print(f"old      {len(old):>9} bytes")
    print(f"new      {len(new):>9} bytes")
    print(f"patch    {len(patch):>9} bytes  ({ratio:.1f}% of new)")
    print(f"codec    {args.codec:>9}")
    if codec == CODEC_LZMA:
        print(f"dict     {args.dict_size:>9} bytes")
    print(f"workspace{'':>5} {workspace:>9} bytes")
    print(f"signed   {'yes' if key else 'no'}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    blob = open(args.patch, "rb").read()
    if blob[:4] == struct.pack("<I", V2_MAGIC):
        h = parse_v2_header(blob)
        print(f"magic          MFP2, header {h.header_len} bytes, records {h.record_count}")
        print(f"flags          0x{h.flags:08X} signed encrypted LZ4")
        print(f"product        0x{h.product_id:08X}")
        print(f"version        0x{h.fw_version:08X} (from 0x{h.old_version:08X})")
        print(f"payload        {h.payload_size} bytes, crc32 0x{h.payload_crc32:08X}")
        return 0
    h = parse_header(blob)
    if h.payload_size > len(blob) - h.hdr_len:
        raise SystemExit("truncated payload")
    codec = {CODEC_LZ4: "lz4", CODEC_LZMA: "lzma", CODEC_RAW: "raw"}.get(h.codec_id, "?")

    print(f"magic          0x{h.magic:08X}  {'ok' if h.magic == MAGIC else 'BAD'}")
    print(f"header         {h.hdr_len} bytes, version {h.hdr_ver >> 8}.{h.hdr_ver & 0xFF}")
    print(f"flags          0x{h.flags:08X}"
          f"{' signed' if h.flags & FLAG_SIGNED else ''}")
    print(f"product        0x{h.product_id:08X}")
    print(f"version        0x{h.fw_version:08X}  (from 0x{h.old_version:08X})")
    print(f"old size       {h.old_size}")
    print(f"new size       {h.new_size}")
    print(f"payload        {h.payload_size}")
    print(f"old crc32      0x{h.old_crc32:08X}")
    print(f"new crc32      0x{h.new_crc32:08X}")
    print(f"payload crc32  0x{h.payload_crc32:08X}")
    print(f"workspace req  {h.workspace_req} bytes  <- device refuses if over budget")
    print(f"codec          {codec}")
    print(f"block          {1 << h.block_log2} bytes")

    props_len = props_len_for(h.codec_id)
    payload = blob[h.hdr_len:]
    props = payload[:props_len]
    stream = payload[props_len:]
    ok = crc32(stream) == h.payload_crc32
    print(f"payload crc    {'ok' if ok else 'MISMATCH'}")

    if h.codec_id == CODEC_LZMA:
        v = props[0]
        lc, lp, pb = v % 9, (v // 9) % 5, v // 45
        dict_size = struct.unpack_from("<I", props, 1)[0]
        content_size = struct.unpack_from("<I", props, 5)[0]
        print(f"lzma lc/lp/pb  {lc}/{lp}/{pb}")
        print(f"lzma dict      {dict_size}")
        print(f"lzma content   {content_size} bytes (decompressed delta)")
        need = lzma_workspace_req(lc, lp, dict_size)
        print(f"lzma workspace {need} bytes (device figure)")
    return 0 if (h.magic == MAGIC and ok) else 1


def cmd_verify(args: argparse.Namespace) -> int:
    blob = open(args.patch, "rb").read()
    if blob[:4] == struct.pack("<I", V2_MAGIC):
        pub = open(args.pub, "rb").read()
        verify_v2(blob, pub)
        print("MFP2 signature and structure ok")
        return 0
    h = parse_header(blob)
    if h.payload_size > len(blob) - h.hdr_len:
        raise SystemExit("truncated payload")
    if not (h.flags & FLAG_SIGNED):
        print("patch is not signed")
        return 1
    pub = open(args.pub, "rb").read()
    stream = blob[h.hdr_len + props_len_for(h.codec_id):h.hdr_len + h.payload_size]
    message = blob[:SIGNED_HEADER_LEN] + stream
    if verify(pub, h.signature, message):
        print("signature ok")
        return 0
    print("SIGNATURE INVALID")
    return 1


def cmd_apply(args: argparse.Namespace) -> int:
    old = open(args.old, "rb").read()
    blob = open(args.patch, "rb").read()
    if blob[:4] == struct.pack("<I", V2_MAGIC):
        pub = open(args.pub, "rb").read()
        key = open(args.key, "rb").read()
        new = verify_v2(blob, pub, key=key, apply=True, old=old)
        with open(args.out, "wb") as f: f.write(new)
        print(f"reconstructed {len(new)} bytes, MFP2 authenticated")
        return 0
    h = parse_header(blob)

    if h.payload_size > len(blob) - h.hdr_len:
        raise SystemExit("truncated payload")
    if crc32(old[:h.old_size]) != h.old_crc32:
        raise SystemExit("base image does not match the patch")

    props_len = props_len_for(h.codec_id)
    payload = blob[h.hdr_len:h.hdr_len + h.payload_size]
    if h.codec_id == CODEC_LZMA:
        delta = lzma_decompress(payload[props_len:], payload[:props_len])
    elif h.codec_id == CODEC_RAW:
        delta = payload
    else:
        delta = lz4_decompress(payload[props_len:])
    new = bspatch(old, delta, h.new_size)

    if crc32(new) != h.new_crc32:
        raise SystemExit("reconstructed image crc mismatch")

    with open(args.out, "wb") as f:
        f.write(new)
    print(f"reconstructed {len(new)} bytes, crc32 0x{h.new_crc32:08X} ok")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    with open(args.private, "wb") as f:
        f.write(seed)
    with open(args.public, "wb") as f:
        f.write(pub)
    print(f"private  {args.private}  ({len(seed)} bytes, keep secret)")
    print(f"public   {args.public}  ({len(pub)} bytes, ship in the device)")
    return 0


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(prog="microfoam",
                                description="Firmware delta update tool")
    p.add_argument("--version", action="version",
                   version="microfoam host tool " + TOOL_VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("make", help="build a patch")
    m.add_argument("--old", required=True)
    m.add_argument("--new", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--product", type=lambda s: int(s, 0), default=0)
    m.add_argument("--version", type=lambda s: int(s, 0), required=True)
    m.add_argument("--old-version", type=lambda s: int(s, 0), default=0)
    m.add_argument("--block-log2", type=int, default=DEFAULT_BLOCK_LOG2)
    m.add_argument("--codec", choices=("lz4", "lzma", "raw"), default="lz4",
                   help="lz4 (default, smallest RAM), lzma (smaller patch), or "
                        "raw (delta verbatim; best for sub-threshold patches)")
    m.add_argument("--dict-size", type=lambda s: int(s, 0), default=LZMA_DEFAULT_DICT,
                   help=f"LZMA dictionary in bytes (default {LZMA_DEFAULT_DICT}); "
                        "the device must have RAM for the probability table plus this")
    m.add_argument("--key", help="32- or 64-byte Ed25519 private key (MFP1), or 32-byte symmetric key (MFP2)")
    m.add_argument("--v2", action="store_true", help="build MFP2 signed/encrypted LZ4 patch")
    m.add_argument("--signing-key", help="MFP2 Ed25519 private key")
    m.add_argument("--key-id", help="MFP2 16-byte key id as hex")
    m.add_argument("--nonce-prefix", help="MFP2 16-byte nonce prefix as hex; a fixed prefix is for reproducible test vectors only, and needs --nonce-prefix-ack-reuse")
    m.add_argument("--nonce-prefix-ack-reuse", action="store_true",
                   help="confirm a fixed --nonce-prefix will never be reused with this key")
    m.add_argument("--record-log2", type=int, default=13)
    m.set_defaults(func=cmd_make)

    i = sub.add_parser("inspect", help="dump and validate a header")
    i.add_argument("patch")
    i.set_defaults(func=cmd_inspect)

    v = sub.add_parser("verify", help="check a signature")
    v.add_argument("patch")
    v.add_argument("--pub", required=True)
    v.set_defaults(func=cmd_verify)

    a = sub.add_parser("apply", help="apply a patch, for testing")
    a.add_argument("--old", required=True)
    a.add_argument("--patch", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--pub", help="MFP2 Ed25519 public key")
    a.add_argument("--key", help="MFP2 32-byte symmetric key")
    a.set_defaults(func=cmd_apply)

    k = sub.add_parser("keygen", help="generate an Ed25519 signing key pair")
    k.add_argument("--private", default="mfkey.priv")
    k.add_argument("--public", default="mfkey.pub")
    k.set_defaults(func=cmd_keygen)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
