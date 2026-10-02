#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixture variants for the MFP2 boundary test.

Each variant is *structurally valid and correctly signed* but fails exactly one
downstream gate: the AAD record index, the nonce derivation, the AEAD tag, the
ciphertext, or the key id. That is the whole point of generating them here — a
plain bit-flip dies at the signature gate and therefore proves nothing about
the gate it is named after.

So every mutation is applied to the assembled container and the result is then
re-signed with a recomputed payload CRC. The device is left no cheap way out:
it has to reject on the strength of the binding under test.

`--self-check` asserts the property that makes a variant meaningful at all: it
must parse, carry a matching payload CRC and a valid signature, and only then
be rejected by the host verifier. A variant that dies at parse is a broken
fixture, not a passing test — which is precisely how a missing record_count
field once left the reorder and nonce cases silently vacuous.
"""
import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "host"))
import microfoam as M  # noqa: E402

V2_OFF_PAYLOAD_SIZE = 28
V2_OFF_PAYLOAD_CRC = 40
SIG_DOMAIN = b"MCF2SIG\0"

# A prefix the producer never used. The header declares it, the ciphertexts were
# sealed under the original one, so the device derives a different nonce.
WRONG_NONCE_PREFIX = bytes(range(0xE0, 0xF0))


def record_units(area: bytes):
    """Byte spans of each record unit: LE32 length || ciphertext || AEAD tag."""
    units = []
    pos = 0
    while pos < len(area):
        if len(area) - pos < 4:
            raise SystemExit("fixture record framing truncated")
        clen = struct.unpack_from("<I", area, pos)[0]
        span = 4 + clen + M.V2_RECORD_TAG_SIZE
        if span > len(area) - pos:
            raise SystemExit("fixture record framing overruns the area")
        units.append((pos, span))
        pos += span
    return units


def framed_records(hdr: bytes, area: bytes):
    """The record units of `area`, refusing anything the header does not declare.

    Every legitimate variant here mutates the record area in place and leaves
    its length alone, so the header's declared payload size is a real invariant
    to check against. It has to be checked: bytearray slice assignment RESIZES
    when the assigned span differs in length, and resign() recomputes
    payload_size from whatever it is handed, so a resized area would otherwise
    be blessed into a patch that is internally consistent, still signed, and no
    longer testing the binding it is named for. Counting units is not enough -
    the framing is self-describing, so a shortened area can still yield the
    declared number of units. Length is the anchor that actually catches it.
    """
    declared_len = struct.unpack_from("<I", hdr, V2_OFF_PAYLOAD_SIZE)[0]
    declared_count = struct.unpack_from("<I", hdr, M.V2_OFF_RECORD_COUNT)[0]
    if len(area) != declared_len:
        raise SystemExit(
            f"variant changed the record area length: {len(area)} bytes, "
            f"header declares {declared_len}")
    units = record_units(area)
    if len(units) != declared_count:
        raise SystemExit(
            f"variant no longer frames: {len(units)} record units, "
            f"header declares {declared_count}")
    return units


def resign(hdr: bytes, area: bytes, seed: bytes) -> bytes:
    """Re-derive payload size, payload CRC and signature over a mutated blob."""
    h = bytearray(hdr)
    area = bytes(area)
    framed_records(h, area)
    struct.pack_into("<I", h, V2_OFF_PAYLOAD_SIZE, len(area))
    struct.pack_into("<I", h, V2_OFF_PAYLOAD_CRC, M.crc32(area))
    h[M.V2_OFF_SIGNATURE:M.V2_OFF_SIGNATURE + M.SIG_SIZE] = M._ed25519ph_sign(
        seed, SIG_DOMAIN + M._v2_header_for_sig(h) + area)
    return bytes(h) + area


def self_check(name: str, blobv: bytes, pub: bytes, key: bytes, old: bytes) -> None:
    """Prove the variant reaches the gate it is named after, then is rejected."""
    h = M.parse_v2_header(blobv)
    area = blobv[h.header_len:]
    if M.crc32(area) != h.payload_crc32:
        raise SystemExit(f"{name}: variant fails its own payload CRC")
    if not M._ed25519ph_verify(pub, h.signature,
                               SIG_DOMAIN + M._v2_header_for_sig(blobv[:h.header_len]) + area):
        raise SystemExit(f"{name}: variant is not validly signed")
    framed_records(blobv[:h.header_len], area)
    try:
        M.verify_v2(blobv, pub, key=key, old=old)
    except SystemExit as exc:
        print(f"  self-check: {name} parses, is signed, and is rejected ({exc})")
        return
    raise SystemExit(f"{name}: host verifier ACCEPTED the variant")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--patch", required=True, help="valid MFP2 patch (fixture valid.mfp2)")
    ap.add_argument("--pub", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--old", required=True)
    ap.add_argument("--signing-key", required=True, help="32-byte Ed25519 seed")
    ap.add_argument("--out-reordered", required=True)
    ap.add_argument("--out-wrong-nonce", required=True)
    ap.add_argument("--out-tag-tamper", required=True)
    ap.add_argument("--out-ct-tamper", required=True)
    ap.add_argument("--out-bad-key-id", required=True)
    ap.add_argument("--self-check", action="store_true",
                    help="verify the variants are rejected by the host verifier")
    args = ap.parse_args()

    blob = Path(args.patch).read_bytes()
    pub = Path(args.pub).read_bytes()
    key = Path(args.key).read_bytes()
    old = Path(args.old).read_bytes()
    seed = Path(args.signing_key).read_bytes()
    if len(seed) not in (32, 64) or len(key) != 32:
        raise SystemExit("bad key sizes")
    seed = seed[:32]

    h = M.parse_v2_header(blob)
    hdr = blob[:h.header_len]
    area = blob[h.header_len:]
    if M.crc32(area) != h.payload_crc32:
        raise SystemExit("fixture patch fails its own payload CRC")
    if not M._ed25519ph_verify(pub, h.signature, SIG_DOMAIN + M._v2_header_for_sig(hdr) + area):
        raise SystemExit("fixture patch fails its own signature")

    units = framed_records(hdr, area)
    if len(units) < 2:
        raise SystemExit(f"need >=2 records for the reorder variant, got {len(units)}")
    (p0, l0), (p1, l1) = units[0], units[1]

    # Reordered records: the units are swapped verbatim, so record 0 now holds
    # the ciphertext that was produced for record 1. Signature and payload CRC
    # are rebuilt, so the container is well-formed and correctly signed; only
    # the AAD record index ties a ciphertext to its position. A device that
    # trusts framing order instead of the AAD index would decrypt garbage.
    # Rebuilt rather than slice-assigned: bytearray slice assignment RESIZES
    # when the spans differ, which silently shortens the record area and turns
    # the variant into a framing failure instead of an authentication one.
    swapped = (area[:p0] + area[p1:p1 + l1] + area[p0 + l0:p1]
               + area[p0:p0 + l0] + area[p1 + l1:])
    if len(swapped) != len(area):
        raise SystemExit("reorder variant changed the record area length")
    reordered = resign(hdr, swapped, seed)

    # Wrong nonce prefix: the header declares a prefix the producer never used,
    # so the device derives a different per-record nonce than the ciphertext was
    # sealed under. Everything else, the signature included, is valid.
    hh = bytearray(hdr)
    hh[M.V2_OFF_NONCE_PREFIX:M.V2_OFF_NONCE_PREFIX + M.V2_NONCE_PREFIX_SIZE] = WRONG_NONCE_PREFIX
    wrong_nonce = resign(bytes(hh), area, seed)

    # AEAD tag tamper: one bit of record 0's tag. The payload CRC is recomputed,
    # so the corruption is not caught by the cheap check first — the tag
    # verification is what has to reject it.
    a = bytearray(area)
    a[p0 + l0 - 1] ^= 1
    tag_tamper = resign(hdr, bytes(a), seed)

    # Ciphertext tamper: one bit of record 0's ciphertext, same reasoning.
    a = bytearray(area)
    a[p0 + 4] ^= 1
    ct_tamper = resign(hdr, bytes(a), seed)

    # Unknown key id: a different, still non-zero id, validly signed, so the
    # device reaches the key provider instead of dying at the signature gate.
    hh = bytearray(hdr)
    hh[M.V2_OFF_KEY_ID] ^= 1
    bad_key_id = resign(bytes(hh), area, seed)

    outputs = (
        (args.out_reordered, "reordered", reordered),
        (args.out_wrong_nonce, "wrong-nonce", wrong_nonce),
        (args.out_tag_tamper, "tag-tamper", tag_tamper),
        (args.out_ct_tamper, "ct-tamper", ct_tamper),
        (args.out_bad_key_id, "bad-key-id", bad_key_id),
    )
    for path, _name, blobv in outputs:
        Path(path).write_bytes(blobv)

    if args.self_check:
        for _path, name, blobv in outputs:
            self_check(name, blobv, pub, key, old)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
