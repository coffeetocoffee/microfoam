#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixture variants for the MFP2 boundary test.

Builds patches that carry a *valid signature over structurally invalid
content* — re-ordered records and a mismatched nonce prefix — so the C test
can prove the device rejects them for the right reason rather than dying at
the signature gate like a plain bit-flip does. Run with --self-check, it
also proves the host verifier catches both variants.
"""
import argparse
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "host"))
import microfoam as M  # noqa: E402


def load_variant_inputs(blob: bytes, pub: bytes, key: bytes, old: bytes):
    """Shared parse + decrypt, returning the pieces variants re-assemble."""
    h = M.parse_v2_header(blob)
    area = blob[h.header_len:]
    if M.crc32(area) != h.payload_crc32:
        raise SystemExit("fixture patch fails its own payload CRC")
    if not M._ed25519ph_verify(pub, h.signature,
                               b"MCF2SIG\0" + M._v2_header_for_sig(blob[:h.header_len]) + area):
        raise SystemExit("fixture patch fails its own signature")
    records = []
    pos = 0
    for i in range(h.record_count):
        clen = struct.unpack_from("<I", area, pos)[0]
        enc = area[pos + 4:pos + 4 + clen + 16]
        aad = b"MCF2REC\0" + M._v2_header_for_aad(blob[:h.header_len]) + struct.pack("<II", i, clen)
        plain = M._v2_open(key, h.nonce_prefix[:M.V2_NONCE_PREFIX_SIZE] + struct.pack("<Q", i), enc, aad)
        records.append(plain)
        pos += 4 + clen + 16
    if pos != len(area):
        raise SystemExit("fixture record framing mismatch")
    return h, records


def reassemble(h, records, nonce_prefix: bytes, signing_seed: bytes, key: bytes) -> bytes:
    """Rebuild a patch from plaintext records with a fresh nonce prefix."""
    hlen = h.header_len
    hdr = bytearray(hlen)
    struct.pack_into("<IHHIIIIIIIIIII", hdr, 0, M.V2_MAGIC, hlen, M.V2_VERSION,
                     M.V2_REQUIRED_FLAGS, h.product_id, h.fw_version,
                     h.old_size, h.new_size, 0, h.old_crc32, h.new_crc32, 0,
                     h.workspace_req, h.old_version)
    struct.pack_into("<BBH", hdr, 52, M.CODEC_LZ4, h.record_log2, h.tlv_len)
    hdr[120:136] = h.key_id
    hdr[136:152] = nonce_prefix
    hdr[192:hlen] = h.tlvs
    record_log2 = h.record_log2
    area = bytearray()
    for i, plain in enumerate(records):
        if len(plain) > (1 << record_log2):
            raise SystemExit("record exceeds declared record size")
        aad = b"MCF2REC\0" + M._v2_header_for_aad(hdr) + struct.pack("<II", i, len(plain))
        enc = M._v2_aead(key, nonce_prefix + struct.pack("<Q", i), plain, aad)
        area += struct.pack("<I", len(plain)) + enc
    struct.pack_into("<I", hdr, 28, len(area))
    struct.pack_into("<I", hdr, 40, M.crc32(bytes(area)))
    sigmsg = b"MCF2SIG\0" + M._v2_header_for_sig(hdr) + bytes(area)
    hdr[56:120] = M._ed25519ph_sign(signing_seed, sigmsg)
    return bytes(hdr) + bytes(area)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--patch", required=True, help="valid MFP2 patch (fixture valid.mfp2)")
    ap.add_argument("--pub", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--old", required=True)
    ap.add_argument("--signing-key", required=True, help="32-byte Ed25519 seed")
    ap.add_argument("--out-reordered", required=True)
    ap.add_argument("--out-wrong-nonce", required=True)
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

    h, records = load_variant_inputs(blob, pub, key, old)
    if len(records) < 2:
        raise SystemExit(f"need >=2 records for reorder variant, got {len(records)}")

    # Reordered records: same plaintexts, swapped encryption order. A device
    # that trusts framing order instead of the AAD record index would decrypt
    # garbage that still carries a valid signature.
    swapped = list(records)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    nonce = bytes(range(0xF0, 0x100))
    reordered = reassemble(h, swapped, nonce, seed, key)
    Path(args.out_reordered).write_bytes(reordered)

    # Wrong nonce prefix: valid signature, keys and key id all correct, but
    # the device derives a different nonce than the producer used.
    nonce2 = bytes(range(0xE0, 0xF0))
    wrong_nonce = reassemble(h, records, nonce2, seed, key)
    Path(args.out_wrong_nonce).write_bytes(wrong_nonce)

    if args.self_check:
        # Both variants must pass the signature check yet fail authentication
        # or reconstruction in the host verifier.
        for name, blobv in (("reordered", reordered), ("wrong-nonce", wrong_nonce)):
            try:
                M.verify_v2(blobv, pub, key=key, old=old)
            except SystemExit:
                pass
            else:
                raise SystemExit(f"host verifier ACCEPTED the {name} variant")
            print(f"  self-check: {name} variant rejected by host verifier")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
