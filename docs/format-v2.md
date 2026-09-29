# Microfoam patch container format, version 1.0

Magic `'MFP1'` — 0x3150464D, little-endian.

All integers are little-endian at fixed offsets with no padding. The header is naturally
aligned and needs no packing. Both the C reference (`src/mcf_container.c`) and the Python host
tool (`host/microfoam.py`) assert their field offsets against this table independently, and
`host/selftest.py` compares the two implementations field by field, so they cannot drift.

## Layout

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 4 | `magic` | `0x3150464D` (`'MFP1'`) |
| 4 | 2 | `hdr_len` | Header size in bytes. 120 in v1.0. Allows extension. |
| 6 | 2 | `hdr_ver` | Major in the high byte, minor in the low. v1.0 = `0x0100`. |
| 8 | 4 | `flags` | See below. |
| 12 | 4 | `product_id` | Product or board binding. Compared against the device's provisioned value. |
| 16 | 4 | `fw_version` | Version of the image this patch produces. Must be strictly greater than the running version. |
| 20 | 4 | `old_size` | Length of the base image this patch applies to. |
| 24 | 4 | `new_size` | Length of the reconstructed image. |
| 28 | 4 | `payload_size` | Bytes following the header, including codec properties. |
| 32 | 4 | `old_crc32` | CRC-32 of the base image. |
| 36 | 4 | `new_crc32` | CRC-32 of the reconstructed image. |
| 40 | 4 | `payload_crc32` | CRC-32 of the compressed stream, excluding codec properties. |
| 44 | 4 | `workspace_req` | **Decoder RAM required, in bytes.** The keystone field. |
| 48 | 4 | `old_version` | Version of the base image this patch requires. Must equal the running version. |
| 52 | 1 | `codec_id` | 1 = LZ4, 2 = LZMA. 0 is AUTO and is never valid on the wire; other values are unsupported. |
| 53 | 1 | `block_size_log2` | log2 of the processing window. 8..20. |
| 54 | 2 | `reserved` | Must be zero. |
| 56 | 64 | `signature` | Ed25519 signature, R‖S. Zero when `FLAG_SIGNED` is clear. |
| 120 | var | `codec_props` | Codec parameters. |
| 120 + n | var | `payload` | Compressed delta stream. |

`hdr_len` is 120 bytes in v1.0. The payload begins at `hdr_len`, not at 120, so a future minor
revision may append fields.

### Why the signature field is 64 bytes

An Ed25519 **signature** is 64 bytes (two 32-byte halves, R and S). Its **public key** is 32
bytes. Conflating the two shifts the payload by 32 bytes and corrupts every field after it.
This is a regression test in `host/selftest.py`; it was a real defect during development.

## Flags

| Bit | Name | Meaning |
|---|---|---|
| 0 | `SIGNED` | `signature` is populated and must verify. |
| 1 | `RAW` | The payload is not compressed. |
| 2 | `CODEC_LZMA` | LZMA codec. |
| 3 | `CODEC_LZ4` | LZ4 codec. |

## Signed region

The signature covers `header[0 .. 56)` followed by the compressed stream, excluding the signature
field and codec-properties block. The verifier callback receives these as two spans; implementations
must verify their concatenation without including the properties bytes. `payload_crc32` covers the
stream alone.

## Validation order

Performed once, in `mcf_hdr_parse()`. Everything downstream trusts the result.

| # | Check | Rejection |
|---|---|---|
| 1 | `magic == 'MFP1'` | `MCF_E_FORMAT` |
| 2 | major version supported | `MCF_E_UNSUPPORTED` |
| 3 | `MIN_HDR <= hdr_len <= MAX_HDR`, and `hdr_len <= patch_size` | `MCF_E_FORMAT` |
| 4 | `product_id` matches the device | `MCF_E_PRODUCT` |
| 5 | `fw_version` strictly greater than the running version | `MCF_E_ROLLBACK` |
| 6 | `old_version` equals the running version | `MCF_E_MISMATCH` |
| 7 | `codec_id` known to this build and permitted by the configuration | `MCF_E_UNSUPPORTED` |
| 8 | sizes consistent; `payload_size <= patch_size - hdr_len`; `block_size_log2` in 8..20 | `MCF_E_FORMAT` / `MCF_E_TRUNCATED` |
| 9 | `workspace_req <= ram_budget`, and two block buffers also fit | `MCF_E_DICT_TOO_LARGE` |
| 10 | reserved field is zero; only known flags are set; RAW is rejected; codec flag agrees with `codec_id` | `MCF_E_FORMAT` |
| 11 | signature valid over the signed region (header[0..55] + compressed stream) | `MCF_E_SIGNATURE` |
| 12 | `payload_crc32` matches | `MCF_E_CORRUPT` |

Cheap structural checks come first; the cryptographic check comes last, after everything
that could be decided without it.

### Step 9 in detail

This is the check the format exists for.

The patch states the decoder RAM it needs. The device compares that against the integrator's
`ram_budget` **during header validation, before a single byte is allocated.** A patch that
demands more memory than the device has is rejected with `MCF_E_DICT_TOO_LARGE`.

Without this field, a device with insufficient heap discovers the shortfall only when the
allocator returns `NULL` part-way through initialisation — and a decoder that does not check
that return value will proceed to dereference a null dictionary. That is a hard fault in the
field, reachable by anyone who can influence patch production.

Note that the allocation size is subsequently taken from the codec's own
`workspace_size()` result rather than from this field, so a header that *under*-declares
cannot cause an allocation smaller than the codec needs.

## Codec properties

### LZ4 — 4 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `content_size`, exact decompressed length |

### LZMA — experimental and unsupported

The handwritten LZMA decoder is a non-shippable WIP under `contrib/lzma-wip/` and
currently passes only 133/335 conformance cases. Its 9-byte properties block is an
internal experiment, not a stable wire-format contract. Production builds must leave
`MCF_ENABLE_LZMA` off and reject LZMA patches; use a reviewed liblzma integration and
a new format revision before standardizing LZMA.

## LZ4 stream

```
repeat:
  u32 le  block_len        (0 marks the end of the stream)
  u8[]    block_len bytes of LZ4 block-format data
```

The explicit `content_size` and the end marker are what make truncation detectable: a stream
cut short leaves the decoder unable to reach the declared total or to find the end marker,
and `mcf_lz4_finish()` reports `MCF_E_TRUNCATED` rather than accepting a short
reconstruction.

## Delta stream

After decompression, the stream is BSDIFF43: a sequence of control triples.

| Field | Encoding |
|---|---|
| `diff_len` | 8 bytes, sign-magnitude, little-endian |
| `extra_len` | 8 bytes, sign-magnitude, little-endian |
| `seek` | 8 bytes, sign-magnitude, little-endian |

**The sign-magnitude encoding is not two's complement.** The top bit is a sign flag and the
magnitude occupies the low 55 bits. This is the Endsley variant, so patches are **not**
interchangeable with those produced by Colin Percival's original `bsdiff`.

Application semantics, in order:

1. Read the triple.
2. For `diff_len` bytes, add the corresponding base-image bytes, treating positions outside
   the base image as zero.
3. Emit `extra_len` literal bytes.
4. Advance the base cursor by `seek`.

Because the seek is applied **after** the diff, it positions the base for the **next** triple,
not for its own. Getting this backwards produces a stream that reconstructs almost-correctly
and fails only at the end — see the note in `host/microfoam.py`.

Bounds enforced by the engine: `diff_len` and `extra_len` are non-negative and bounded to
`INT32_MAX`; `newpos + diff_len + extra_len` may not exceed `new_size`; and the base cursor is
checked for overflow in both directions, so a malicious triple cannot walk it anywhere.

## Compatibility

| | |
|---|---|
| Forward | An unknown major version is rejected with `MCF_E_UNSUPPORTED`. A newer minor may be accepted by ignoring fields beyond `hdr_len`. |
| Backward | The BSDIFF43 delta payload is unchanged from earlier tooling. Only the container header is new, so a v1 patch converts with a header translation and no re-diff. |
| Renaming | A format revision re-badges the magic to `'MFP2'`; `hdr_ver` remains authoritative. |
