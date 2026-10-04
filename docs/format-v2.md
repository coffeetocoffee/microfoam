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
| 52 | 1 | `codec_id` | 1 = LZ4, 2 = LZMA, 3 = raw. 0 is AUTO and is never valid on the wire; other values are unsupported. |
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
| 1 | `RAW` | The payload is the delta verbatim; the codec id must be `MCF_CODEC_RAW`. |
| 2 | `CODEC_LZMA` | LZMA codec. |
| 3 | `CODEC_LZ4` | LZ4 codec. |

The `RAW` flag and `codec_id == 3` must agree in both directions, exactly as the compressed
codec flags must agree with theirs: a flag set without the matching id is `MCF_E_FORMAT`, and
an id without its flag is too. This closes the trick of claiming compression that was never
applied, or the reverse.

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
| 10 | reserved field is zero; only known flags are set; the codec flag and `codec_id` agree in both directions (including RAW) | `MCF_E_FORMAT` |
| 11 | LZMA only: properties decode; `lc+lp` within `lzma_max_lc_plus_lp`; `dict_size <= lzma_max_dict` | `MCF_E_FORMAT` / `MCF_E_DICT_TOO_LARGE` |
| 12 | signature valid over the signed region (header[0..55] + compressed stream) | `MCF_E_SIGNATURE` |
| 13 | `payload_crc32` matches | `MCF_E_CORRUPT` |

Cheap structural checks come first; the cryptographic check comes last, after everything
that could be decided without it.

### Step 11 in detail — the LZMA parameter policy

The properties block declares `lc/lp/pb` and a dictionary size, and those two set the
decoder's resident cost: the probability table is `2 * (1984 + 768 << (lc + lp))` bytes and
the dictionary is allocated at the declared size. A product therefore configures
`mcf_config_t.lzma_max_dict` and `lzma_max_lc_plus_lp` (`0` = no limit) and the library
refuses a patch outside that policy here, during header validation and before any
allocation, reporting `MCF_SITE_HDR_LZMA_PROPS` or the workspace stage. The decoded
parameters remain readable through `mcf_session_lzma_info()` so the field failure is
diagnosable rather than just a number.

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

A codec's properties block sits at the head of the payload; the compressed (or raw) stream
follows immediately after it. `hdr_len` is where the payload starts, and the properties
length is fixed per codec id, so the split is unambiguous.

### Raw — 0 bytes

The payload is the delta stream verbatim: no properties, no framing, no per-block headers.
`MCF_FLAG_RAW` must be set and `codec_id` must be 3.

### LZ4 — 4 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `content_size`, exact decompressed length |

### LZMA — 9 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | encoded properties, `pb*45 + lp*9 + lc` |
| 1 | 4 | dictionary size, little-endian |
| 5 | 4 | `content_size`, exact decompressed length |

The 9-byte block is a stable wire contract. The device decoder is the vendored LZMA SDK
(`third_party/lzma-sdk`); it decodes raw LZMA1 with these parameters. The dictionary size
is part of the stream's meaning — a match reaching further back cannot be resolved — so
the host tool compresses with a dictionary the device can hold, and the declared size is
what the device allocates. The exact `content_size` is the truncation guard:
`mcf_lzma_finish()` reports `MCF_E_TRUNCATED` unless the decoder produced exactly that many
bytes. The device workspace is `2 * (1984 + (768 << (lc + lp)))` (probability table) plus
the SDK-rounded dictionary plus 256 bytes of decoder state; the host tool writes that figure
into `workspace_req`, and a build without `-DMCF_ENABLE_LZMA=ON` rejects the patch as
`MCF_E_UNSUPPORTED` before any allocation. See the README's Codecs section for the host
tool's `--codec lzma` usage and `docs/lzma-history.md` for why the decoder is the SDK.

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

**The decode window is a hard constraint.** The device decodes each block into a single fixed
buffer — the processing window, `cfg.block_size` clamped to `new_size` — so the widest window any
configuration can reach is exactly `new_size`. A block that would expand past it is rejected as
`MCF_E_CORRUPT` at site 17. A producer must therefore frame within the image
(`framing <= new_size`), and the device window must be at least the framing
(`cfg.block_size >= framing`). The host tool caps its framing at the image automatically and
writes the exponent it actually used to the header's `block_size_log2`; that header field drives
only the pre-allocation budget check (`1 << block_size_log2 > (ram_budget - workspace_req) / 2`
is `MCF_E_DICT_TOO_LARGE` at site 14, before anything is allocated), while the decode buffer comes
from the caller's `cfg.block_size`. MFP2 has the same inner window with the record size in the
framing role: its window is `min(record_size, new_size)`.

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
