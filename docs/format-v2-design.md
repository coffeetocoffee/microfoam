# Microfoam Container/API v2 Design Proposal

**Status:** design only; not implemented or supported.
**Scope:** reviewed LZMA, authenticated encryption, and codec-aware resume.
**Compatibility rule:** v1 remains unchanged and remains the default interoperable format. A v1 reader MUST reject v2. A v2 reader MAY support v1 through an explicit compatibility path, but MUST NOT infer v2 from v1 fields.

This document is a normative proposal for the next implementation phase. It intentionally does not change the current wire format or enable the quarantined LZMA decoder.

## 1. Goals and non-goals

### Goals

- Define a stable, reviewed LZMA1 codec profile with a bounded and enforceable decoder-memory requirement.
- Support optional confidentiality and integrity using libsodium XChaCha20-Poly1305-IETF, with no custom cryptographic primitives.
- Preserve bounded-memory streaming; ciphertext size must not imply allocating the whole patch payload.
- Define checkpoints only at restartable boundaries and bind each journal entry to the exact patch, codec profile, and serialized engine/codec state.
- Preserve existing v1/LZ4 behavior and fail closed on unsupported combinations.

### Non-goals

- No change to the shipped v1 LZMA profile; the v2 profile below is new, not a revision of it.
- No arbitrary seeking into one continuous LZMA stream.
- No claim that encryption hides metadata in the container header. Product/version/size/codec metadata remains visible.
- No key derivation, password handling, key storage, key rotation, or recipient management inside Microfoam. The integrator owns those policies.

## 2. Versioning and framing

Use a new four-byte magic `MFP2` and major version `2`. Do not change the meaning of `MFP1` or reinterpret v1's reserved bytes. V2 uses a fixed 192-byte base header followed by zero or more aligned TLV extensions, followed by a sequence of payload records.

All integers are little-endian. Header length includes the 192-byte base header and all TLVs. Unknown critical TLVs are rejected. Unknown noncritical TLVs may be ignored only when covered by the authentication/signature rules below.

### 2.1 Fixed base header (192 bytes)

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 4 | `magic` | `'MFP2'` |
| 4 | 2 | `header_len` | 192..4096 bytes; multiple of 4 |
| 6 | 2 | `format_version` | `0x0200` for v2.0 |
| 8 | 4 | `flags` | `SIGNED`, `ENCRYPTED`, `CODEC_LZMA`, `CODEC_LZ4`, `RESUME_CHUNKS`; all other bits rejected |
| 12 | 4 | `product_id` | Target product binding |
| 16 | 4 | `fw_version` | Must be strictly greater than running version |
| 20 | 4 | `old_size` | Base image size |
| 24 | 4 | `new_size` | Reconstructed image size |
| 28 | 4 | `payload_size` | Complete record-area byte count, including per-record tags and framing |
| 32 | 4 | `old_crc32` | CRC-32 of base image |
| 36 | 4 | `new_crc32` | CRC-32 of reconstructed image |
| 40 | 4 | `payload_crc32` | CRC-32 of the complete record area; corruption check only, not authentication |
| 44 | 4 | `workspace_req` | Maximum simultaneous decoder + record + engine workspace, excluding caller-owned flash buffers |
| 48 | 4 | `old_version` | Must equal running version |
| 52 | 1 | `codec_id` | 1=LZ4, 2=LZMA1 profile defined below |
| 53 | 1 | `record_log2` | 8..16; maximum plaintext/ciphertext bytes per record is `2^record_log2` |
| 54 | 2 | `tlv_len` | `header_len - 192` |
| 56 | 64 | `signature` | Ed25519 signature; all-zero when `SIGNED` is clear |
| 120 | 16 | `key_id` | Opaque key selector; all-zero when unencrypted |
| 136 | 24 | `nonce_prefix` | XChaCha20 nonce prefix; random/unique per key, all-zero when unencrypted |
| 160 | 4 | `record_count` | Number of payload records |
| 164 | 4 | `codec_profile` | 0=codec-defined default; otherwise a registered immutable profile id |
| 168 | 8 | `reserved` | MUST be zero |
| 176 | 16 | `header_digest` | Reserved in v2.0; MUST be zero. Future use requires a new minor revision and explicit rules. |

The signature field's location remains fixed so simple v2 readers can parse it. The signature input excludes bytes 56..119 but covers every other byte of the complete header, including `key_id`, nonce, TLVs, payload CRC, and lengths.

### 2.2 TLVs

Each TLV is `u16 type, u16 flags, u32 length, value[length], zero padding to 4-byte boundary`. Bit 0 of `flags` means critical. Unknown critical TLVs reject the patch. Unknown noncritical TLVs are retained in the authenticated header bytes and may be ignored semantically.

TLV values may carry codec tuning metadata, build provenance, or future policy. Security-sensitive parameters MUST NOT be placed in noncritical TLVs.

## 3. Payload records and AEAD

The payload area is a concatenation of `record_count` records. Each record is:

```
u32 ciphertext_len
u8  ciphertext[ciphertext_len]
u8  tag[16]
```

`ciphertext_len` MUST be in `1..2^record_log2`; all records except the last SHOULD be full sized. The concatenation of decrypted record plaintexts is the codec stream, including the codec profile/properties prefix as defined below.

### 3.1 XChaCha20-Poly1305-IETF

When `ENCRYPTED` is set:

- Each record is encrypted independently with `crypto_aead_xchacha20poly1305_ietf_encrypt_detached` or its combined equivalent.
- The 24-byte nonce is `nonce_prefix[0..15] || LE64(record_index)`. `record_index` starts at zero and MUST NOT wrap.
- The 32-byte key is returned by the integrator's v2 key-provider callback for the fixed 16-byte `key_id`. Microfoam does not store or derive keys.
- Associated data is `"MCF2REC\0" || header_without_signature || LE32(record_index) || LE32(ciphertext_len)`. `header_without_signature` is the complete `header_len` bytes with signature bytes 56..119 zeroed. The record framing length is authenticated.
- Tag verification MUST complete before any plaintext from that record is passed to the codec. On failure the session returns `MCF_E_AUTH` and writes no plaintext derived from that record to the destination.
- The same `(key, nonce)` pair MUST never encrypt different plaintext. The host tool generates a fresh random nonce prefix by default; deterministic builds require explicit nonce-prefix input and an operator guarantee of uniqueness.

When `ENCRYPTED` is clear, records retain the same length framing but have no tag and their data is plaintext. A v2 implementation MUST reject any mismatch between the flag and record layout.

### 3.2 Signatures and checksums

- `payload_crc32` covers exact on-wire record bytes, including ciphertext and AEAD tags. It is only an early corruption check.
- `SIGNED` covers `"MCF2SIG\0" || header_without_signature || complete_record_area`. This authenticates metadata and the complete encrypted or plaintext payload. Signature verification happens before flash writes.
- If both signature and AEAD are used, both MUST verify. AEAD protects confidentiality and per-record integrity; the signature provides publisher authenticity. Neither may be treated as a substitute for the other.
- If encrypted but unsigned patches are permitted by a product, that must be an explicit integrator policy. The library default policy SHOULD require signatures for firmware installation.
- The Ed25519 provider remains external/vetted (libsodium or hardware root of trust); the quarantined custom implementation is never linked.

## 4. Codec profiles

### 4.1 LZ4

V2 LZ4 uses the existing Microfoam framed LZ4 blocks, but each v2 record boundary is also an independent restart boundary. The record plaintext is one or more complete LZ4 frames; record boundaries MUST occur between frames, never inside a frame.

### 4.2 Reviewed LZMA1 profile

V2 codec id 2 means **raw LZMA1 stream using liblzma**, not `.xz` or `.lzma` container format. Properties prefix is exactly 16 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII `LZP2` |
| 4 | 1 | `lc` |
| 5 | 1 | `lp` |
| 6 | 1 | `pb` |
| 7 | 1 | reserved, zero |
| 8 | 4 | dictionary size, little-endian |
| 12 | 4 | exact decompressed delta size, little-endian |

Constraints: `lc <= 4`, `lp <= 4`, `lc + lp <= 4`, `pb <= 4`; dictionary is 4 KiB..16 MiB and must be a power of two; content size is nonzero and must match the engine input size. The encoder uses `lzma_raw_encoder`; the decoder uses `lzma_raw_decoder` with the stated filter chain and a custom `lzma_allocator` backed by Microfoam's bounded session allocator.

`workspace_req` is not trusted as a sufficient bound. v2 configuration sets `ram_budget`; before allocation, the adapter calculates liblzma's maximum dictionary plus probability/filter state and record buffers, rejects if that exceeds budget, then supplies an allocator that refuses allocations beyond the remaining budget. The library MUST NOT allow liblzma's default heap allocator in embedded mode.

A single raw LZMA1 stream is not independently restartable. Therefore LZMA resume uses the record profile below: each record contains a complete raw LZMA1 stream for one independently decodable delta segment. Segment boundaries MUST coincide with BSDIFF43 control-triple boundaries. The segment plaintext header is `u32 uncompressed_len`; LZMA properties are common header metadata. Each segment has an independent decoder and cannot reference bytes from earlier segments. Host tooling MUST split at triple boundaries and encode each segment separately.

The experimental 9-byte WIP properties block is never valid under v2.

## 5. Codec/API v2 contract

The public API adds:

- `mcf_codec_allocator_t`: caller-owned bounded allocate/free callbacks and remaining-budget accounting;
- `mcf_codec_ops_v2_t`: immutable descriptor with `workspace_bound`, `init`, `decode_record`, `finish_record`, `destroy`, and optional `checkpoint_size`, `checkpoint_export`, `checkpoint_import` callbacks;
- a caller-owned per-session codec table, preserving the existing no-global-registry rule;
- per-session `key_provider`, `decrypt_record`, and signature verifier contexts, independently of flash HAL context;
- explicit `mcf_format_policy` to allow v1, v2, unsigned, encrypted, and required-signature modes.

A codec checkpoint is opaque bytes with a codec ID and checkpoint schema version. The codec must serialize only state required to resume at a documented record boundary; it must not serialize pointers or allocator addresses. If the codec lacks checkpoint hooks or checkpoint schema differs, resume falls back to replay from the beginning. The engine checkpoint stores the next triple boundary and base cursor, not a compressed byte position inferred by the engine.

All callback failures are propagated with precise statuses. In particular, allocation exhaustion is `MCF_E_NOMEM`/`MCF_E_DICT_TOO_LARGE`, authentication failure is `MCF_E_AUTH`, and invalid checkpoint bytes cause a cold replay, not acceptance of unverified state.

## 6. Resume journal v2

Journal records are versioned and bind to a cryptographic patch identifier:

- magic, journal schema version, record length;
- 32-byte SHA-256 of the complete v2 header and record area (or a streaming digest recomputed during probe);
- output position and engine triple-boundary state;
- codec id + checkpoint schema version + checkpoint byte length + checkpoint bytes;
- CRC for torn-write detection.

The journal is not an authenticity source. Before using a checkpoint, the session validates journal CRC, patch digest, destination prefix CRC, codec id/schema, engine boundary invariants, and that the corresponding encrypted record has authenticated. A journal referencing an unauthenticated/future record is rejected. With no compatible codec checkpoint, the implementation replays from stream start and discards the already-programmed output prefix.

Journal persistence remains best-effort by default. Failure sets `MCF_SESSION_FLAG_RESUME_DEGRADED`; it never changes the correctness result of the image update.

## 7. Validation order

1. Check magic/version/header lengths and exact v2 flag combinations.
2. Parse TLVs; reject duplicate singleton types, malformed padding, unknown critical types, and nonzero reserved fields.
3. Validate product/version/rollback and sizes with overflow-safe arithmetic.
4. Validate codec ID/profile, record count, record framing bounds, total payload size, and worst-case workspace.
5. Check ciphertext record CRC (optional early rejection).
6. Verify publisher signature over canonical header and on-wire records when required.
7. Obtain key only after policy/signature checks; authenticate each record before handing plaintext to codec.
8. Decode/apply only authenticated record plaintext; enforce segment/triple boundary constraints.
9. Verify base and final image CRCs, read-back verify flash, then commit.

No flash erase/program begins before structural checks and required signature checks pass. For chunk authentication, an output chunk may be written only after the full corresponding AEAD record tag verifies.

## 8. Version compatibility

**v1 compatibility corrections:** the shipped v1 codec IDs are `1=LZ4` and `2=LZMA`; `0`
is the AUTO configuration value and is invalid on the wire. V1's current resume journal is
exactly 20 bytes (five little-endian `uint32_t` fields), despite an old comment that called
it 28 bytes. V2 defines its journal independently and MUST NOT infer its size or schema from
that stale comment.

- v1 (`MFP1`, major 1): unchanged. Only supported production codec remains LZ4; signatures use the current v1 canonical region. No encryption.
- v2 (`MFP2`, major 2): new header, record framing, and optional AEAD. v1 firmware rejects v2 as unsupported.
- No same-major reinterpretation of reserved v1 bytes.
- Unknown v2 major: reject. Unknown critical TLV: reject. Unknown codec/profile: reject before allocation or flash writes.
- Downgrade policy is still enforced using `fw_version`; format version does not bypass anti-rollback.

## 9. Host tooling and deterministic output

The host tool exposes explicit `--format v1|v2`, `--codec lz4|lzma`, `--encrypt`, key ID, and key input options. Default remains v1/LZ4 for compatibility. Encryption uses a cryptographically secure random nonce prefix by default, so encrypted outputs are intentionally nondeterministic unless a nonce prefix is explicitly supplied for reproducible builds. Reusing a prefix with the same key is a hard error unless an explicit unsafe-test-only override is enabled; release CLI must not expose that override.

Host `inspect` reports encryption/key ID/nonce/record count without printing secrets. `verify` validates the publisher signature; `apply` must authenticate/decrypt records before decoding. Python uses the installed `cryptography` implementation or PyNaCl/libsodium binding; it must not implement AEAD itself.

## 10. Acceptance tests before enabling v2

### LZMA

- Published liblzma raw LZMA1 vectors across profile constraints and dictionary boundaries.
- Encode/decode interoperability in both directions between Microfoam host tool and liblzma.
- Memory-cap tests proving the bounded allocator rejects over-budget dictionaries before allocation.
- Truncated input, invalid properties, wrong content size, malformed final record, and per-record reset tests.
- Cross-test applies host-generated LZMA v2 patches in C.

### AEAD

- Known XChaCha20-Poly1305-IETF vectors from libsodium/RFC test material.
- Valid encrypted+signed patch accepted; valid encrypted unsigned patch accepted only under explicit policy.
- Wrong key, changed nonce, changed key ID, changed authenticated header field, changed ciphertext, changed tag, reordered/duplicated/truncated records all rejected before affected output is written.
- Missing decrypt/key provider rejects encrypted patches with `MCF_E_UNSUPPORTED` or `MCF_E_AUTH`, consistently documented.
- Verify payload ciphertext/tag CRC is not mistaken for authenticity.

### Resume

- Interrupt/resume at every eligible record/triple boundary for LZ4 and LZMA segmented profiles.
- Checkpoint export/import round-trip for each codec and schema.
- Truncated, corrupted, foreign-patch, wrong-codec, wrong-schema, and unauthenticated-record journal checkpoints all cold-replay or reject safely.
- Mutation test demonstrates corrupted checkpoint state cannot reach flash without validation.

### Build/release

- Default v1 build has no liblzma/sodium dependency and passes existing C/Python/cross tests.
- Optional LZMA, sodium AEAD/signature, and combined builds pass CTest.
- Conan options are explicit and dependency propagation is verified by a downstream consumer build.
- No WIP handwritten LZMA/Ed25519 source appears in production source lists.

## 11. Open decisions before implementation

These are protocol/product decisions and must be resolved before coding v2:

1. **Key model:** one symmetric device-group key, per-device keys selected by `key_id`, or hardware-backed key-provider only? Recommended default: integrator key provider, per-device/tenant key slots, no key bytes in config files.
2. **Signature policy:** require publisher signature for all firmware patches, including encrypted ones? Recommended: yes by default; encryption is not publisher identity.
3. **LZMA segmentation:** are independent per-triple streams acceptable despite worse ratio, or should LZMA be v2 without resume optimization? Recommended first v2 release: independent segments for auditable restart; measure ratio before enabling.
4. **Encryption packaging:** may the host use PyNaCl (libsodium) or is Python `cryptography` a required dependency? This affects tool installation and interoperability tests.
5. **Public ABI:** v2 callbacks can be added alongside v1 APIs (`mcf_*_v2`) or by a major library API version bump. Recommended: parallel v2 API until downstream migration is complete.

Until these decisions are approved and the acceptance gates pass, v2 remains a design proposal and must not be advertised as implemented.
