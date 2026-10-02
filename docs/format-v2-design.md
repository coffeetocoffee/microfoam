# Microfoam Container/API v2 Executable Contract

**Status: approved wire/execution contract (2026-09-30); execution implemented (v1.6.0).**

This document freezes the executable MFP2 profile. `mcf_v2_session_*` implements
it: signature before key lookup, per-record authentication before decode, and
the unchanged MFP1 engine for the authenticated delta stream. `mcf_v2_parse()`
itself remains a structural parser only: success means shape validation, never
authenticity or acceptance. MFP1 is unchanged; an MFP1 reader rejects MFP2.

The sole executable v2 profile is **signed + encrypted + LZ4**. It uses
XChaCha20-Poly1305-IETF for per-record authenticated encryption and Ed25519ph
for publisher signatures. Plaintext, unsigned, LZMA, and other codec profiles
are forbidden for execution. There is no fallback/downgrade from this profile.

## 1. Fixed header and compatibility

All integers are little-endian. MFP2 has magic `MFP2`, major version `0x0200`,
a 192-byte fixed base header, zero or more aligned TLVs, then exactly
`record_count` records. `header_len` is 192..4096 inclusive, divisible by four;
`tlv_len == header_len - 192`. The offsets and sizes in
`include/microfoam_v2.h` are normative and unchanged:

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 4 | `magic` | `MFP2` |
| 4 | 2 | `header_len` | Base plus TLVs |
| 6 | 2 | `format_version` | `0x0200` |
| 8 | 4 | `flags` | Exactly `SIGNED | ENCRYPTED | CODEC_LZ4`; no other bit |
| 12 | 4 | `product_id` | Target product |
| 16 | 4 | `fw_version` | Strictly newer than running version |
| 20 | 4 | `old_size` | Base image size |
| 24 | 4 | `new_size` | Reconstructed image size |
| 28 | 4 | `payload_size` | Entire record area including 4-byte lengths and 16-byte tags |
| 32 | 4 | `old_crc32` | Base image CRC-32 |
| 36 | 4 | `new_crc32` | Reconstructed image CRC-32 |
| 40 | 4 | `payload_crc32` | CRC-32 over exact record-area bytes; corruption check only |
| 44 | 4 | `workspace_req` | Declared maximum simultaneous decoder/record/engine workspace; not a trusted bound |
| 48 | 4 | `old_version` | Must equal running version |
| 52 | 1 | `codec_id` | Exactly 1 (LZ4) |
| 53 | 1 | `record_log2` | 8..13 inclusive; record plaintext at most 8192 bytes |
| 54 | 2 | `tlv_len` | `header_len - 192` |
| 56 | 64 | `signature` | Ed25519ph signature; mandatory |
| 120 | 16 | `key_id` | Opaque symmetric-key selector; nonzero/meaningful for encryption |
| 136 | 24 | `nonce_prefix` | First 16 bytes used as nonce prefix; remaining 8 bytes MUST be zero |
| 160 | 4 | `record_count` | Number of records; nonzero |
| 164 | 4 | `codec_profile` | 0 only (defined LZ4 framing profile) |
| 168 | 8 | `reserved` | MUST be zero |
| 176 | 16 | `header_digest` | Reserved; MUST be zero |

The signature field is excluded from the signed header by replacing bytes
56..119 with zero, not by shifting or removing them. All other header bytes,
including the complete TLV area, are covered. Unknown critical TLVs reject;
unknown noncritical TLVs may be ignored semantically but remain covered by the
signature and AEAD associated data. TLV padding MUST be zero; duplicate
singleton TLVs reject. Security-critical parameters cannot be noncritical TLVs.

`CODEC_LZMA` and `RESUME_CHUNKS` are known legacy/reserved flag definitions for
source compatibility, but are not permitted in the frozen executable profile.
The codec flag and codec ID MUST agree exactly: LZ4 flag set, LZ4 ID, no LZMA
flag. Any other combination rejects.

## 2. Records and LZ4 profile

The record area consists of exactly `record_count` records:

```
u32 ciphertext_len       // little-endian, 1..2^record_log2
u8  ciphertext[ciphertext_len]
u8  tag[16]
```

Every record is independently XChaCha20-Poly1305-IETF authenticated. Ciphertext
length equals plaintext length. The concatenated record plaintext is a sequence
of complete existing Microfoam framed LZ4 blocks/streams; a record boundary
MUST be between complete LZ4 frames, never within one. Decode/engine semantics
remain the existing BSDIFF43 semantics. There is no LZMA or codec auto-detection.

The records MUST consume exactly `payload_size`, and the input patch MUST
contain exactly `header_len + payload_size` bytes (no missing or trailing data).
Lengths, sums, record counts, and offset arithmetic are checked without integer
overflow. Empty records are invalid. Record indices are `0..record_count-1` and
must not wrap.

## 3. Key provider and key lifetime

The implemented execution API obtains the 32-byte symmetric key only through the
`mcf_v2_key_provider_fn` declaration in `include/microfoam_v2.h`. It passes the
fixed 16-byte `key_id`, writes the key to caller/library-provided output, and
returns `MCF_OK` only with a complete key. The callback and its context must
remain valid until the operation completes. Microfoam does not derive, persist,
log, or retain keys between operations. The host/integrator is responsible for
key provisioning and key-id mapping.

All key copies, including callback output, temporary key state, and crypto
library scratch containing key material, MUST be erased on every success and
failure path with a non-optimizable zeroization operation before their storage
is released or reused. A provider failure is fail-closed; no decryption, codec
input, or flash modification follows it. The provider's negative status is
propagated; an invalid positive/nonzero callback result is `MCF_E_IO`.

## 4. Nonce and associated-data construction

Use libsodium-compatible XChaCha20-Poly1305-IETF semantics. For record index
`i`, the 24-byte nonce is exactly

```
nonce_prefix[0..15] || LE64(i)
```

The 8 bytes at header offsets 152..159 are required zero, so the defined 16-byte
prefix does not collide ambiguously with the independently stored record count.
A `(key, nonce)` pair MUST never encrypt different plaintext. Producers generate
a fresh unpredictable 16-byte prefix for each patch/key pair; prefix reuse for a
key is a hard production error. Deterministic output is allowed only when the
operator independently guarantees uniqueness.

For each record, associated data is the exact concatenation

```
"MCF2REC\0"                         // 8 bytes
header[0..header_len), with [56..119] zeroed
LE32(record_index)
LE32(ciphertext_len)
```

The record length is therefore authenticated. The 16-byte AEAD tag is not part
of AAD; it is the detached tag for that record. Tag verification MUST finish
before any plaintext from that record is exposed to the codec or engine.

## 5. Ed25519ph signed message

The mandatory signature algorithm is RFC 8032 Ed25519ph, not ordinary Ed25519
and not Ed25519 over an application-computed SHA-512 digest. The exact message
fed to Ed25519ph is the byte concatenation

```
"MCF2SIG\0"                         // 8-byte domain separator
header[0..header_len), with [56..119] zeroed
complete record area[0..payload_size) // lengths, ciphertexts, and tags as stored
```

The signature field at 56..119 contains the 64-byte Ed25519ph signature over
that message. Implementations MUST use a vetted RFC 8032 Ed25519ph provider and
must use its prehash-mode API with the exact domain message above. Missing
verifier/provider or missing signed flag is rejection, never acceptance. The
signature is checked before any flash erase/program; a bad signature returns
`MCF_E_SIGNATURE`. AEAD is still mandatory and independently checked: the
signature does not substitute for record authentication and vice versa.

`payload_crc32` covers the exact on-wire record area including lengths,
ciphertexts, and tags. It can reject accidental corruption early but is not an
authenticator and MUST NOT stand in for signature or AEAD verification.

## 6. Fail-closed validation, ordering, and statuses

No flash erase or program may begin until all structural checks, policy checks,
payload CRC, and mandatory signature verification have succeeded. A record's
plaintext may reach the codec only after its tag authenticates. No bytes derived
from a failed record may reach the destination. On any failure, stop processing,
release resources, wipe key/plaintext scratch as applicable, and leave no
partially trusted data eligible for later use. Never retry with weaker
cryptography, treat CRC as authentication, or accept an unsupported profile.

Normative checks and status mapping:

| Condition | Status |
|---|---|
| Null/invalid API arguments | `MCF_E_PARAM` |
| Bad magic, invalid lengths/flags/reserved/TLV, invalid codec-profile agreement, invalid record framing or trailing bytes | `MCF_E_FORMAT` |
| Unsupported major/version or unsupported crypto/provider/profile capability | `MCF_E_UNSUPPORTED` |
| Declared bytes extend past available patch input | `MCF_E_TRUNCATED` |
| Product mismatch | `MCF_E_PRODUCT` |
| `fw_version` is not newer | `MCF_E_ROLLBACK` |
| `old_version` or base-image identity/CRC mismatch | `MCF_E_MISMATCH` |
| Payload CRC mismatch or malformed/corrupt decoded content | `MCF_E_CORRUPT` |
| Signature absent when required, invalid, or verifier reports verification failure | `MCF_E_SIGNATURE` |
| Valid signature but AEAD tag/key authentication failure | `MCF_E_AUTH` |
| Key provider reports unavailable key | `MCF_E_AUTH`; provider's other negative operational status is propagated |
| Key provider returns invalid positive/nonzero result | `MCF_E_IO` |
| Workspace allocation failure | `MCF_E_NOMEM` |
| Workspace exceeds configured budget | `MCF_E_DICT_TOO_LARGE` |
| Source I/O failure | `MCF_E_IO` |
| Decode truncation | `MCF_E_TRUNCATED` |
| Flash failure | `MCF_E_FLASH` |

`MCF_E_AUTH` is implemented in the public `mcf_status_t` and is the required
v2 execution status for authenticated key/tag failure. Authentication failure
MUST NOT be aliased to `MCF_OK`, CRC-only success, or a weaker verification
status.

Validation order:

1. Validate arguments, MFP2 magic/version, header and total patch lengths.
2. Validate exact required flags, codec ID/profile, record log2 (8..13), reserved
   bytes, TLVs, and overflow-safe product/version/size constraints.
3. Validate all framing/count/lengths consume exactly the record area; compute
   and check payload CRC.
4. Verify mandatory Ed25519ph signature over the exact domain-separated message.
5. Obtain key via callback, validating callback result; wipe key on every exit.
6. Authenticate each record before releasing plaintext to LZ4/engine.
7. Verify base and reconstructed image CRCs, perform flash read-back verification,
   then commit. No erase/program precedes step 4.

## 7. Implementation acceptance boundary

MFP2 execution is implemented in `src/mcf_v2_session.c`: a caller-owned session
performs the validation order above, uses vetted streaming Ed25519ph and
XChaCha20-Poly1305 providers, authenticates each record before
decode/application, and wipes key and plaintext scratch on all exits. Records are
decrypted one at a time into a small sliding window and consumed as the engine
asks for them, so the decrypted payload is never wholly resident; workspace is
O(record), not O(payload). `begin()` walks every record once to obtain the exact
decoded delta size the synthetic MFP1 header must declare, so a record-level AEAD
failure is still detected before the first flash erase. The
acceptance evidence is the sodium CI job, which runs `sodium_rfc_test`
(RFC 8032 and AEAD tamper coverage) plus the `mfp2_host_to_session` test: a
PyNaCl-produced signed/encrypted patch is applied end to end by the C session,
byte-compared to the target image, and rejected under every tamper variant
(signature, ciphertext, key, key id, tag, truncation, header, reordering,
nonce prefix) with zero flash mutations. That test also applies the same patch in
a workspace far smaller than the decrypted payload, which the resident-payload
design could not. Parser success alone remains inspection-only; execution is the
session path.

The structural parser carries its own property contract, shared through
`tests/v2_parse_fixture.h` by a deterministic mutation loop
(`tests/v2_format_test.c`) and a coverage-guided fuzz target
(`tests/fuzz_v2_parse.c`, built with `MCF_BUILD_FUZZER=ON`): for every input,
`mcf_v2_parse` returns a defined status, leaves the input buffer byte-identical,
and - on success - yields a view that an independent re-derivation of the frozen
framing reproduces, with iteration yielding exactly `record_count` records. The
portable `v2_fuzz_smoke` target runs those assertions on every platform; the CI
`fuzz` job adds Clang/libFuzzer coverage guidance under ASan/UBSan over a corpus
of real host-produced patches.

## 8. Resume (record-aligned)

Resume is an optimisation layered on a scheme that is already safe without it:
the destination is a staging region, and recovery is always "start over" from
it. The journal exists to avoid re-transferring and re-programming the part
already done after a power cut, not to make the update correct.

**Design.** The journal lives in a caller-designated NVM region
(`mcf_v2_config_t.journal_addr`, block-aligned, outside the destination), the
same shape as MFP1's. It is opt-in: with `journal_addr == 0` the session never
touches NVM and behaves exactly as a cold run.

The session arms the inner engine to halt exactly on erase-block boundaries
(`mcf_session_set_stop`); whenever it halts there, the session captures the
engine's complete position (`mcf_session_snapshot`: next unconsumed
decompressed byte, output offset, base cursor, phase, and the outstanding diff
and literal counts - a mid-triple point included) and writes one
`mcf_v2_journal_t`. `record_index` and `record_base_d` name the record whose
plaintext contains that byte and the decoded offset where the record starts.

A resume re-authenticates and re-feeds the codec from that record onward only.
The already-programmed records below it are neither re-fed nor re-written:
`mcf_session_restore` positions the engine at the recorded point, dropping the
intra-record prefix before interpreting anything, and `out_off` - always a
multiple of the erase-block size - means the block containing it is treated as
disposable and re-erased on first use, discarding whatever the interrupted run
left half-written there. Work repeated: at most one record's plaintext,
bounded by `2^record_log2` bytes. Work saved: the flash erase and program of
the entire prefix.

**Integrity.** `prefix_crc32` is compared against a fresh read of the
reconstructed prefix, `session_id` binds the record to this exact patch
header, and the record carries its own CRC; a damaged, stale, or foreign
record returns `MCF_E_NOT_FOUND` and the update starts clean - an ordinary
condition after a power cut, not an error. Like MFP1's journal it is not an
authenticity control: it lives in NVM the device itself writes, and an
attacker who can write that NVM has already won. Patch authenticity is
sections 4-6's job.

**Failure handling.** A checkpoint that cannot be written does not abort the
update; the session stops checkpointing and sets
`MCF_V2_SESSION_FLAG_RESUME_DEGRADED` so callers that require resumability can
see the lost guarantee. A finished update clears the journal.

**Scope note.** This is record-granular resume for MFP2's structure, not a
codec-vtable rewind. MFP1's replay-based resume is unchanged; its one real
correctness fix in this area is re-arming the erase cursor to the start of the
erase block that contains the resume point, so a partially programmed block is
rewritten whole (covered by the MFP1 resume tests).
