# Streaming MFP2 Record Decryption — Design Note

**Status: IMPLEMENTED (2026-10-01). No wire change.** The design below is what
`src/mcf_v2_session.c` now does; see section 6 for what actually shipped and
where it deviates from the original sketch. Supersedes the earlier "PROPOSED"
state of this note.

## 1. Problem

The implemented MFP2 execution path (v1.6.0) decrypts **all** records into
workspace before handing the plaintext stream to the inner MFP1 session
(`mcf_v2_session_begin`, `src/mcf_v2_session.c`). The workspace contract is
therefore:

```
total_need = 124 (synthetic MFP1 header) + payload_size (all record plaintext)
```

The full decrypted delta must fit in RAM at once — **O(payload)** workspace.
On a target whose delta is large relative to its RAM (e.g. a 300 KB delta on a
256 KB-part MCU), execution is impossible today regardless of budget. The
ciphertext itself is never fully resident — only the plaintext — but that is
exactly the expensive part.

This note specifies the alternative: **decrypt record i only when the engine
reaches it, consume it, wipe it, move on** — O(record) plaintext workspace,
where record = 1 << record_log2 ≤ 8192 bytes.

This idea originated in an external insight ("integrate authenticated record
decryption into the session state machine"); the rest of that insight was
audited as already-implemented (see project history, 2026-10-01) — this is the
one genuinely open item it named.

## 2. Why it is feasible without a wire change

The format was designed so records are independent AEAD units. Nothing below
requires a header, TLV, framing, nonce, AAD, or signature change:

1. **Records authenticate independently.** Each record has its own detached
   tag, AAD (`"MCF2REC\0" || header(sig,payload-CRC zeroed) || LE32(i) ||
   LE32(len)`), and nonce (`nonce_prefix[0..15] || LE64(i)`). Record i can be
   authenticated at any time without seeing any other record.
2. **A record boundary is always a complete-LZ4-frame boundary** (frozen
   contract, §2 of the v2 design doc). The concatenated record plaintexts are
   self-contained framed LZ4 streams; the codec never needs bytes from the
   next record to finish the current one.
3. **The engine is already pull-based.** `mcf_engine_io_t.refill` drives
   decoding; the engine never assumes the whole stream is resident. The
   streaming design lives entirely in what `refill` returns.
4. **Resume already crosses record boundaries.** The record-aligned journal
   (v1.6.0) re-enters the feed at an arbitrary record with `in_discard`
   dropping the intra-record prefix — the machinery for "start feeding at
   record k" exists and is tested.

## 3. Design

### 3.1 What changes in the session

Today `mcf_v2_session_begin` runs one loop: parse framing → verify signature →
key lookup → for every record: AEAD-decrypt into `scratch[124+out]`. Then it
builds the synthetic MFP1 header and opens the inner session, whose
`mcf_sess_refill` LZ4-decodes from that fixed plaintext span
(`hdr.payload`/`payload_stream_len`, `src/mcf_session.c`).

In the streaming design the record loop **moves out of `begin()`** and into
the refill path:

- `begin()` performs only: validation order steps 1–5 (framing, policy,
  payload CRC, signature, key lookup), the framing walk *without* decryption
  (record offsets/lengths recorded in a small cursor table — O(record_count)
  metadata, already derivable from `mcf_v2_parse`'s validated view), synthetic
  header construction, and inner-session open. Crucially the synthetic header
  can no longer declare the exact decoded `delta_size` up front, because the
  LZ4 framing has not been walked yet — see §3.3.
- The inner session's `refill` is replaced by a v2-aware refill: when the LZ4
  decoder needs bytes past what the current record window holds, the refill
  authenticates + decrypts the **next** record into a ring/window buffer,
  advances the cursor, and returns the newly available span. One record is
  resident at a time; its plaintext is wiped as the window shifts past it.

### 3.2 The record window

Two buffers are needed, because the LZ4 framing walk (and `v2_lz4_size`-style
validation) may need to look at the current block while the engine consumes
the previous one:

```
window = 2 * (1 << record_log2)   double-buffer: current + next record
```

This is the same shape as the inner session's existing `inner_ws =
2*(1<<record_log2) + 16` decode window — the budget arithmetic already
demonstrates the pattern. Total workspace becomes:

```
124 (header) + window + inner engine workspace   →   O(record + block)
```

instead of `124 + payload_size + inner_ws`.

### 3.3 The three hard problems (and their resolutions)

**(a) The synthetic header's `delta_size` field (offset 120).** Today
`begin()` computes the exact decoded delta size by walking all plaintext LZ4
blocks (`v2_lz4_size`) before opening the inner session. Streaming cannot do
that without decrypting everything. Resolution: the MFP1 header field is
**the props-block content size the LZ4 codec enforces**
(`mcf_lz4_init` reads it; `mcf_lz4_finish` rejects a short stream). The
producer already guarantees that the concatenated LZ4 stream decodes to
exactly `new_size`-derived `delta_size`; but the *device* cannot verify the
declaration without the walk. Two honest options:

- **Option A (recommended): keep a begin()-time framing-only walk.** The
  record *lengths* are in the clear (framing, not content); decrypting is not
  needed to know *where* records start. But walking LZ4 *blocks* needs
  plaintext. So Option A means: stream-decrypt record-by-record during
  `begin()` too — but hold only one record at a time and keep only the running
  total (O(record) workspace, O(payload) CPU, exactly like today's CPU cost).
  After the walk, wipe and rewind the cursor, then run the engine. CPU doubles
  (the walk re-feeds LZ4 at run time) — no: the walk computes sizes only, it
  does not produce output the engine reuses. Accept this: **begin() cost
  ≈ today's begin() + one extra plaintext pass**, but RAM drops to O(record).
  Note this preserves today's *exact* failure-ordering semantics: a corrupt
  LZ4 stream is still rejected in `begin()` before any flash erase, because
  the framing walk covers every block of every record.
- **Option B: defer content validation to the engine.** The engine already
  stops at `new_size` (`mcf_engine.c`: `newpos >= newsize` → DONE; the sanity
  check bounds triples against `new_size`), and `mcf_lz4_finish` enforces
  `content_size`. Declaring `delta_size` as the *upper bound*
  `payload_size` (records decode to ≤ their ciphertext length in the worst
  expansion-free case... — **no**: LZ4 can expand, so no safe bound exists
  without the walk). Option B is rejected: an under-declared `delta_size`
  truncates a valid patch; an over-declared one lets a corrupt stream run
  until some later check. Option A it is.

**(b) Payload CRC (inner header offset 40 / `MCF_SITE_HDR_CRC`).** The inner
session's `finish()` recomputes the payload CRC by streaming over
`hdr.payload` — the fixed plaintext span that no longer exists. Resolution:
in the v2 path the *ciphertext* payload CRC is already verified against the
signature-covered header in `begin()` (`mcf_crc32` over
`patch[header_len..]`), so the inner check is redundant for v2 and must be
**suppressed** — add an internal flag (e.g. `mcf_config_t`-internal bit or an
`mcf_session` field set only by the v2 session) that skips inner payload-CRC
verification. This is not a weakening: the v2 payload CRC is checked earlier
and against signature-covered bytes; the inner check exists for the MFP1
direct path where the header is unauthenticated.

**(c) Resume interaction.** The v2 journal records `record_index` and
`record_base_d`; a resumed run starts the feed at record k. In the streaming
design the refill cursor simply initialises to k and the walk in (a) is
likewise started at k for the *size* computation (sizes of earlier records
are not needed — the engine resumes at absolute output coordinates and only
needs `delta_size` declared in the synthetic header; the walk must therefore
still cover records k..end to compute the total). Confirm: `delta_size` is a
whole-stream property, so the begin()-time walk cannot skip earlier records'
*content* — it must decrypt them too. Cost on resume is the same as a cold
begin(); the journal still saves flash re-programming, which is the point.
No journal format change.

### 3.4 Failure ordering (unchanged semantics)

The frozen contract (§6) requires: no flash erase/program before signature
verification; no plaintext to the codec before its tag authenticates. The
streaming design preserves both:

- Signature, key, and payload-CRC checks remain wholly inside `begin()` before
  any engine step.
- The begin()-time walk (Option A) authenticates every record before
  `mcf_session_begin` runs — so, exactly like today, **a record-level AEAD
  failure can never occur after the first flash erase**. This is a deliberate
  consequence of keeping the walk: if the walk were dropped, mid-execution
  AEAD failure handling would become a new failure surface (flash already
  partially programmed, session must fail closed with no rollback story).
  Do not drop the walk without revisiting §6.

### 3.5 What does NOT change

- Wire format, header offsets, AAD, nonce, signature domain, status mapping.
- The host (`host/microfoam.py`) — producer-side serialization is identical.
- The MFP1 engine and inner session for the direct MFP1 path.
- Parser, journal format, KAT vectors, tamper matrix expectations (statuses
  are unchanged; only *when* decryption happens moves).
- `mcf_v2_parse` inspection path.

## 4. Verification plan (when implemented)

1. All existing suites must pass unchanged (UCRT64 sodium 9/9, MSVC 7/7) —
   the boundary test's byte-exactness and zero-mutation assertions are the
   regression gate.
2. New test: a session configured with a workspace **too small for
   O(payload)** but larger than O(record) must (a) succeed byte-exact under
   the streaming design and (b) today's code rejects with
   `MCF_E_DICT_TOO_LARGE` — this is the differential that proves the feature.
3. Tamper matrix re-run: every variant must fail with the same status as
   today and zero flash mutations — in particular the *late-record* corruption
   case, which in the streaming design is still caught in `begin()` (§3.4).
4. Resume suite re-run unchanged (6 scenarios).
5. KAT unchanged (host-side construction is untouched).

## 5. When NOT to do this

- If all targets comfortably fit `payload_size + inner_ws` in RAM, the
  current design is simpler, fully verified, and should stay. The O(payload)
  design also has a virtue the streaming one gives up: the whole plaintext is
  CRC-checked in one place before anything runs.
- Do not attempt LZMA under streaming: LZMA is excluded from the executable
  profile precisely because its range coder has no mid-stream re-entry; the
  streaming window would multiply that problem, not solve it.
- Do not implement this opportunistically inside a bugfix. It is a
  begin()/refill restructure with its own verification burden (§4).

## 6. What shipped (2026-10-01)

Implemented in `src/mcf_v2_session.c` with an inert hook in
`src/mcf_session.c`. All four verification items above pass: UCRT64 sodium 9/9,
MSVC no-sodium 7/7, the tamper matrix with **identical statuses and zero flash
mutations**, the 6 resume scenarios, and the pinned KAT unchanged.

Concretely:

- **Workspace** is now `124 + (2*(1<<record_log2) + 4) + (16 + header_len)`,
  then the inner session's slice. For the CI fixture (record_log2 = 8,
  header_len = 192) that is **1376 bytes** where the resident-payload design
  needed **9412** — the boundary test asserts both numbers and runs the patch
  in the smaller workspace.
- **The feed** (`v2_feed_run`) is the whole mechanism: it keeps a sliding
  window of framed-stream bytes, decrypts records into it as the codec asks,
  compacts and wipes consumed bytes, and synthesises the four-byte terminal
  zero block that ends the framing. It reports only *complete* LZ4 blocks,
  because `mcf_lz4_decode` rejects a block that is not wholly present.
- **The inner session** gained a streamed-feed mode: `mcf_session_set_streamed`
  supplies an already-validated header view plus the feed callback, and
  `mcf_sess_refill` consults it instead of `hdr.payload`. With it unused the
  MFP1 path is byte-identical (all pre-existing MFP1 tests pass unchanged).
- **The payload-CRC walk is skipped** on this path (§3.3b), and the synthetic
  header carries a zero CRC field. The v2 ciphertext CRC is still checked in
  `begin()` against signature-covered bytes, so nothing is weakened.
- **`begin()` keeps its walk** (§3.3a, Option A) — one record at a time, so
  RAM stays O(record) while the exact `delta_size` is still known before any
  flash erase. The cost is one extra plaintext decrypt pass over the payload
  (CPU only; flash-bound workloads are unaffected).
- **The checkpoint** names the containing record from a small ring of recently
  decrypted `(index, decoded base, decoded length)` entries instead of
  re-parsing resident plaintext. Journal format and resume semantics are
  unchanged, and the resume tests pass untouched.
- **Key lifetime changed**: the key can no longer be wiped at the end of
  `begin()`, because the feed decrypts during `step()`. It is wiped in
  `v2_fail`, in `mcf_v2_session_finish`, and in `mcf_v2_session_close`.
  (This was the one bug the port introduced — an end-of-`begin()` wipe made
  every record fail authentication mid-run.)

Note the struct `mcf_v2_session_t` grew fields, so this is an ABI change for
callers compiled against v1.6.0; recompile against the new header.
