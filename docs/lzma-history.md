# The retired from-scratch LZMA decoder

**Status: retired. Superseded by the vendored LZMA SDK (`third_party/lzma-sdk`).**
The decoder reached 133 of 335 vector/block-size combinations and was not shipped.
Rather than continue chasing the remaining defect, the project adopted the reviewed
upstream implementation, which passes 335/335 (`tests/lzma_conformance_test.c`).
This page is kept as a record of the defect classes and the method lessons, because
they are the argument for using a reviewed range coder instead of a hand-written one.

The original work-in-progress files (`mcf_lzma.c`, `mcf_lzma.h`, `lzma_test.c`,
`lz_callprobe.c`, `lz_oracle.py`) were removed when the SDK was adopted. The vector
generator lives on as `host/lzma_vectors.py` and the harness as
`tests/lzma_conformance_test.c`.

## Contents (as they existed before retirement)

| File | Purpose |
|---|---|
| `mcf_lzma.c` / `mcf_lzma.h` | From-scratch LZMA1 decoder: range coder, literal state machine, length and distance decoders, dictionary ring (removed; now `third_party/lzma-sdk` + `src/mcf_lzma.c`) |
| `lzma_test.c` | Conformance harness: 67 vectors x 5 block sizes (now `tests/lzma_conformance_test.c`) |
| `lz_callprobe.c` | Per-call state dump, for locating a divergence (removed) |
| `../host/lzma_vectors.py` | Generates the vectors using Python's `lzma` module, i.e. liblzma (retained) |

The **vector generator is the valuable part.** 67 vectors from liblzma covering the literal
state machine in both its plain and match-byte forms, repeated distances, the position-slot
and alignment trees, a 4 KB dictionary against a 20 KB input so the ring wraps repeatedly,
and the full legal `lc`/`lp`/`pb` range (liblzma constrains `lc + lp <= 4`). Average ratio
13.8%. The harness decodes each at five block sizes, because a match may straddle any
boundary and the result must not depend on chunking.

**liblzma is the only valid oracle.** The `Decoder` class in `host/lzma_vectors.py` is *not*
independent - it was written from the same understanding as the C, so it can only confirm the
two agree, never that either is right. It carried the same layout bugs the C had and produces
`0xff` where liblzma produces `0x73`. Judge this decoder solely against liblzma output.
## Defects found and fixed

**Round one - six defects, none of which moved the failure count:**

| Defect | Why it mattered |
|---|---|
| `LEN_PROBS` = 274 | The length coder is choice, choice2, a low and a mid tree **per position state** (16 x 8 each), and one shared high tree: **514**. At 274 the literal table overlapped the repeated-length coder. |
| `PosSlot` sized 64 | It spans `NUM_LEN_TO_POS_STATES x 64` = 256. At 64 every region after it shifted down and the literal table landed on 1654 instead of 1846. |
| `rc_byte` advanced past the input | On a short read it still incremented the cursor, so the caller's source position overshot the buffer. |
| No short-read handling | The loop kept consuming zeros. `input_exhausted` stops it and `finish()` reports `MCF_E_TRUNCATED`. |
| No dictionary overflow check | A match reaching before the ring was accepted rather than rejected. |
| Nothing copied out of the ring | LZMA decodes into its own dictionary, so output never reached the caller. |

**Round two - the range coder:**

| Defect | Effect |
|---|---|
| **`RC_TOP_VALUE` = `0xFF000000`** | The spec says `kTopValue = 1 << 24`. Normalising ~16x too rarely let `range` decay through zero partway through every stream. **It presents as "the decoder ran out of input", not as an arithmetic error**, which is why it survived six prior fixes. 0/335 -> 11/335. |

**Round three - the final match:**

| Defect | Effect |
|---|---|
| Final match rejected instead of clamped | liblzma emits a last match past `content_size` when the size is known rather than an end marker. 11/335 -> 132/335. |

**Round four - the output path.** Found by noticing that failures correlated with block
size: 65/65 failing at 256, 512 and 1024; only 5 at 4096; 3 at 65536. A decoder bug would
not care about chunking, so the fault was in the streaming path.

| Defect | Effect |
|---|---|
| **A match could overshoot `cap`** | The loop checked capacity only between symbols, so one long match wrote past the caller's buffer. A cut match now leaves its remainder in `pending` and continues on re-entry. |
| **Ring copy-out assumed two pieces** | One call can produce more bytes than the dictionary holds, wrapping the ring several times. Now loops. |
| **`dict_get` read unwritten memory** | A distance reaching before the start of output must read the window's pre-history, which the format defines as zero. Now returns 0 for `dist > produced` - which is also that rule, and makes the result independent of the caller's buffer. Fixed the 20,000-byte zero-run case. |
| **`input_exhausted` was never initialised** | An uninitialised field that reads as zero under `calloc`, so the decoder *appeared* correct under a zeroed harness and failed under a dirty one. `init` now clears the whole state object instead of assigning fields individually, so a field added later cannot be forgotten. The harness now poisons the workspace with `0xA5` before every vector. |

The uninitialised field is the most instructive: it passed every test, because the only
thing between it and discovery was a harness that happened to hand the decoder zeroed
memory. Poisoning the workspace is now permanent.

## What remains

**One bug, in the match/distance logic rather than the range coder.** The suite is 133/335 and
whole classes decode exactly: random data 9000/9000, a zero run 20000/20000, a repetitive case
16000/16000, and the `lc=0 lp=3 pb=4` sweep 3000/3000 at every block size.

**What is now verified correct, by measurement rather than by inspection:**

- The range decoder on every path. `rc_bit` normalises once per bit, and `rc_bit_direct` now
  normalises **inside** the loop, once per direct bit, as the reference decoder does.
  Normalising once at the end halved `range` up to 25 times without replenishing.
- The probability model. For the leading literals every `isMatch` bit is 0, so each entry
  must follow `p(n) = 2048 - 1024*(31/32)^n` exactly. Measured against that closed form
  there is no deviation.
- The first decoded symbol of vector 0 byte-for-byte.
- The probability table layout: `P_LITERAL` lands on 1846, `PosSlot` is 4 x 64 = 256 entries,
  the `SpecPos` region is 115 entries with the maximum touched index below `P_ALIGN`, and
  `LEN_PROBS` is 514 with position-state-major low and mid trees.

**Where it goes wrong.** Vector 0 (the firmware image, lc=3 lp=0 pb=2, 64 KB dictionary)
decodes correctly for 75 bytes and then emits a distance of roughly 48 million against a
65,536-byte dictionary, which the bounds check rejects. The `lp=3` sweep vector, whose best
distances run to about 3,000, decodes perfectly, so this is not general distance decoding.
Vector 0 is the case that needs the largest distances - its const table and string table sit
near the top of the window - so the fault is in the large-`pos_slot` branch of
`mcf_lzma_dist`, specifically the interaction between the reverse tree and the align tree.

**What would settle it.** Write a third decoder - a direct, slow, literal transcription of
RFC 8032's distance decoder with no optimisation and no shared code - and diff its
`pos_slot`, `direct`, reverse-tree and align-tree values against `mcf_lzma_dist` for vector 0
at output 75. Every previous attempt to localise this by inspection, and by consumption
measurement, was wrong. A second opinion with independent code is the only thing that has not
already been tried and found wanting.

## Two things that were wrong, recorded so they are not repeated

**The Python decoder in `host/lzma_vectors.py` is not an oracle.** It was written from the
same understanding as the C, so it can only confirm the two agree, never that either is
right. It produced `0xff` where liblzma produces `0x73`. Only liblzma counts.

**`lz_oracle.py` measures minimum input required, not bytes read.** A streaming range
decoder normalises whenever `range` drops below 2^24 and pulls in a byte whether or not the
current symbol needs it, so it reads ahead; liblzma does the same and it is not observable
through Python's API. Diffing a decoder's read position against those numbers shows
expected read-ahead, not a desync. That mistake produced a spurious 14-byte "divergence" at
output 75 and sent an entire round of work after a rep-distance bug that did not exist.

## Honest summary

Four rounds, **fifteen real defects fixed**, 0 to 133 of 335. Each round was confident the
next measurement would close it; two of those measurements were themselves wrong. The
consistent shape across this decoder and the Ed25519 attempt is that every local check
passes and the composition is wrong somewhere that reading cannot reach. That is an argument
about method, not about luck, and it is why the recommendation is unchanged: for a range
coder, take a reviewed implementation.

Nothing on this page is an open design question. The shipped LZMA codec is the vendored LZMA
SDK (`third_party/lzma-sdk`, wrapped by `src/mcf_lzma.c`); this page is the record of why the
hand-written decoder it replaced was abandoned.
