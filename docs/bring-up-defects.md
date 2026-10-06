# Defects found during bring-up

Recorded because they are the kind that survive to the field: each was found by a test, a
fuzz run, or a toolchain — not by reading the code — and every one of them would have shipped.

| Found by | Defect |
|---|---|
| Host round-trip | An Ed25519 signature is **64** bytes, not 32. The 32-byte figure is the *public key*. A 32-byte field shifted the payload and corrupted every field after it. |
| Randomised testing | A suffix-search `bsdiff` that assumed 16 verified bytes when it had proven 8. |
| Randomised testing | The BSDIFF43 seek positions the base for the **next** triple, not its own. |
| Compilation | `MCF_SESSION_DECLARE` cast the storage object rather than its address. |
| Compilation | The codec decoded the 4-byte length prefix as block data. |
| Compilation | The codec reported the *remaining* count where the caller expected *consumed*, so the source cursor jumped to the end marker. |
| Test suite | The host tool and the device disagreed on the LZ4 block size. |
| Test suite | The payload CRC was only verified for signed patches, leaving unsigned ones unchecked. |
| CI (macOS) | A test-local type named `dev_t` collided with the POSIX type of that name — invisible on Linux and Windows, fatal on AppleClang. |
| Test audit | MFP2 resume could checkpoint **once and then never again**. The feed filled its window, running dozens of records ahead of the engine; the checkpoint's four-entry record ring held only the newest four, so the engine's record was evicted and every later checkpoint was skipped as unresumable — silently, behind `RESUME_DEGRADED`. The suite resumed from the single first checkpoint and passed. |
| Test audit | A checkpoint taken when the engine's next byte sat exactly on a record boundary — it had consumed everything the feed produced — was rejected, because the ring lookup demanded *containment* in a record. On a diff-heavy patch that is every checkpoint after the first, so such runs were never resumable at all. |
| Test audit | The probe rejected any checkpoint with `d_off > new_size`. `d_off` counts **delta-stream** bytes, and the stream is longer than the image (every control triple adds 24 bytes), so on a many-triples patch every checkpoint was rejected — again silently. |
| Test audit | The probe rejected `out_off == new_size`. That is the final block boundary — all output programmed, only verify left — so a power cut there forced a full re-transfer of the whole image. |

The host/device LZ4 block-size disagreement, the unchecked payload CRC, and the macOS `dev_t`
collision are the argument for the fault-injection suite and the three-OS matrix: none was
visible from reading the code, and all would have shipped.

The four MFP2 resume entries above came from auditing the resume tests rather than the code:
each defect is a *silent* fallback to "start over", so every existing resume assertion still
passed while the feature was inoperative for real patch shapes. The lesson recorded with them is
that a resume test must assert the journal **advances** and that the run does not **degrade** —
resuming from one captured checkpoint proves only that one checkpoint was written.

One entry outlived bring-up. The BSDIFF43 seek ordering was recorded here while the engine still
disagreed with its own host tool — the log named the defect, but the engine was not corrected
until `v1.9.3`, which is why most real firmware diffs (deletions, reorders, non-contiguous base
reuse) could not be applied by the library that produced them. `docs/lzma-history.md` is the
equivalent record for the retired from-scratch LZMA decoder.
