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

The last three are the argument for the fault-injection suite and the three-OS matrix: none was
visible from reading the code, and all would have shipped.

One entry outlived bring-up. The BSDIFF43 seek ordering was recorded here while the engine still
disagreed with its own host tool — the log named the defect, but the engine was not corrected
until `v1.9.3`, which is why most real firmware diffs (deletions, reorders, non-contiguous base
reuse) could not be applied by the library that produced them. `docs/lzma-history.md` is the
equivalent record for the retired from-scratch LZMA decoder.
