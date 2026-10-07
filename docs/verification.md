# Verification

How Microfoam's claims are checked, and by what. The README states the headline figures;
this page holds the evidence behind them.

The check counts in the table below are not prose. `host/check_counts.py` runs each suite in a
build tree, reads the count that suite reports for itself, and fails if it disagrees — so a
documented number cannot silently stop being true. It runs in CI as the `documented_counts`
test.

## The suites

Warning-clean under `-Wall -Wextra -Wconversion -Wsign-conversion -Werror`, with the standard
configurations passing in both Debug and Release.

| Suite | Checks | What it proves |
|---|---|---|
| `microfoam_tests` | 110 checks | round trip, the `mcf_ctx_size()` cost query, resume, the BSDIFF43 seek ordering, small-image framing, fault injection |
| `custom_codec_test` | 46 checks | caller-owned codec descriptors, per-session table isolation, failure propagation at init, decode and finish |
| `hal_concurrency_test` | 27 checks | two sessions driven interleaved through a whole decode |
| `v2_format_test` | 45 checks | MFP2 header/TLV/record-framing rules, plus a deterministic mutation/property loop |
| `host_selftest` | 119 checks | host round-trips, the measured LZ4-vs-LZMA ratio, format-layout agreement, signing, the MFP2 KAT, host-side tamper cases |
| `sodium_rfc_test` | 17 checks | published Ed25519 / Ed25519ph / XChaCha20-Poly1305 vectors and adapter tamper cases *(with `MCF_ENABLE_SODIUM=ON`)* |
| `ed25519_test` | 354 checks | SHA-512 digests, RFC 8032 §7.1/§7.3 vectors, a negative matrix, the `S + L` case, domain separation, and a **differential** against libsodium *(with `MCF_ENABLE_ED25519=ON`)* |
| `lzma_conformance_test` | 335 checks | 67 liblzma vectors at five block sizes each *(with `MCF_ENABLE_LZMA=ON`)* |
| `lzma_policy_test` | 15 checks | dictionary and `lc+lp` policy rejections with their exact status and stage *(with `MCF_ENABLE_LZMA=ON`)* |

Also in the ctest matrix:

| Test | What it adds |
|---|---|
| `v2_fuzz_smoke` | the parser property oracle, portable build |
| `cross_test`, `cross_test_raw`, `cross_test_lzma` | host-tool patches applied by the C library, byte-exact |
| `mfp2_host_to_session` | a PyNaCl signed+encrypted patch rejecting 14 tamper variants with zero flash mutations, each pinned to its exact status; resume interrupted at many step counts, resuming byte-exact from every checkpoint (journal advances, no degrade; mid-DIFF captures included; a many-triples patch whose `d_off > new_size` and whose final checkpoint is at `out_off == new_size`) |
| `documented_counts` | this table against what the suites report |
| `quickstart_config` | the README's quick-start pair is runnable, not just plausible |

One check is not a ctest because it does not need a built tree: `cmake/deprecation_probe.cmake`
runs at **configure** time on every platform and toolchain, compiling
`tests/deprecation_probe.c` twice — once asserting that all three `MCF_DEPRECATED` messages reach the
compiler's output verbatim, and once asserting `MCF_NO_DEPRECATED` removes them. The message is
the only part of the deprecation contract nothing else can observe, so it is the part that is
asserted rather than remembered.

> [!IMPORTANT]
> **The cross test is the one that matters most.** A library verified only against its own
> encoder proves nothing about the format. Two independently written implementations agreeing
> on a real 35 KB firmware pair is evidence.

## The parser and the faults

The **MFP2 parser** is the one surface that consumes attacker-controlled bytes, so it is held to
a property contract rather than a list of cases. Coverage-guided fuzzing runs in two places: a
bounded 90-second run on every push (the `fuzz` job), and a scheduled ten-minute run against a
corpus cached across runs (the `Long fuzz` workflow), so coverage compounds instead of being
rediscovered each time.

**Fault injection** covers erase failure, program failure, *program succeeding but storing the
wrong bytes*, truncated payloads, flipped bits, wrong product, downgrade attempts, base-version
mismatch, over-budget workspace, unknown codec, future format version, wrong new-image CRC,
abort, and signed-without-verifier — each asserting a *specific* status code, and none may
return `MCF_OK`. The zero-flash-mutation claim is itself falsifiable.

Design and rationale: [architecture §18](architecture.md#18-test-strategy-and-ci).

## Measured footprint

Measured with `arm-none-eabi-gcc` at `-Os`, every source compiled with the full strict warning
set and zero warnings. CI gates `.text` against committed ceilings
(`cmake/size_gate.cmake`) and fails if any static RAM appears at all.

| Target | Code (`.text`) | Static RAM |
|---|---|---|
| Cortex-M0 | **12,358 B** | 0 B |
| Cortex-M3 | 11,420 B | 0 B |
| Cortex-M4 | 11,426 B | 0 B |
| Cortex-M7 | 11,422 B | 0 B |

RAM, measured on Cortex-M0: **340 B** session + **528 B** workspace at a 256 B block =
**868 B total**, no heap. The workspace figures are what `mcf_ctx_size()` returns, and the
self-test asserts that query against the allocator's actual request. Full profile tables,
including the LZMA case, are in
[architecture §10.4](architecture.md#104-measured-profiles).

The ceilings in `cmake/size_baseline.txt` sit a few percent above the figures above. That is
deliberate: the CI toolchain is whatever the runner provides, so its minor version drifts, and a
minor version moves code size by a few bytes. An exact figure would fail on that drift while
telling you nothing — a real regression is hundreds of bytes to kilobytes, an order of magnitude
above the allowance.

## Portability

A CI job also compiles the same core and opt-in source set with upstream clang
`--target=arm-none-eabi` on all four cores under the same strict warning set. This is a free,
redistributable **armclang frontend and diagnostic proxy** — the same frontend and the same
diagnostic engine Arm's tool is built on, which is why `-Wconversion` and `-Wsign-conversion`
being clean under both is worth having. It is not armclang and does not claim to be. No size
comparison is gated there: a clang ceiling would baseline a compiler nobody ships. Licensed
armclang and IAR builds remain unverified.

See [.github/workflows/ci.yml](../.github/workflows/ci.yml) for the matrix itself.