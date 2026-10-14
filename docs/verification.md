# Verification

How Microfoam's claims are checked, and by what. The README states the headline figures;
this page holds the evidence behind them.

The check counts in the table below are not prose. `host/check_counts.py` runs each suite in a
build tree, reads the count that suite reports for itself, and fails if it disagrees — so a
documented number cannot silently stop being true. It runs in CI as the `documented_counts`
test.

Which suites that actually covers depends on the tree, and the script says so rather than
implying otherwise. The default configuration builds five of the nine: the four behind
`MCF_ENABLE_SODIUM`, `MCF_ENABLE_ED25519` and `MCF_ENABLE_LZMA` are opt-in, and between them they
hold 721 of the 1,072 documented checks. Those suites are reported as **not built** or **skipped**
and named in the summary, not folded into a pass. The `sodium` CI job is the one tree that builds
all nine at once, and it runs the script with `--require-all`, which turns a missing or skipped
suite into a failure — so the counts are verified in one place in full, rather than the union of
counts being verified nowhere. Locally, the same script with `--require-all` gives the same gate
once the optional modules are configured on.

## The suites

Warning-clean under `-Wall -Wextra -Wconversion -Wsign-conversion -Werror`, with the standard
configurations passing in both Debug and Release. The `host` job runs Debug on all three
platforms and adds one Release leg, so a configuration the documentation names is exercised by
CI rather than only by whoever happens to build it locally.

| Suite | Checks | What it proves |
|---|---|---|
| `microfoam_tests` | 137 checks | round trip, the `mcf_ctx_size()` cost query, resume, the BSDIFF43 seek ordering, small-image framing, fault injection, idempotent `finish()`/single commit, use-after-close refusal, and the magic-constant spellings |
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
| `v1_fuzz_smoke` | the MFP1 parser property oracle, portable build |
| `v2_fuzz_smoke` | the MFP2 parser property oracle, portable build |
| `cross_test`, `cross_test_raw`, `cross_test_lzma` | host-tool patches applied by the C library, byte-exact |
| `mfp2_host_to_session` | a PyNaCl signed+encrypted patch rejecting 14 tamper variants with zero flash mutations, each pinned to its exact status **and its exact failure site**; the MFP2 queries (`mcf_v2_session_total`, `mcf_v2_session_error_site`); an inner-engine failure keeping its site through the v2 wrapper; resume interrupted at many step counts, resuming byte-exact from every checkpoint (journal advances, no degrade; mid-DIFF captures included; a many-triples patch whose `d_off > new_size` and whose final checkpoint is at `out_off == new_size`) |
| `documented_counts` | this table against what the suites report |
| `version_check` | the seven hand-written release sites against each other, so a bumped `pyproject.toml` cannot ship beside a stale firmware header |
| `quickstart_config` | the README's quick-start pair is runnable, not just plausible |
| `size_gate` | `.text` within the committed ceiling and 0 B static RAM, per core; skips by name without `arm-none-eabi-gcc` |

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

Both the **MFP1 parser** and the **MFP2 parser** are surfaces that consume attacker-controlled bytes, so they are held to
a property contract rather than a list of cases. Coverage-guided fuzzing runs for each format:
- **MFP1**: a bounded 90-second run on every push (the `fuzz-v1` job)
- **MFP2**: a bounded 90-second run on every push (the `fuzz` job), and a scheduled ten-minute run against a
corpus cached across runs (the `Long fuzz` workflow), so coverage compounds instead of being
rediscovered each time.

**Fault injection** covers erase failure, program failure, *program succeeding but storing the
wrong bytes*, truncated payloads, flipped bits, wrong product, downgrade attempts, base-version
mismatch, over-budget workspace, unknown codec, future format version, wrong new-image CRC,
abort, and signed-without-verifier — each asserting a *specific* status code, and none may
return `MCF_OK`. The zero-flash-mutation claim is itself falsifiable.

Design and rationale: [architecture §18](architecture.md#18-test-strategy-and-ci).

## Which gate rejected the patch

A status code says *whether* a patch was refused. It does not say *which check* refused it, which
is the difference between a one-line diagnosis and an afternoon. MFP1 has always answered this with
`mcf_error_site()`; MFP2 did not, and its `mcf_v2_session_t.site` field was never written at all — so
every MFP2 failure reported site 0, "no site", regardless of cause. `mcf_v2_session_error_site()`
now returns it, and `mcf_v2_session_total()` joins it so progress can be read the same way MFP1's
`mcf_session_total()` works.

The tamper suite pins all 14 variants to their exact site, so the matrix documents itself:

| Tamper | Status | Site |
|---|---|---|
| inconsistent payload size, truncated payload | `MCF_E_FORMAT`, `MCF_E_TRUNCATED` | 35 `V2_PARSE` |
| corrupted AEAD tag, flipped ciphertext byte | `MCF_E_CORRUPT` | 39 `V2_PAYLOAD_CRC` |
| tampered key id, header field, signature byte | `MCF_E_SIGNATURE` | 40 `V2_SIGNATURE` |
| unknown key id | `MCF_E_AUTH` | 41 `V2_KEY` |
| wrong symmetric key, reordered records, wrong nonce, tampered AEAD tag or ciphertext, duplicated record | `MCF_E_AUTH` | 46 `V2_AEAD` |

Note that six different attacks on AEAD bind to the same site. That is the point: they fail for six
distinct reasons, but the site names the *stage*, and the stage is what an integrator needs.

> [!NOTE]
> **The ordering here is load-bearing.** `v2_fail()` closes the inner MFP1 session, and
> `mcf_session_close()` resets the inner site to `MCF_SITE_NONE`. A site read after that close
> would therefore report 0 for exactly the failures it exists to describe. `v2_fail_inner()`
> captures the inner site *before* closing and falls back to 48 `V2_INNER` only when the inner
> engine recorded none. `inner_site_case` in `mfp2_boundary_test` injects a flash program failure —
> an inner-engine fault with site 27 — and asserts 27 survives the wrapper. Moving that capture
> below the close fails the suite with `site 48, expected 27`.

## The version the build claims

The release version is written by hand into seven places: `CMakeLists.txt`, `pyproject.toml`,
`conanfile.py`, `host/microfoam.py`, the `MCF_VERSION_*` macros, the README spec table, and the
reconciliation note in `docs/architecture.md`. Nothing compared them. Bumping five and forgetting
two builds cleanly, passes every test, and ships a firmware header that contradicts the PyPI
metadata — a failure that is invisible until a user compares them.

`version_check` compares all seven and names the offenders. It fails on drift, on a site that has
stopped declaring a version, and on a file that disagrees with itself. CI adds the half a tarball
cannot run: with `--tag-check`, an exact git tag on HEAD must match the tree. The packaging job
separately asserts that the *installed* `microfoam --version` equals the tree version, which closes
the loop on the artifact rather than the source.

## Measured footprint

Measured with `arm-none-eabi-gcc` at `-Os`, every source compiled with the full strict warning
set and zero warnings. `.text` is gated against committed ceilings (`cmake/size_gate.cmake`,
driven by `host/size_gate.py`), and the gate fails if any static RAM appears at all.

The gate is a ctest — `ctest -R size_gate` — so it is part of the recipe the README gives, not
only a CI step. It needs the bare-metal ARM toolchain, which most machines do not have; where it
is absent the test **skips by name** (`SKIP_RETURN_CODE`) rather than being unregistered, so the
output distinguishes "the footprint was not checked here" from "the footprint was checked and
passed". CI runs it per core with the toolchain installed, where a skip cannot occur.

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

## Building the sodium configuration from a path containing spaces

The MSVC configurations build fine from any path, but a **gcc** tree configured under MSYS2
will not configure if the source path contains a space. CMake's compiler check splits the
argument list at the space and the compiler never sees its input:

```
-- The C compiler identification is unknown
Check for working C compiler: C:/msys64/ucrt64/bin/gcc.exe - broken
```

This is a property of the MSYS2 toolchain's argument handling, not of this project: the same
compiler, flags and sources configure cleanly from a space-free path, and the `deprecation
probe` in `cmake/deprecation_probe.cmake` fails the same way. It is not specific to
`build-sodium`, and it is not caused by anything in the tree.

The workaround is to build the sodium tree from a path with no spaces. Copying the source is
enough — the build directories do not need to come along:

```powershell
$dst = "$env:TEMP\microfoam-build"
if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
New-Item -ItemType Directory $dst | Out-Null
foreach ($d in @('src','include','tests','cmake','third_party','host','docs','.github')) {
    Copy-Item -Recurse -Force ".\$d" "$dst\$d"
}
foreach ($f in @('CMakeLists.txt','README.md','conanfile.py','pyproject.toml','LICENSE')) {
    Copy-Item -Force ".\$f" "$dst\$f"
}

# MSYS2 needs its own bin on PATH, or gcc fails before it is ever invoked.
$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"

cmake -S $dst -B "$dst\b" -G Ninja -DCMAKE_BUILD_TYPE=Release -DMCF_ENABLE_SODIUM=ON `
      -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe `
      -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe `
      -DSODIUM_INCLUDE_DIR=C:/msys64/ucrt64/include `
      -DSODIUM_LIBRARY=C:/msys64/ucrt64/lib/libsodium.dll.a
cmake --build "$dst\b"
ctest --test-dir "$dst\b" --output-on-failure
```

That is the configuration behind the **15/15** local result: all nine suites, `gcc` under
`-Wall -Wextra -Wconversion -Wsign-conversion -Werror`, including the MFP2 producer-to-session
integration and the `size_gate`. Run `ctest --test-dir "$dst\b" -R documented_counts` after
changing any check count in this document — the gate reads the counts back out of the built
binaries and fails if the table above has drifted.

Worth knowing when interpreting a failure: gcc catches `-Wconversion` and `-Wsign-conversion`
violations that MSVC accepts silently. A tree that is clean under MSVC can still fail here, and
that is the strict set doing its job, not a regression.