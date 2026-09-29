# Microfoam — Software Architecture

> **Tiny bubbles. Tiny footprint. Full-strength upgrade.**

| Field | Value |
|---|---|
| **Project name** | **Microfoam** |
| **Tagline** | *Tiny bubbles. Tiny footprint. Full-strength upgrade.* |
| **Description** | A firmware delta update library for resource-constrained microcontrollers |
| **C symbol prefix** | `mcf_` / `MCF_` |
| **Host tool** | `microfoam` |
| **Package name** | `microfoam` |
| **Document type** | Software Architecture Description |
| **Version** | 1.0 |
| **Status** | Draft for review |
| **License** | MIT (see §20) |
| **Target audience** | Library maintainers, firmware integrators, security reviewers |

### On the name

Microfoam is the thin layer of bubbles in a latte — roughly one percent of the volume and
all of the texture. That is the design target of this library: the smallest possible resident
cost, carrying the whole capability. The name also sets the correct expectation for a reader
who has just been told this replaces a library that needed 10–20 KB of heap: the footprint
is the point, and it is stated in the tagline so nobody has to read §10 to learn it.

The prefix `mcf_` is chosen for the same reason — four characters, no collision with `bs_`
in an integrator's existing tree, and consistent with the word's own length.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Context and Problem Statement](#2-context-and-problem-statement)
3. [Findings: The Evidence Base](#3-findings-the-evidence-base)
4. [Architecture Goals and Non-Goals](#4-architecture-goals-and-non-goals)
5. [Design Principles](#5-design-principles)
6. [System Context and Deployment Model](#6-system-context-and-deployment-model)
7. [Layered Architecture](#7-layered-architecture)
8. [Data Flow](#8-data-flow)
9. [Public API Design](#9-public-api-design)
10. [Memory Model and Budget](#10-memory-model-and-budget)
11. [Concurrency and Real-Time Model](#11-concurrency-and-real-time-model)
12. [Flash Write Contract](#12-flash-write-contract)
13. [On-Flash Format Specification (v2)](#13-on-flash-format-specification-v2)
14. [Security Model](#14-security-model)
15. [Power-Fail Resilience and Recovery](#15-power-fail-resilience-and-recovery)
16. [Build System and Toolchain Support](#16-build-system-and-toolchain-support)
17. [Host Tooling](#17-host-tooling)
18. [Test Strategy and CI](#18-test-strategy-and-ci)
19. [Versioning and Compatibility](#19-versioning-and-compatibility)
20. [License](#20-license)
21. [Delivery Roadmap](#21-delivery-roadmap)
22. [Risk Register](#22-risk-register)
23. [Open Questions](#23-open-questions)
24. [Appendices](#24-appendices)

---

## 1. Executive Summary

This document specifies the target software architecture for **Microfoam** — a
production-grade firmware delta update library for resource-constrained microcontrollers. It
is a **forward-looking specification**, not a description of existing code.

All public symbols use the `mcf_` prefix; the host tool is invoked as `microfoam`. Section
13 defines the on-flash patch format, which carries the `'MFP1'` magic.

The architecture is derived from a structured assessment of a widely-deployed reference
implementation of the same problem domain (binary delta patching with LZMA compression for
MCU OTA). That assessment is recorded in **§3** and serves as the evidence base: every
significant design decision in this document exists to correct a specific, identified defect
class from the reference work. The reference implementation is not named here, and no
reference source code is reproduced.

**The core problem.** A device in the field holds firmware version *N*. The manufacturer
releases version *N+1*. Transmitting the full image over a constrained link (BLE, LoRa,
infrared, serial at 9600 baud) is slow, power-hungry, and expensive. A delta patch
transmitting only the *difference* is typically 5–15% of the original size. The device must
reconstruct the full image locally and atomically swap to it. This library performs the
device-side reconstruction.

**The central architectural finding** from the assessment is not any individual bug — it is
that **the memory cost of the library is an implicit, undocumented, unenforced contract
encoded in a single byte inside a binary produced by a closed-source tool.** Everything else
in §3 is a consequence of the library having no formal, declared, self-describing interface:
no error model, no state ownership, no resource contract, no integrity model.

**The four architectural commitments** of this design are:

1. **Total error transparency.** Every failure is detected, propagated, and reported with a
   specific code. A function never reports success on failure. (§9.2)
2. **An explicit, self-describing memory contract.** RAM cost is computable at build time,
   and the library refuses — rather than crashes — when a patch demands more memory than the
   device has. (§10)
3. **Declared resource ownership.** No mutable global state. All session state lives in a
   caller-owned context object, making the library reentrant and unit-testable. (§11)
4. **Authenticity as a first-class feature.** Patches are signed and versioned. An
   unauthenticated firmware update is an arbitrary code execution primitive. (§14)

**Projected footprint** (see §10 for derivation):

| Target profile | RAM | ROM | Notes |
|---|---|---|---|
| Constrained (Cortex-M0, LZ4 codec) | **≤ 4 KB** | ~3 KB | Primary design target |
| Standard (Cortex-M3/M4, LZ4 codec) | ≤ 6 KB | ~4 KB | Recommended default |
| Max ratio (Cortex-M3/M4, LZMA codec) | ≤ 34 KB | ~9 KB | Opt-in, higher download savings |

The reference implementation documents a requirement of "≥ 10 KB RAM" and an unverified
"~5 KB ROM". This design targets an order of magnitude less RAM in its primary
configuration by making the compression codec pluggable and shipping a low-footprint codec
as the default (§7.3).

---

## 2. Context and Problem Statement

### 2.1 Domain

Firmware delta update — also called incremental or differential upgrade — for
resource-constrained microcontrollers. The scope is the **device-side patch application**
only. Patch *generation* is a host-side concern (§17).

### 2.2 The two halves of the problem

```
  HOST (build server)                          DEVICE (field unit)
  ───────────────────                          ──────────────────
  old.bin  ──┐                                  old image (in flash)
             ├─► bsdiff ──► LZMA ──► patch.bin    │
  new.bin  ──┘        + container header         ├─► apply patch
                                                │     │
                                                ├─► verify CRC
                                                ├─► atomically swap
                                                └─► reboot into new image
```

The left half is understood, stable, and solved by well-known open-source tools. The right
half is where embedded projects consistently get it wrong, and is what this library addresses.

### 2.3 Constraints that drive the architecture

| Constraint | Consequence for the design |
|---|---|
| **Tight RAM (8–64 KB typical)** | No whole-file buffering. Streaming, fixed-window processing. Pluggable codecs (§7.3). Computable budget (§10). |
| **No filesystem** | Source image and patch live at absolute addresses in memory-mapped or SPI-attached flash. The "file" abstraction is an address + length. |
| **NOR flash semantics** | Program can only clear bits (1→0). Erase is block-granular. Erase+program+buffering must be modelled explicitly (§12). This is a frequent source of silent corruption when abstracted away. |
| **RTOS present, watchdog armed** | Long blocking calls are unacceptable. Cooperative stepping and progress callbacks (§9.5, §9.6). No internal OS dependency. |
| **Unreliable power** | Any interruption mid-restore must be recoverable or safely discardable (§15). |
| **Slow, power-hungry link** | Download volume is the primary cost driver. Compresses the value of a slightly larger decoder. |
| **Long field lifetimes** | The deployed fleet cannot be recalled. A latent defect is a permanent liability. Errors must be diagnosable *in the field*, not only in the lab. |
| **Security exposure** | The update channel is a remote code execution surface. Requires signature verification and anti-rollback (§14). |

### 2.4 Stakeholders

| Stakeholder | Need |
|---|---|
| Firmware integrator | Minimal, hard-to-misuse porting surface; clear RAM cost; predictable failure |
| Library maintainer | Testable, portable, no global state, reproducible build |
| Security reviewer | Authenticity, integrity, anti-rollback, auditable format |
| Release engineer | Reproducible patches; version traceability |
| Operations / support | Field-diagnosable failures; recovery from interrupted updates |

---

## 3. Findings: The Evidence Base

This section records the assessment that motivates the architecture. It is included because a
design that is not traceable to evidence is a design that cannot be reviewed.

Throughout, "the reference implementation" denotes a widely-used open-source device-side
bspatch library for MCUs implementing the BSDIFF43 delta format over an LZMA stream.

### 3.1 Real bugs

Defects that produce incorrect behaviour, crashes, or resource corruption. Severity:
**C**ritical (silent data corruption or hard fault), **H**igh (failure reported as success),
**M**edium (resource leak or degraded behaviour), **L**ow (hygiene).

| # | Sev | Location | Defect | Impact |
|---|---|---|---|---|
| B-01 | **C** | LZMA layer | Decoder allocation return value is discarded. On failure the decoder proceeds with null internal buffers. | **Under-provisioned heap causes a hard fault in the field.** This is the single most likely real-world failure mode. |
| B-02 | **C** | Delta engine | Flash write callback failure is detected, logged to a disabled macro, and then success is returned. | Failing flash write yields a full-length, silently corrupt firmware image. |
| B-03 | **C** | Public API | The top-level entry point discards the engine's return code and unconditionally returns the *expected* output size. Every internal error path returns the same value as success. | **The documented integration check ("did I write the expected number of bytes?") can never fail.** A completely failed restore is indistinguishable from a successful one. |
| B-04 | **H** | Public API | Error value `0` is overloaded: it means both "success, zero bytes" and "failed to initialize". | Callers cannot distinguish outcomes. |
| B-05 | **H** | LZMA layer | Decompressor error codes are discarded; partial output is returned as success. | Corrupt or truncated patches are accepted as a shorter valid stream. |
| B-06 | **H** | Logging | The diagnostic macro expands to `printf("\r\n"format, ...)` where `format` is a literal token, not the variadic parameter. | **Debug builds do not compile.** All error instrumentation in the library is dead code. |
| B-07 | **M** | Delta engine | Allocated buffers are not released on the eight internal error-return paths. | Heap fragmentation; a failed update attempt permanently degrades the device. |
| B-08 | **M** | Public API | Allocated buffers and the file handle are not released on the early error paths of the entry point. | As B-07. |
| B-09 | **M** | LZMA layer | A failed initialisation is reported but execution continues into the decoder. | Proceeds to dereference an uninitialised decoder. |
| B-10 | **M** | File abstraction | Read silently truncates on overrun and returns a short count indistinguishable from success. | Truncated reads propagate as valid data. |
| B-11 | **M** | File abstraction | Read-position setter performs no range validation; a subsequent remaining-bytes computation underflows unsigned. | Reads outside the intended region. |
| B-12 | **M** | LZMA layer | Static decoder state is guarded by an early return that silently reuses the previous session's state. | Cross-session contamination. |
| B-13 | **L** | Public API | A function parameter's address is taken and dereferenced through an incompatible pointer type. | Undefined behaviour; fragile under aggressive optimisation. |
| B-14 | **L** | Build | The package manifest calls `sys.exit()` with no `import sys`; the assembler is passed `-x c`; a source file is referenced with the wrong filename case for a case-sensitive filesystem. | Packaging and multi-platform builds fail. |
| B-15 | **L** | LZMA layer | Unused debug instrumentation calls an undefined logging function. | Fails to compile when the debug option is enabled. |

### 3.2 Design gaps

Absent capabilities — things the architecture does not have at all.

| # | Gap | Consequence |
|---|---|---|
| G-01 | **No integrity authentication.** A 32-bit CRC is the only check. | An attacker who controls the update channel can construct a patch that passes CRC and executes arbitrary code. CRC is not a security primitive. |
| G-02 | **No anti-rollback.** No version counter, no minimum-version enforcement. | An attacker can replay a known-good older image to reinstate a patched vulnerability. |
| G-03 | **No product binding.** Header fields for target architecture, OS, image type, and product name are defined but never validated. | A patch built for one product can be applied to another. |
| G-04 | **No format versioning.** No magic-number check, no version field, no header-length field. | No way to evolve the format. Any change is a breaking change. |
| G-05 | **Inconsistent endianness encoding.** Some header fields are big-endian, adjacent fields are little-endian, and no marker distinguishes them. | Cross-tool and cross-version interoperability is fragile and undocumented. |
| G-06 | **The flash contract conflates erase and program.** The callback is documented as requiring self-erasure, but no erase primitive, alignment contract, or cross-block buffering is provided. | The obvious integration — wiring the callback to a flash page-program primitive — produces silent corruption. |
| G-07 | **No progress, abort, or timeout mechanism.** The restore is one uninterruptible call. | The documented integration must disable the task watchdog for the duration. Abort is impossible. Low-power designs cannot yield. |
| G-08 | **The old image must be directly addressable** as a raw pointer. | Excludes external flash, filesystem resources, and decrypted-at-runtime images. This limitation is raised in the reference project's issue tracker and remains unanswered. |
| G-09 | **No resumability or power-fail model.** | A power loss during restore leaves the device in an undefined state. |
| G-10 | **No test suite, no CI, no reference vectors.** | A security-critical code path ships with zero automated verification. |
| G-11 | **No publishable host tool.** The tool that defines the wire format is a closed binary distributed via file-sharing. | The format is unauditable and unreproducible. No third party can generate a valid patch. No one but the original author can maintain the system. |
| G-12 | **No build-time resource query.** RAM cost cannot be determined without trial and error. | The dominant support burden. |

### 3.3 Weaknesses

Structural qualities that are not bugs but degrade the result.

| # | Weakness | Detail |
|---|---|---|
| W-01 | **The memory contract is implicit and unenforced** | The decoder's working dictionary size is dictated by a field inside the patch. The device never reads it, never validates it, and never reports it. Combined with B-01, a patch compressed with any non-matching tool setting causes a hard fault rather than an error. **This single coupling explains essentially all reported integration failures.** |
| W-02 | **The documented memory figure is not reproducible from the code** | The stated requirement ("≥ 10 KB RAM") is inconsistent with the decoder's own probability table, which occupies ~15.6 KB under default algorithm parameters. The stated figure is only achievable under a specific, unpublished encoder configuration. |
| W-03 | **No global-state discipline** | Session state lives in file-scope static variables. The library is not reentrant. Concurrency safety is an undocumented obligation pushed entirely onto every integrator. |
| W-04 | **The default codec is oversized for the target** | The default choice imposes a hard ~15.6 KB RAM floor for probability tables, independent of buffer tuning. This single decision sets the library's minimum viable target at a 32 KB-RAM Cortex-M3. |
| W-05 | **Byte-at-a-time hot loop** | The read path branches per byte, in the most frequently executed code in the library. |
| W-06 | **64-bit arithmetic throughout** | Extensive use of 64-bit types where the values are already bounded to 32 bits by existing sanity checks. Material code-size penalty on 8/16-bit cores and Cortex-M0. |
| W-07 | **Excessive platform dependencies** | The public header includes standard I/O. The build compiles a compression *encoder* and a file-I/O layer that a device never uses. |
| W-08 | **Global namespace pollution** | Core routines are exported at global scope with names that collide with common firmware libraries, creating link failures and subtle symbol interposition. |
| W-09 | **Build system is not portable** | Hardcoded processor selection, recursive source globbing, and long conditional toolchain chains embedded in the build script rather than expressed as toolchain files. |
| W-10 | **Unstructured, undocumented container format** | The header struct is a fixed-size aggregate with no explicit packing or size assertions, so its on-flash layout is compiler-dependent and unguaranteed. |
| W-11 | **Maintenance is a single point of failure** | The wire format is defined by a binary artifact, the code by one author, with an unanswered issue backlog. |

### 3.4 What the reference implementation gets right

A fair assessment records the strengths, and these are genuinely good decisions that this
architecture **preserves**:

- **The streaming pull model.** The decompressor is a source the patcher pulls from, never
  a full in-memory image. This is the correct fundamental design for a bounded-memory target.
- **The small fixed work window.** Processing in 1 KB blocks keeps the working set
  independent of image size.
- **A minimal porting surface.** Three callbacks — allocate, free, flash-write — is a
  genuinely good abstraction, and the refactor from macros to a registration interface was a
  real improvement.
- **A clean stream adapter.** Separating the delta engine from its I/O via a struct of
  function pointers is a sound design, even though the current instance is incomplete.
- **Producible results.** The approach is proven in deployed volume. The reconstruction
  algorithm is correct; what is missing is everything around it.

**Design implication.** The algorithm core is sound and is retained. The architecture
rebuilds the contract surface around it.

### 3.5 Severity summary

| Class | Count | Characteristic |
|---|---|---|
| Real bugs — Critical | 3 | Silent corruption or hard fault, not detectable by the caller |
| Real bugs — High | 3 | Failure indistinguishable from success |
| Real bugs — Medium | 6 | Resource corruption, out-of-bounds access |
| Real bugs — Low | 3 | Build and hygiene |
| Design gaps | 12 | Absent capability |
| Weaknesses | 11 | Structural quality |

The distribution — three silent-corruption defects and four failure-reporting defects
(B-01, B-02, B-03, B-05) — is itself the finding. **The reference implementation fails in the
direction of appearing to succeed.** Every one of these is a field failure that no lab test
would catch without deliberately injecting a fault.

---

## 4. Architecture Goals and Non-Goals

### 4.1 Goals

| # | Goal | Success criterion |
|---|---|---|
| **G1** | Total error transparency | Every failure path returns a specific negative code. A test that injects a fault at each allocation, read, decode, and write step observes the correct code in 100% of cases. |
| **G2** | Explicit memory contract | `mcf_ctx_size()` returns the exact RAM requirement for a given configuration. The library returns `MCF_E_DICT_TOO_LARGE` rather than failing to allocate. |
| **G3** | Minimal porting surface | Five callbacks. No macros, no source edits, no header modification. |
| **G4** | Reentrancy | No mutable global state. Two independent sessions with distinct contexts operate concurrently without interference. Verified by test. |
| **G5** | Authenticated updates | A patch without a valid signature over a header with an acceptable version counter is rejected. |
| **G6** | Constrained-target support | Primary configuration fits in ≤ 4 KB RAM on a Cortex-M0. |
| **G7** | Interruptibility | The restore is a resumable state machine. The caller may abort, yield, or power down between steps. |
| **G8** | Correct flash semantics | Erase/program/buffering are handled by the library against an explicit, documented device contract. |
| **G9** | Auditability | Open format specification, published host tool, deterministic reproducible patches. |
| **G10** | Build portability | Builds warning-clean under the verified GCC/ARM GCC paths; armclang and IAR remain portability targets pending licensed toolchain verification. |

### 4.2 Non-Goals

| # | Non-goal | Rationale |
|---|---|---|
| N1 | **Patch generation on device** | Never required; belongs on the build host. |
| N2 | **Bootloader / A-B slot management** | Firmware-layout and swap policy is product-specific. The library exposes a completion hook and leaves swap policy to the integrator (§15.3). |
| N3 | **Transport** | The library consumes a patch already resident in memory. BLE/LoRa/UART/USB transport is out of scope. |
| N4 | **Encrypted patches in v1** | v1 remains unencrypted. Authenticated encryption is specified as a separate v2 design in `docs/format-v2-design.md`; it is not implemented in the shipped format. |
| N5 | **Optimal patch ratio** | Ratio is bounded by the host tool's search effort. The library prioritises device cost. The host tool may try multiple codecs and select the smaller result. |
| N6 | **RTOS integration** | No scheduler dependency. Cooperative stepping (§9.6) is sufficient and portable. |

---

## 5. Design Principles

Each principle is a direct response to a finding in §3.

| # | Principle | Responds to |
|---|---|---|
| **P1** | **Fail loudly, fail specifically.** No silent degradation, no swallowed error codes, no overloading of return values. | B-01, B-02, B-03, B-05, G-12 |
| **P2** | **The contract is the API.** If a resource is required, its cost is computable and its exhaustion is a returnable error, never a fault. | W-01, W-02, B-01 |
| **P3** | **State is owned by the caller, never by the library.** | W-03, B-12 |
| **P4** | **The library does not lie about hardware.** If a flash write failed, say so. If a file is short, say so. Never return a plausible value. | B-02, B-10 |
| **P5** | **Boundaries are typed and validated at runtime, once.** Parse the container, validate every field, then operate on trusted values. | B-11, G-03, G-04 |
| **P6** | **Authenticity is not optional.** An update path without signatures is an unfinished design. | G-01, G-02 |
| **P7** | **Long operations are steppable.** Anything that can take seconds is a state machine. | G-07, G-09 |
| **P8** | **The smallest adequate codec is the default.** Compression ratio is a host-side cost; RAM is a device-side cost. | W-04, W-01 |
| **P9** | **The device contract is documented, not inferred.** Buffer sizes, alignment, endianness, and packing are specified and asserted. | G-05, W-10, B-13 |
| **P10** | **Everything is verifiable in CI.** A generated fixture, a reference implementation cross-check, and a size regression gate. | G-10, G-11 |

---

## 6. System Context and Deployment Model

### 6.1 Deployment

```
┌─────────────────────────────── Device ────────────────────────────────┐
│                                                                       │
│   Transport          Update        Application      Bootloader         │
│   (BLE/LoRa/UART) ──► Manager ──►  (RTOS task)     (A/B select)     │
│      out of scope         │            │                  ▲            │
│                           │            │                  │            │
│                           ▼            ▼                  │            │
│                    ┌──────────────────────────────────┐   │            │
│                    │      DELTA UPDATE LIBRARY       │   │            │
│                    │                                  │   │            │
│                    │  session → engine → codec        │   │            │
│                    └────────────────┬─────────────────┘   │            │
│                                     │ callback interface     │            │
│                                     ▼                        │            │
│                              HAL: flash / ram               │            │
│                                                                       │
│   [Slot A: running]      [Slot B: under construction]  [Patch staging] │
└───────────────────────────────────────────────────────────────────────┘
```

### 6.2 Integration contract

The integrator provides an implementation of the **Hardware Abstraction Layer** (§12) and a
session context allocated from a pool or static storage. The library provides everything
else. **No source modification is required to integrate** — this is preserved from the
reference implementation and is a genuinely good property.

---

## 7. Layered Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  L5   PUBLIC API          mcf_session_*                         │  Application-facing
│       error model, lifecycle, query, step                      │
├─────────────────────────────────────────────────────────────────┤
│  L4   SESSION             state machine, progress, abort,      │  Orchestration
│                           resume, policy                       │
├─────────────────────────────────────────────────────────────────┤
│  L3   DELTA ENGINE        bsdiff43 control-loop, block apply   │  Algorithm
│                           (algorithm-neutral, codec-agnostic)  │
├─────────────────────────────────────────────────────────────────┤
│  L2   CONTAINER           header parse/validate, integrity,    │  Format
│                           signature, anti-rollback              │
├─────────────────────────────────────────────────────────────────┤
│  L1   CODEC (pluggable)   LZ4 (default) │ LZMA (opt-in) │ …   │  Compression
├─────────────────────────────────────────────────────────────────┤
│  L0   HAL                 flash erase/write/read, alloc, log   │  Platform
└─────────────────────────────────────────────────────────────────┘
                          ▲ mcf_ctx_t owns all mutable state ──┘
```

Dependency rule: **strictly downward.** A layer may call only layers below it. The codec
layer knows nothing about the delta format; the delta engine knows nothing about compression;
the session layer owns all policy.

### 7.1 L0 — Hardware Abstraction Layer

The only platform-dependent surface. Five callbacks (§12). Everything above is portable C99
with no standard-library dependency beyond `<string.h>` and `<stdint.h>`.

### 7.2 L3 — Delta Engine

Retains the BSDIFF43 control-triple algorithm, which is proven and appropriate. The engine is
**codec-agnostic**: it consumes a byte source and a byte sink and knows nothing about how
they are backed.

The engine is a pure transformation with two injected functions and an explicit context. It
performs no allocation, no I/O, and holds no static state.

```c
typedef struct {
    /* Injected source: raw delta stream (post-codec) */
    int  (*read)(void *u, uint32_t off, uint8_t *p, uint32_t len);
    /* Injected sink: reconstructed bytes, sequential */
    int  (*write)(void *u, const uint8_t *p, uint32_t len);
    /* Injected base image access: arbitrary backing store */
    int  (*old_read)(void *u, uint32_t off, uint8_t *p, uint32_t len);
    void *u;
} mcf_io_t;
```

The `old_read` callback is the direct architectural answer to **G-08**. A raw pointer is
retained as a zero-cost special case, resolved at session configuration.

**All sanity checks the engine performs** are retained and strengthened:

- Control triple fields bounded to `[0, INT32_MAX]`; the seek delta is additionally
  range-checked against the base image extent to prevent pointer arithmetic overflow.
- The base-image read is bounds-checked per byte before use, so a malformed seek degrades to
  a defined "zero-fill outside the base image" behaviour rather than an out-of-bounds access.
- Every 64-bit intermediate is eliminated; the control fields are bounded to 32 bits by
  construction, so the engine is 32-bit-clean. (**P9**, addressing **W-06**)

### 7.3 L1 — Pluggable Codec

Codec descriptors are caller-owned and session-scoped through `mcf_config_t.codecs` and
`codec_count`; there is no mutable process-global registration table. Built-in LZ4 is always
available, while custom codec IDs must use the reserved `MCF_CODEC_CUSTOM_MIN` range and be
provided explicitly by each session.

The single highest-leverage structural decision (**P8**, addressing **W-04**).

```c
typedef struct mcf_codec mcf_codec;

typedef struct {
    const char *name;
    int  (*init)(mcf_codec *c, const uint8_t *props, uint32_t props_len, void *heap);
    int  (*decode)(mcf_codec *c, uint8_t *out, uint32_t *out_len,
                   const uint8_t *in, uint32_t *in_len);
    int  (*finish)(mcf_codec *c);
    void (*destroy)(mcf_codec *c);
    uint32_t (*required_workspace)(const uint8_t *props, uint32_t props_len);
} mcf_codec_ops_t;
```

Two codecs ship:

| Codec | Decoder state | Workspace | RAM | Ratio vs LZMA | Role |
|---|---|---|---|---|---|
| **LZ4** | ~256 B | ring buffer, configurable | **~1.5 KB @ 1 KB ring** | −5% to −15% on binary diffs | **Default** |
| **LZMA** | ~16 KB probs (parameter-dependent) | dictionary, configurable | ~20–34 KB | baseline | Opt-in, max ratio saving |

**The architectural consequence.** The reference implementation's ~15.6 KB probability
table is an unconditional RAM floor imposed by its default codec — no amount of buffer
tuning removes it, and it is why the library cannot target a Cortex-M0. Making the codec
pluggable and defaulting to a low-footprint codec removes that floor and moves the primary
target from "Cortex-M3 with a 20 KB heap" to "Cortex-M0 with 4 KB", which is most of the
addressable market for this class of product.

**Ratio mitigation.** The host tool compresses with both codecs and emits whichever patch is
smaller, so the device pays for whichever it was built for while the *manufacturer* always
gets the best available result. A device that can afford LZMA and a device that cannot both
benefit from the same release.

### 7.4 L2 — Container

Parses, validates, and integrity-checks the patch header, then exposes a validated view to
the layers above. It performs **no** patch application. Its contract is: *after `mcf_hdr_open`
returns `MCF_OK`, every field in the view is in range, consistent, and authenticated.*

This is principle **P5** — one validation boundary, so no downstream layer re-validates.

### 7.5 L4 — Session

The state machine (§9.6), policy, progress reporting, resume, and resource ownership. This
layer exists because the reference implementation has no equivalent, which is why its error
handling is per-function ad hoc rather than systematic.

---

## 8. Data Flow

### 8.1 Host-side (informational — the library is device-side)

```
old.bin ─┐
         ├─► bsdiff (BSDIFF43) ─► raw delta stream ─► codec compress ─┐
new.bin ─┘                                                              │
                                                                       ▼
                                                          container: v2 header +
                                                          codec props + payload +
                                                          signature
```

The signature covers the header and payload but excludes the signature field itself.

### 8.2 Device-side, successful path

```
  mcf_session_open()
      │  L2: parse header (magic, version, lengths, product, codec, dict)
      │  L2: verify header MAC / signature
      │  L2: check version > current        ── reject ──► MCF_E_ROLLBACK
      ▼
  mcf_session_begin()
      │  L2: verify base image CRC          ── reject ──► MCF_E_MISMATCH
      │  L1: codec->init(props)
      │  L1: check dict_size <= budget      ── reject ──► MCF_E_DICT_TOO_LARGE
      │  L1: allocate workspace
      ▼
  while (state != DONE):
    mcf_session_step()
        │  L1: decode → fill block from patch flash
        │  L3: apply delta block (diff against base, then literal bytes)
        │  L0: erase + program + verify the sink block
        │  L4: invoke progress callback → may abort
        │  L4: periodically checkpoint for resume (§15)
        ▼
  mcf_session_finish()
      │  L2: verify reconstructed image CRC ── reject ──► MCF_E_CORRUPT
      │  L4: invoke the commit hook — swap policy belongs to the integrator
      ▼
  DONE
```

### 8.3 Error flow

```
  any layer detects failure
        │
        ▼
  return negative mcf_status_t ──► session state := FAILED
                                     resource released (P1: B-07, B-08)
                                     error code preserved verbatim
                                     status queryable via mcf_session_status()
```

**Invariant: a session in state `DONE` has produced an image whose CRC was verified.** No
other state may be reported as success. This directly closes **B-03** and **B-05**.

---

## 9. Public API Design

### 9.1 Surface

Five functions, one query, one context. This is the contract an integrator implements and
calls — deliberately close to the reference implementation's successful refactor, so prior
porting effort transfers.

```c
/* ---- HAL callbacks (bound per session) ---- */
/* Set cfg.hal before mcf_session_open(); each session may use a different HAL. */
mcf_status_t mcf_hal_register(const mcf_hal_t *hal); /* validation only */

/* Heapless sessions set caller-owned `workspace` and `workspace_size` in each
 * mcf_config_t; concurrent sessions require separate buffers. */

/* ---- Session lifecycle ---- */
mcf_status_t mcf_session_open(mcf_session_t *s, const mcf_config_t *cfg);
mcf_status_t mcf_session_begin(mcf_session_t *s);
int32_t     mcf_session_step(mcf_session_t *s);   /* MCF_OK, or bytes remaining */
mcf_status_t mcf_session_finish(mcf_session_t *s);
void        mcf_session_close(mcf_session_t *s);

/* ---- Queries ---- */
mcf_status_t mcf_session_status(const mcf_session_t *s);
uint32_t    mcf_session_progress(const mcf_session_t *s);
uint32_t    mcf_session_error_line(const mcf_session_t *s);
uint32_t    mcf_ctx_size(const mcf_config_t *cfg);   /* exact RAM requirement */
```

Plus a single-call convenience wrapper `mcf_session_run()` for simple integrations that do not
need stepping — implemented entirely in terms of the above, adding no new behaviour.

### 9.2 Error model (**P1**)

```c
typedef enum {
    MCF_OK              =   0,
    MCF_E_PARAM         =  -1,  /* invalid argument or null pointer        */
    MCF_E_STATE         =  -2,  /* call invalid in current state           */
    MCF_E_NOMEM         =  -3,  /* workspace allocation failed            */
    MCF_E_FORMAT        =  -4,  /* bad magic, version, or header length   */
    MCF_E_UNSUPPORTED   =  -5,  /* unknown codec, arch, or flag            */
    MCF_E_DICT_TOO_LARGE=  -6,  /* patch requires more RAM than budgeted  */
    MCF_E_PRODUCT       =  -7,  /* patch not built for this product       */
    MCF_E_MISMATCH      =  -8,  /* base image CRC mismatch                */
    MCF_E_CORRUPT       =  -9,  /* payload decode or integrity failure    */
    MCF_E_TRUNCATED     = -10,  /* patch shorter than the header declares */
    MCF_E_SIGNATURE     = -11,  /* signature verification failed          */
    MCF_E_ROLLBACK      = -12,  /* version not newer than current         */
    MCF_E_FLASH         = -13,  /* erase, program, or verify failed       */
    MCF_E_IO            = -14,  /* underlying source/sink read failed     */
    MCF_E_ABORTED       = -15,  /* cancelled via progress callback        */
    MCF_E_COMMIT        = -16   /* integrators' commit hook rejected      */
} mcf_status_t;
```

**Return convention.** `int32_t` functions return `>= 0` bytes on success and a negative
`mcf_status_t` on failure. `mcf_status_t` functions return a code. **Zero is never
ambiguous**: it means "success, zero bytes", and only that. (**B-03**, **B-04**)

`mcf_session_error_line()` records a coarse stage identifier (which layer and which step
failed) so a field failure is diagnosable from a log line without a debugger (**P1**,
stakeholder: Operations).

### 9.3 Context ownership (**P3**)

```c
typedef struct mcf_session mcf_session_t;   /* opaque, caller-allocated */
```

The caller provides the storage — from a static object, a pool allocator, or the heap. The
library never allocates the session itself and never holds a static session pointer. This
eliminates **B-12** and makes the library reentrant by construction.

A convenience `MCF_SESSION_DECLARE(name, cfg)` macro provides static storage without
requiring a heap.

### 9.4 Configuration

```c
typedef struct {
    const uint8_t *patch_base;      /* patch image in memory               */
    uint32_t       patch_size;

    /* Base image: direct memory (fast path) or callback (general) */
    const uint8_t *old_base;        /* NULL ⇒ use old_read callback        */
    uint32_t       old_size;
    int  (*old_read)(void *u, uint32_t off, uint8_t *p, uint32_t len);
    void         *old_ctx;

    /* Destination for the reconstructed image */
    uint32_t       dst_addr;        /* via HAL                            */

    /* Codec: NULL ⇒ auto-select smallest workspace that fits */
    const char    *codec;
    uint32_t       block_size;      /* 0 ⇒ MCF_DEFAULT_BLOCK_SIZE (1024)   */

    /* Memory ceiling for codec workspace; the library refuses to exceed it */
    uint32_t       max_workspace;

    /* Optional */
    int  (*progress)(void *u, uint32_t done, uint32_t total);
    void *progress_ctx;
    int  (*commit)(void *u);        /* invoked after CRC passes           */
    void *commit_ctx;

    /* Memory budget for sizing (see §10) */
    uint32_t       ram_budget;
} mcf_config_t;
```

`max_workspace` and `ram_budget` are the mechanism that converts an implicit contract into
an enforced one (**P2**). The library computes the requirement from the patch, compares it
against the budget, and returns `MCF_E_DICT_TOO_LARGE` if it does not fit. **It never
attempts an allocation it cannot satisfy.** This is the direct fix for **B-01** and **W-01**.

### 9.5 Progress and abort (**P7**)

```c
int (*progress)(void *u, uint32_t done, uint32_t total);   /* != 0 ⇒ abort */
```

Invoked once per processed block. Returning non-zero sets `MCF_E_ABORTED`, releases all
resources, and leaves the session in `FAILED` — a clean, defined outcome rather than a
forced watchdog reset (**G-07**).

### 9.6 Step-wise state machine (**P7**)

```c
typedef enum {
    MCF_ST_IDLE = 0, MCF_ST_HEADER, MCF_ST_VALIDATE, MCF_ST_ALLOC,
    MCF_ST_DECODE,    MCF_ST_APPLY,   MCF_ST_WRITEBACK, MCF_ST_VERIFY,
    MCF_ST_COMMIT,    MCF_ST_DONE,    MCF_ST_FAILED
} mcf_state_t;
```

`mcf_session_step()` advances by one block and returns. A caller may service its watchdog,
sleep, yield, or persist state between steps. `mcf_session_run()` is a trivial loop over
`step()` for callers who do not need this.

This also provides the natural insertion point for the resume journal (§15).

---

## 10. Memory Model and Budget

### 10.1 The governing principle (**P2**)

> The device must know what a patch will cost *before* committing memory to it, and must
> refuse the patch cleanly if it cannot pay.

The reference implementation violates this at every level (**W-01**, **W-02**). This
architecture makes the contract explicit, queryable, and enforced.

### 10.2 Static RAM budget

Let `B` = block size (default 1024), `W` = codec workspace, `S` = session state,
`H` = HAL-provided scratch.

| Component | Size | Notes |
|---|---|---|
| Work buffer (diff apply) | `B` | Engine working window |
| Block read buffer | `B` | Engine input staging |
| Codec workspace | `W` | From `required_workspace(props)` |
| Session state | `S` | Constant, ≈ 200 B |
| **Total** | **`2B + W + S`** | `mcf_ctx_size()` returns this |

`H` is owned by the HAL for erase/program buffering and is not included.

### 10.3 Derivation of codec workspace

| Codec | Formula | Default configuration |
|---|---|---|
| **LZ4** | `~256 B + ring_size` | `ring = 4·B` ⇒ **~4.3 KB** @ B=1024 |
| **LZMA** | `probs + dict` where `probs = (1846 + 768·2^(lc+lp))·2 B` | `lc=3,lp=0` ⇒ 15,980 B; `dict=16 KB` ⇒ **~32 KB** |

The LZMA probability table is the reason the reference implementation cannot target a
Cortex-M0: it is an unconditional floor set by the codec, not by buffer sizing. This is the
quantitative core of **W-04**.

### 10.4 Projected profiles

| Profile | Codec | B | Workspace | **Total RAM** | ROM |
|---|---|---|---|---|---|
| **Constrained (M0)** | LZ4 | 512 | ~2.3 KB | **≈ 3.3 KB** | ~3 KB |
| **Standard (M3/M4)** — default | LZ4 | 1024 | ~4.3 KB | **≈ 6.3 KB** | ~4 KB |
| **Constrained, minimal** | LZ4 | 256 | ~1.3 KB | **≈ 2.3 KB** | ~3 KB |
| **Max ratio (M3/M4)** | LZMA | 1024 | ~32 KB | **≈ 34 KB** | ~9 KB |

**Primary design target: the Standard profile at ≈ 6.3 KB, with the Constrained profile at
≈ 3.3 KB for the lowest end.** Compare with the reference implementation's documented
"≥ 10 KB", which is not reproducible from its own code (**W-02**).

### 10.5 Static allocation option

For systems with no heap, `MCF_SESSION_DECLARE` plus `mcf_ctx_size()`-sized static buffers
give a fully static, allocation-free build. This is a common requirement in
safety-certified and hard-real-time firmware and is not supported by the reference design.

---

## 11. Concurrency and Real-Time Model

### 11.1 Guarantees

| Property | Guarantee |
|---|---|
| Mutable global state | **None.** All state is in the caller-owned `mcf_session_t`. |
| Reentrancy | **Yes.** Two sessions with distinct contexts are fully independent. |
| Thread safety of one session | **No.** A single session must be driven by one context at a time. Documented, not defended against. |
| HAL reentrancy | Depends on the implementation; stated as a HAL requirement. |
| Blocking calls | **None.** Every call is bounded by one block of work. |

**`mcf_ctx_size()` is pure and reentrant** — safe to call from an allocator or a build script.

### 11.2 Integration guidance

```
  /* Interrupt-driven: service the watchdog between steps */
  while (mcf_session_step(&g_upgrade) == MCF_OK) {
      wdt_kick();
      if (power_should_sleep()) { enter_low_power(); }   /* safe: state is on stack/static */
  }
```

The RTOS-lock-and-disable-the-watchdog pattern the reference implementation's documented
integration requires (**G-07**) becomes unnecessary. The integrator's concurrency burden
drops from "externalise a lock" to "do not share a context", which is checkable by review.

### 11.3 No OS dependency

The library uses no scheduler, no timers, no locks, and no RTOS headers. It is portable to
bare-metal, superloop, and RTOS systems identically.

---

## 12. Flash Write Contract

### 12.1 The problem (**G-06**)

NOR flash cannot be programmed over existing data — program only clears bits. A correct
update requires: *erase the containing block, buffer across block boundaries, program,
optionally verify.* The reference implementation collapses this into a single
"write" callback with no erase primitive, no alignment contract, and no buffering.

The result is that the most natural integration — wiring the callback to a page-program
primitive — produces **silent corruption**, and the library's own error path then hides it
(**B-02**). This is the most dangerous interface defect in the reference work.

### 12.2 The contract

```c
typedef struct {
    /* Erase `len` bytes starting at `addr`. `len` is always a multiple of
     * mcf_flash_block_size() and aligned to it. */
    int (*erase)(void *u, uint32_t addr, uint32_t len);

    /* Program `len` bytes. `len` is always a multiple of the HAL's program
     * granularity, which the library queries. Never crosses a block boundary. */
    int (*write)(void *u, uint32_t addr, const uint8_t *p, uint32_t len);

    /* Read `len` bytes. May be NULL if the region is directly addressable. */
    int (*read)(void *u, uint32_t addr, uint8_t *p, uint32_t len);

    /* Erase/program granularity in bytes. Power of two. */
    uint32_t (*block_size)(void *u);

    /* Optional. Non-zero ⇒ write-only device; enables the streaming fast path
     * that skips the read-back verify. */
    int (*is_readonly)(void *u, uint32_t addr, uint32_t len);
} mcf_flash_ops_t;
```

### 12.3 What the library now guarantees

1. **Alignment** — the library queries granularity and never issues an unaligned or
   block-crossing operation.
2. **Buffering** — the library buffers across erase-block boundaries so the HAL never has
   to. This is the defect's direct fix.
3. **Erase-before-program** — enforced by the library, not requested in a comment.
4. **Write verification** — read-back compare after program, unless `is_readonly` says the
   region cannot be read. Failure returns `MCF_E_FLASH`.
5. **Error propagation** — any HAL failure aborts the session and is reported verbatim
   (**B-02**).

### 12.4 Buffering cost

`mcf_ctx_size()` includes the HAL scratch required for boundary buffering when the erase
block exceeds the work block. For a typical 2 KB STM32 sector with `B = 1024`, the library
buffers one sector (2 KB); for a 64 KB NOR block it buffers the block or requires the
integrator to supply a larger `B`. This trade-off is documented rather than hidden.

---

## 13. On-Flash Format Specification (v1 shipped; v2 design proposal in `docs/format-v2-design.md`)

### 13.1 Requirements

- Explicit magic, version, and header length, so the format can evolve (**G-04**).
- Uniform, declared endianness (**G-05**).
- Product binding (**G-03**).
- Cryptographic authenticity and monotonic versioning (**G-01**, **G-02**).
- The decoder's memory requirement stated in the header and validated before allocation
  (**W-01**, **P2**).

### 13.2 Layout

All integers **little-endian**, no padding, fixed offsets. The header is
`static_assert`-ed against `sizeof` in the C reference, and a Python parser asserts the same
layout, so the two cannot drift.

| Off | Size | Field | Purpose |
|---:|---:|---|---|
| 0 | 4 | `magic` | `'MFP1'` = 0x3150464D — **G-04** |
| 4 | 2 | `hdr_len` | Header size in bytes; permits extension — **G-04** |
| 6 | 2 | `hdr_ver` | Major<<8 \| minor — **G-04** |
| 8 | 4 | `flags` | bit0 signed, bit1 raw, bit2 LZMA, bit3 LZ4 |
| 12 | 4 | `product_id` | Board/product binding — **G-03** |
| 16 | 4 | `fw_version` | Monotonic; anti-rollback — **G-02** |
| 20 | 4 | `old_size` | Base image length |
| 24 | 4 | `new_size` | Reconstructed image length |
| 28 | 4 | `payload_size` | Bytes after the header |
| 32 | 4 | `old_crc32` | Base image integrity |
| 36 | 4 | `new_crc32` | Reconstructed image integrity |
| 40 | 4 | `payload_crc32` | Delta stream integrity |
| 44 | 4 | `workspace_req` | **Decoder RAM required** — **W-01** |
| 48 | 4 | `old_version` | Version of the base image required |
| 52 | 1 | `codec_id` | 1 = LZ4, 2 = LZMA; 0 is AUTO and invalid on the wire |
| 53 | 1 | `block_size_log2` | Decoder block size |
| 54 | 2 | `reserved` | Must be zero |
| 56 | 64 | `signature` | Ed25519 (R‖S) or ECDSA-P256 — **G-01** |
| 120 | var | `codec_props` | Codec parameters |
| — | var | `payload` | Compressed delta stream |

**`workspace_req` is the keystone field.** It states the decoder's RAM requirement in the
patch itself. The device compares it against `ram_budget` during header validation and
returns `MCF_E_DICT_TOO_LARGE` before allocating a single byte. A mismatched patch is a clean
error, not a fault (**B-01**).

**Minimum header length is therefore 120 bytes**, and `MCF_HDR_MIN_SIZE` is asserted against
`sizeof(mcf_header_t)` at compile time. Note that an Ed25519 *signature* is 64 bytes (R‖S)
while its *public key* is 32; conflating the two shifts the payload by 32 bytes and
corrupts every field after it. This was caught by the host tool's round-trip test, and the
field sizes are now asserted independently in C and in Python.

**No structure is transmitted by layout.** The C struct exists only for host-side tooling
and debugging; the device parser performs explicit little-endian reads of the byte table
above and does not depend on the struct's memory layout. The layout is naturally aligned
and requires no packing, and both the C reference and the Python host tool assert their
field offsets against the table independently, so the two cannot drift.

### 13.3 Retained: the BSDIFF43 delta format

The delta stream format itself is **unchanged**. It is proven, appropriately sized, and its
weaknesses lie in the surrounding contract, not the algorithm (§3.4). Changing it would
invalidate every existing host tool for no engineering benefit.

Consequently, patches produced by the reference toolchain can be made to work by adding a
header-translation step, preserving field investment (**§19**).

### 13.4 Header validation

Performed once, in `mcf_hdr_open()`, and everything downstream trusts the result (**P5**):

```
 1. magic == 'BSPD'                    else MCF_E_FORMAT
 2. hdr_ver major supported            else MCF_E_UNSUPPORTED
 3. hdr_len >= MIN_HDR, <= MAX_HDR     else MCF_E_FORMAT
 4. product_id == configured product   else MCF_E_PRODUCT
 5. fw_version > current version       else MCF_E_ROLLBACK
 6. old_version == current version     else MCF_E_MISMATCH
 7. codec_id known                     else MCF_E_UNSUPPORTED
 8. sizes within flash capacity        else MCF_E_PARAM
 9. workspace_req <= ram_budget        else MCF_E_DICT_TOO_LARGE   ← prevents B-01
10. signature valid over hdr[0..55]+payload  else MCF_E_SIGNATURE   ← prevents G-01
11. hdr CRC valid                      else MCF_E_CORRUPT
```

Order matters: cheap checks first, cryptographic verification last.

---

## 14. Security Model

### 14.1 Threat model

| Asset | Threat |
|---|---|
| Firmware integrity | Attacker delivers a modified patch; device executes attacker code |
| Firmware authenticity | Attacker replays a legitimately-signed older image |
| Update availability | Attacker floods with invalid patches to exhaust flash or block updates |
| Device identity | Patch for product A applied to product B |

**Assumption.** The transport (BLE, LoRa, UART) is untrusted. This is the correct assumption
for any wireless or physical-access OTA path and is the one the reference implementation
implicitly violates by relying on CRC32 alone.

### 14.2 Controls

| Control | Addresses | Mechanism |
|---|---|---|
| **Digital signature** | Arbitrary code execution | Ed25519 (default, ~2 KB flash for verify) or ECDSA-P256 where a hardware accelerator exists. Verified before any patch byte is applied. |
| **Anti-rollback** | Replay of vulnerable versions | `fw_version` must exceed the stored current version. Enforced against a monotonic counter in OTP/eFuse or a signed version record. |
| **Product binding** | Cross-product patch application | `product_id` compared against a device-provisioned value. |
| **Integrity** | Corruption in transit or storage | CRC32 for accidental corruption; the signature for authenticity. CRC is explicitly documented as *not* a security control. |
| **Version pinning** | `old_version` mismatch | Prevents applying a patch to an unexpected base image. |
| **Resource exhaustion** | Malicious patch | `workspace_req` validated before allocation; all sizes range-checked; no allocation on the parse path. |

### 14.3 Signature algorithm selection

| | Ed25519 | ECDSA-P256 |
|---|---|---|
| Code size (verify) | ~2–3 KB | ~4–6 KB |
| Public key | 32 B | 64 B uncompressed |
| Verify time @ 20 MHz M0 | ~10–20 ms | ~40–80 ms, or ~1 ms with an accelerator |
| Implementation risk | Low — self-contained, constant-time available | Moderate — needs constant-time scalar multiplication |

**Default: Ed25519.** Fastest to audit, smallest, and no dependency on a big-integer
library. ECDSA-P256 offered where a hardware accelerator already exists. The verification
hook is a `mcf_verify_fn` so integrators may supply a platform HSM or RoT-backed verifier
without modifying the library.

### 14.4 Explicitly out of scope

Encryption (§4.2 N4) and transport authentication. Both are layered above this library.
**Signature verification is mandatory when enabled; a library build without it is a build
for development only** and is gated behind a compile-time flag that emits a warning.

---

## 15. Power-Fail Resilience and Recovery

### 15.1 Problem

Field devices are powered off mid-restore, batteries die, and users press reset. A restore
that is not resumable and not discardable produces bricked units.

### 15.2 Approach: a resumable step machine

The step-wise state machine (§9.6) makes resumption natural. The session records a **journal**
into a caller-designated small NVM region at every control-triple boundary in the delta
stream, and reads it back after a reset.

```c
typedef struct mcf_journal {
    uint32_t magic;        /* 'RCJM', or 0 if never written */
    uint32_t session_id;   /* CRC-32 of the patch header         */
    uint32_t newpos;       /* output bytes already programmed    */
    uint32_t prefix_crc32; /* CRC-32 of the reconstructed prefix */
    uint32_t record_crc;   /* CRC-32 of the four fields above    */
} mcf_journal_t;
```

`mcf_resume_probe()` validates the record, checks that it belongs to this patch, and verifies
the reconstructed prefix against the flash that is actually there. `mcf_session_begin()` then
continues from that point. A damaged, stale, or mismatched record returns
`MCF_E_NOT_FOUND` and the update starts clean — that is an ordinary condition after a power
cut, not an error.

**Integrity argument.** `prefix_crc32` is compared against a fresh read of the reconstructed
prefix, so flash corruption between power cycles is detected and the resume point discarded
rather than trusted. Without this, resume is a correctness hazard rather than a feature.

**What the journal does not do.** It is not an authenticity control. It lives in NVM the
device itself writes; an attacker who can write that NVM has already won. The threat
addressed is corruption and interruption, not forgery. Patch authenticity is §14's job.

#### 15.2.1 A correction to the original design

The first draft of this section specified resuming by seeking the decompressor to a recorded
`payload_pos`. **That is not expressible in the codec interface as designed, and the
implementation does not attempt it.** A decompressed-stream position and a compressed-stream
position are different coordinate systems, and the compressed one is only meaningful at a
codec block boundary — which the delta engine knows nothing about. Restoring
`io.payload_pos` to a mid-block offset produces a stream that decodes cleanly and is
reconstructed incorrectly.

The implemented behaviour is therefore: **re-derive the prefix from the start of the stream
and discard it**, saving the flash programming of the prefix rather than the CPU. Flash
writes are the expensive part, so this captures most of the benefit and is correct for any
codec without extending the vtable.

Two changes would make resume cheaper, and are the natural next step:

1. Add a `rewind(block_pos, skip)` entry to `mcf_codec_ops_t`, alongside a
   `checkpoint(&block_pos, &skip)`. The codec — not the engine — reports where its current
   block starts and how much of it has been emitted.
2. Have the engine expose the decompressed offset of the current triple, which it already
   knows, instead of the compressed offset.

Until then the re-derive-and-discard behaviour is the correct choice, and the tests in
`tests/test_microfoam.c` cover interrupt-and-continue plus the four rejection paths. If a
checkpoint prefix read or journal write fails, the update continues best-effort and sets
`MCF_SESSION_FLAG_RESUME_DEGRADED`; callers that require resumability must treat that flag
as a product-level warning.

#### 15.2.2 Checkpoint reachability

A checkpoint is only meaningful at a control-triple boundary, and the step budget can run
out exactly on the transition into the extra segment, never reaching the control phase. The
engine therefore also marks the diff-to-extra transition as a safe point when the triple has
no extra segment, so a checkpoint opportunity cannot be skipped indefinitely by an unlucky
block-size-to-triple-size ratio.


### 15.3 Relationship to A/B slots

Slot selection and swap policy are explicitly **out of scope** (§4.2 N2) because they are
product-specific. The library provides:

- the `commit` callback (§9.4), invoked **only after** the reconstructed image's CRC verifies;
- the `MCF_E_COMMIT` code, so an integrator can reject a swap;
- the guarantee that a session reaching `MCF_ST_DONE` has produced a verified image.

An integrator implementing a standard A/B scheme writes a small state marker in `commit`,
selects the new slot, and resets. The library's contribution is the invariant that the
marker is only ever set on verified data — which the reference implementation does not
provide (**B-03**).

### 15.4 Failure-mode matrix

| Interruption point | Device state | Recovery |
|---|---|---|
| Before `BEGIN` | Untouched | Re-run |
| During `DECODE` | Partial image in staging region | Staging region is disposable; re-run |
| During `WRITE` of staging | Partial image in staging region | Staging region is disposable; re-run |
| After staging CRC, before `COMMIT` | Verified image in staging, old slot active | Re-run or commit on next boot |
| During `COMMIT` | Depends on integrator's marker atomicity | Integrator uses a single atomic marker write |

The essential property: **the running image is never modified.** Recovery is always "start
over" from a staging region, and resumption is an optimisation layered on a scheme that is
already safe without it.

---

## 16. Build System and Toolchain Support

### 16.1 Requirements

| # | Requirement | Addresses |
|---|---|---|
| B1 | Builds warning-clean under the verified GCC/ARM GCC paths; armclang and IAR remain unverified portability targets | **W-09** |
| B2 | **No encoding-specific flags** baked into the build script; toolchains expressed as toolchain files | **W-09** |
| B3 | Explicit source lists; no recursive globbing | **W-07** |
| B4 | The compression **encoder** and file-I/O layers are not in the device build | **W-07** |
| B5 | No public header includes standard I/O | **W-07** |
| B6 | All library symbols namespaced (`mcf_`), no global-scope collision | **W-08** |
| B7 | `mcf_ctx_size()` usable at build time for a size regression gate | **G-10** |
| B8 | CMake ≥ 3.15 with a Conan 2.x recipe; both optional for plain-CMake users | — |

### 16.2 Codec selection as a build option

```cmake
option(MCF_CODEC_LZ4   "Enable LZ4 codec (default)"  ON)
option(MCF_CODEC_LZMA  "Enable LZMA codec"           OFF)
option(MCF_SIGN        "Require patch signatures"    ON)
option(MCF_RESUME      "Enable resume journal"       ON)
```

Only selected codecs are compiled, so a device pays only for what it uses.

### 16.3 Explicit source list

The device build compiles: the session, container, delta engine, the selected codec(s), and
the HAL interface. The host build compiles the generator, the delta producer, and the
encoder side of the codecs. **No overlap.**

### 16.4 CI matrix

| Dimension | Values |
|---|---|
| Compiler | GCC/ARM GCC (verified); armclang and IAR are unverified portability targets |
| Core | M0, M3, M4, M7, M33 |
| Build type | Debug, Release (`-Osize`, `-Os` LTO + `--gc-sections`) |
| Analysis | `-Wall -Wextra -Wconversion -Wsign-conversion -Werror`, static analysis |
| Tests | Host unit tests, ASan/UBSan host build, hardware-in-the-loop targets |
| Gates | Zero warnings, all tests pass, **ROM and RAM deltas within budget** |

**B7 is enforced as a gate:** a pull request that increases the reported size for a
configuration without a documented reason fails CI. This is the mechanism that keeps
**P10** true over time rather than only at initial release.

---

## 17. Host Tooling

### 17.1 The gap (**G-11**)

The reference project defines its wire format with a closed-source binary distributed via
file sharing. Consequences: the format is unauditable, patches are not reproducible, no
third party can produce a valid patch, and the system cannot be maintained by anyone but one
person (**W-11**).

**This is the largest non-code defect in the reference work and the precondition for
everything in §13.**

### 17.2 Scope

A `microfoam-host` package providing:

```
microfoam make --old old.bin --new new.bin --product 0x1234 \
               --version 0x00020001 --key priv.key --out patch.bin
microfoam inspect patch.bin          # dump and validate the header
microfoam verify  patch.bin --pub pub.key
microfoam apply   --old old.bin --patch patch.bin --out new.bin   # host-side, for tests
```

### 17.3 Design requirements

| # | Requirement | Rationale |
|---|---|---|
| H1 | **Deterministic.** Identical inputs produce a byte-identical patch. | Reproducible builds; patches are diffable and auditable. No timestamps or random data in the output. |
| H2 | **Dual-codec selection.** Compress with every enabled codec, emit the smallest. | Device cost and host ratio are independent; the manufacturer always gets the best result. |
| H3 | **Sign at generation.** Private keys never leave the build host. | The device only ever holds a public key. |
| H4 | **A reference implementation used only in tests.** The test suite compares against a known-good decoder. | Independent verification that the device decoder is correct. (**G-10**) |
| H5 | **Header layout asserted in two languages.** C and Python parsers, cross-checked. | Prevents the layout drift that causes **W-10**. |
| H6 | **Written in Python or Rust, shipped as a static binary or wheel.** | Not an adoption barrier. |

---

## 18. Test Strategy and CI

The reference implementation has no tests (**G-10**). For a code path that decides whether a
device executes attacker-supplied bytes, this is the most serious process gap.

### 18.1 Test pyramid

| Level | Coverage | Gate |
|---|---|---|
| **Unit** | Codec encode/decode round-trip; header parse; error-code mapping; `mcf_ctx_size()`; bounds checks; journal encode/decode | Per commit |
| **Integration** | Full `session_run` against generated fixtures; both codecs; all block sizes; all failure injections | Per commit |
| **Fault injection** | **Every allocation, read, decode, erase, program, and verify step forced to fail in turn** | Per commit |
| **Property** | Random old/new pairs; arbitrary corruption of the patch; arbitrary truncation at every offset | Nightly |
| **Conformance** | Golden `.bin` fixtures; host reference decoder cross-check; byte-exact output | Per commit |
| **Static analysis** | `-Wall -Wextra -Wconversion -Werror`; cppcheck; ASan/UBSan host build | Per commit |
| **Size** | `mcf_ctx_size()` and ROM size per configuration | Per commit (**B7**) |
| **HIL** | STM32F0/M4, Renesas RX — real flash, real watchdog, real power cycling | Nightly |

### 18.2 The fault-injection suite is the core contribution

It exists to close the exact gap that produced the reference implementation's worst findings.
For each stage — allocation, source read, decode, erase, program, verify — the suite forces a
failure and asserts:

1. The return value is the **specific** expected `mcf_status_t`; and
2. It is **not** `MCF_OK`; and
3. No resources leak (asserted by allocation/deallocation counters); and
4. No bytes were written after the failure.

Property 2 is the direct regression test for **B-01**, **B-02**, **B-03**, and **B-05** — the
four defects that cause silent field failures. This suite is the enforcement mechanism for
**G1** and **P1**, and it must be green before any release.

### 18.3 Coverage of the reference findings

| Finding | Regression test |
|---|---|
| B-01 heap exhaustion | Force workspace alloc to fail → expect `MCF_E_NOMEM`, never a fault |
| B-01 dict mismatch | Patch declares `workspace_req` > budget → expect `MCF_E_DICT_TOO_LARGE` |
| B-02 flash write fail | Force `write` to return error → expect `MCF_E_FLASH`, no further writes |
| B-03 false success | Force any mid-session failure → assert return ≠ `MCF_OK` and state = `FAILED` |
| B-05 corrupt payload | Flip bits at every offset → expect `MCF_E_CORRUPT` |
| B-07/B-08 leaks | Allocation counter balance across every failure path |
| G-01 no signature | Mutate payload with a valid CRC → expect `MCF_E_SIGNATURE` |
| G-02 replay | Patch with `fw_version` ≤ current → expect `MCF_E_ROLLBACK` |
| G-03 cross-product | Correct patch, wrong `product_id` → expect `MCF_E_PRODUCT` |
| W-01 implicit dict | Regenerate patches at many dict sizes; every rejection is an error, never a fault |

---

## 19. Versioning and Compatibility

### 19.1 Library version

Semantic versioning. The **public API is `mcf_*` only**; the container format version
(`hdr_ver`) is tracked separately, because a patch format revision must be able to change
without a library major bump.

### 19.2 Format compatibility

| Strategy | Detail |
|---|---|
| Forward compatibility | Unknown `hdr_ver` major ⇒ `MCF_E_UNSUPPORTED`. A newer device may accept a newer minor by ignoring fields beyond `hdr_len`. |
| Backward compatibility | The v1 BSDIFF43 delta payload is **unchanged in v2**. Only the container header is new. |
| Migration path | A translator converts v1 patches to v2 by recomputing the header. Field device population requires it only for the first signed release. |

### 19.3 Deprecation

No API is removed within a major version. Deprecated entry points remain for one major
cycle with a compile-time warning. `mcf_session_run()` provides the migration path from
single-call to step-wise usage.

---

## 20. License

### 20.1 Choice

**MIT License.**

### 20.2 Rationale

The library derives from two well-known upstream components:

| Upstream component | Upstream license | Compatibility with MIT |
|---|---|---|
| BSDIFF / bspatch | BSD 2-Clause | Permissive; MIT-compatible. Requires retaining the copyright notice and disclaimer. |
| LZMA SDK (7-Zip) | Public domain / 7-Zip license | No restriction. |

**Why MIT:**

- **Compatible with the entire upstream lineage.** The permissive sources can be relicensed
  under MIT; their notices are preserved (§20.3), which is the only obligation either imposes.
- **Maximally permissive for integrators.** No copyleft obligation, no network-copyleft
  trigger, no patent retaliation clause. For a library that is *statically linked* into
  shipped proprietary firmware, this is decisive: an open-source licence with any copyleft
  or network-copyleft character creates a direct, unavoidable obligation on the
  integrator's product.
- **Zero runtime and review cost.** A ~1 KB licence text adds nothing to a firmware image and
  imposes no compliance surface on small teams — which is the primary audience.

**Why not the alternatives:**

| Alternative | Why rejected |
|---|---|
| **AGPL-3.0** | Its network-copyleft clause is the worst possible fit for firmware that is compiled into a shipped binary and whose source is not published. Obligations attach regardless of how the library is linked. It actively discourages the adoption this project needs. *(This is the licence of the reference implementation, and is a principal reason it has not been adopted more widely.)* |
| **Apache-2.0** | Compatible, and its explicit patent grant has merit — but it imposes a NOTICE-file obligation and a "state changes" clause for a 3–9 KB code footprint where the marginal benefit is near zero. |
| **GPL-2.0/3.0** | Copyleft. Incompatible with proprietary firmware distribution, which is the target use case. |
| **BSD-3-Clause** | Essentially equivalent to MIT. Rejected only because the non-endorsement clause adds text without adding value here. |

### 20.3 Required attributions

The following notices must be preserved in source distributions and reproduced in
third-party notices:

```
bspatch / bsdiff
  Copyright 2003-2005 Colin Percival
  Copyright 2012 Matthew Endsley
  Redistribution and use in source and binary forms, with or without modification,
  are permitted provided that the conditions of the BSD 2-Clause Licence are met.

LZMA SDK
  Author: Igor Pavlov
  The LZMA SDK is placed in the public domain. Where a copy of the 7-Zip licence
  is retained in the distribution, its terms continue to apply to those files.
```

Source files carry a single-line SPDX identifier (`SPDX-License-Identifier: MIT`) plus, where
applicable, an `Upstream-License:` line. Attribution is a build-system check, not a
convention — CI fails on a missing SPDX header.

### 20.4 Security disclosure

A `SECURITY.md` defines coordinated disclosure: report privately, 90-day window, credit in
the advisory. A published security contact is a precondition for a project that asks users to
trust it with firmware authenticity.

---

## 21. Delivery Roadmap

Indicative effort for one engineer. Phases are ordered so that each produces a usable
artefact and the highest-risk work is de-risked early.

| Phase | Duration | Deliverable | Exit criteria |
|---|---|---|---|
| **P0 — Foundation** | 2 wks | Repository skeleton, CI, MIT headers, `mcf_hal_t`, error model, `mcf_ctx_size()`, documentation site | Builds clean on all 5 toolchains; all SPI headers present |
| **P1 — Core engine** | 4 wks | Context object, LZ4 codec, BSDIFF43 engine, container parse, `session_run` | Round-trip passes; **all fault-injection tests green** |
| **P2 — Robustness** | 3 wks | Workspace validation (`MCF_E_DICT_TOO_LARGE`), LZMA codec, step-wise API, progress/abort, block-size tuning | Workspace rejection verified at many dict sizes; Constrained profile ≤ 3.3 KB measured |
| **P3 — Security** | 3 wks | v2 header, Ed25519 signatures, product binding, anti-rollback | Signature and rollback tests green; `MCF_SIGN` mandatory in release builds |
| **P4 — Resilience** | 3 wks | Journal, `mcf_resume_probe`, `mcf_session_resume`, power-cycle HIL tests | Interrupted restore resumes correctly; corrupted journal is rejected |
| **P5 — Release** | 2 wks | Host tool, docs, three worked ports (STM32 internal flash, STM32 + SPI NOR, Renesas RX) | Host tool produces byte-identical output on repeat runs; a new integrator succeeds unaided |

**Total: ~17 weeks.** P0–P2 (9 weeks) delivers a strictly better library than the reference
implementation in every measured dimension. P3 is what makes it *shippable* in a security-
sensitive product.

### 21.1 Sequencing rationale

**Fault-injection tests land in P1, not P5.** The reference implementation's four critical
and high findings all share one root cause: the failure path was never exercised. Building
the test suite alongside the first implementation, rather than after, is the single most
important process decision in this roadmap (**P10**).

**P3 is not deferrable.** Shipping a delta updater without signature verification ships a
remote code execution primitive under a reassuring name. The roadmap is ordered so that a
team under schedule pressure can ship P0–P2 as an *internal* tool but cannot plausibly ship
P0–P2 to the field.

---

## 22. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R-01 | LZ4's lower ratio disappoints on some firmware | Medium | Medium | Host tool emits whichever codec is smaller; both ship; ratio measured per product in P2 |
| R-02 | Signature verification too slow on the lowest-end target | Low | Medium | Ed25519 default; measured in P3 HIL; `mcf_verify_fn` allows a HSM/accelerator |
| R-03 | Resume journal adds complexity and new failure modes | Medium | Medium | Correctness does **not** depend on it (§15.4); P4 is a pure optimisation and can be cut without losing safety |
| R-04 | Integrators used to the reference API find the change disruptive | High | Low | API kept deliberately close; deprecation cycle (§19.3); porting notes in P5 |
| R-05 | Upstream attribution obligations missed | Low | High | SPDX headers enforced in CI (§20.3), not by convention |
| R-06 | Format v2 adoption stalls because field devices only understand v1 | Medium | Medium | Header translator (§19.2); v1 patch payload unchanged |
| R-07 | Scope growth from the resume/security features | High | Medium | Explicit non-goals (§4.2); each phase has stated exit criteria |
| R-08 | Single-maintainer continuity (the failure mode of the reference project) | Medium | High | MIT licence, published format, published host tool, documented CI — all of which exist specifically to make the project maintainable by more than one person |
| R-09 | Performance regression from the more thorough bounds checking | Low | Low | Checking is per-block, not per-byte; measured in P2 |

---

## 23. Open Questions

| # | Question | Owner | Needed by |
|---|---|---|---|
| Q-01 | Ed25519 or ECDSA-P256 as the default? Depends on whether target parts have crypto accelerators. | Hardware | P3 |
| Q-02 | Should `fw_version` live in OTP/eFuse, a signed NVM record, or a bootloader-managed slot? Depends on the target's NVM capabilities. | Integrator | P3 |
| Q-03 | Minimum supported `product_id` granularity — per model, per family, or per customer? | Business | P3 |
| Q-04 | Should the journal be a required HAL capability or optional? | Integrator | P4 |
| Q-05 | Is A/B slot support worth building in, given the "out of scope" decision (§4.2 N2)? Most integrators need it. | Product | P5 |
| Q-06 | Should the host tool be Python or Rust? Affects the static-binary distribution story. | Maintainer | P5 |
| Q-07 | Target minimum: is the Constrained profile (≈ 3.3 KB, Cortex-M0) genuinely in scope, or is the Standard profile (≈ 6.3 KB) sufficient? Affects whether further optimisation is warranted. | Product | P2 |

---

## 24. Appendices

### 24.1 Glossary

| Term | Meaning |
|---|---|
| **A/B slot** | Two firmware storage regions; the inactive one is written while the other runs, then selected at boot. |
| **Delta patch** | A file encoding the difference between two binary images, from which the target image can be reconstructed. |
| **BSDIFF43** | The bsdiff variant by Matthew Endsley; the delta format retained by this design (§13.3). |
| **Codec** | A pluggable compression/decompression back end (§7.3). |
| **Context (`mcf_session_t`)** | The caller-owned object holding all session state (§9.3). |
| **HAL** | Hardware Abstraction Layer — the only platform-dependent surface (§12). |
| **Workspace** | Memory a codec needs beyond the fixed work buffers; the key RAM-budget quantity (§10.3). |
| **Staging region** | Non-executing storage the reconstructed image is written to before commit (§15.4). |

### 24.2 Mapping: findings → architectural controls

Traceability from every §3 finding to the design element that prevents it. This table is the
review artefact that makes the architecture auditable.

| Finding | Control | § |
|---|---|---|
| B-01 alloc failure → fault | Workspace pre-validation; `MCF_E_DICT_TOO_LARGE`; alloc-failure tests | 10.4, 13.2, 18.2 |
| B-02 flash failure hidden | Explicit `erase`/`write`; write verification; error propagation | 12.2, 12.3 |
| B-03 false success | Error model; single-exit state machine; `DONE` implies CRC verified | 9.2, 8.3 |
| B-04 ambiguous zero | Return-value convention; zero means zero bytes only | 9.2 |
| B-05 silent partial decode | Codec error propagation; `MCF_E_CORRUPT` | 9.2, 18.2 |
| B-06 logging broken | Removed; `mcf_log` HAL callback, correct varargs | 16.1 B5 |
| B-07/B-08 leaks | Single-exit state machine; leak assertions in CI | 8.3, 18.2 |
| B-09 continue-after-fail | Strict precondition checks at every state transition | 9.6 |
| B-10 silent truncation | `read` returns a status; short reads are errors | 9.2, 12.2 |
| B-11 position underflow | Validated `setpos`; range-checked remaining-size computation | 12.2, 18.1 |
| B-12 stale static state | All state in caller-owned context | 9.3, 11.1 |
| B-13 type-punned pointer | Typed context struct; no parameter-address punning | 9.3 |
| B-14 packaging defects | Explicit toolchain files; CI across all toolchains | 16.1 |
| B-15 undefined log symbol | Removed with the debug scaffolding | 16.1 B5 |
| G-01 no signature | v2 header signature; mandatory in release builds | 13.2, 14.2 |
| G-02 no anti-rollback | `fw_version` monotonic check | 13.2, 14.2 |
| G-03 no product binding | `product_id` validation | 13.2, 13.4 |
| G-04 no versioning | `magic`, `hdr_ver`, `hdr_len` | 13.2 |
| G-05 inconsistent endianness | Uniform little-endian byte-table format; dual-language assertion | 13.2, 17.3 H5 |
| G-06 erase/program conflation | Split HAL contract with alignment and buffering | 12.2, 12.3 |
| G-07 no progress/abort | Progress callback; step-wise machine | 9.5, 9.6 |
| G-08 raw-pointer old image | `old_read` callback abstraction | 7.2, 9.4 |
| G-09 no power-fail model | Journal + resume + staging-region safety argument | 15.2, 15.4 |
| G-10 no tests | Full test pyramid with fault injection and CI gates | 18 |
| G-11 no host tool | Published, deterministic, signing-capable tool | 17 |
| G-12 no resource query | `mcf_ctx_size()`; `max_workspace`; `ram_budget` | 9.4, 10.1 |
| W-01 implicit dict contract | `workspace_req` in header; pre-allocation validation | 13.2, 10.4 |
| W-02 unreproducible RAM figure | Published derivation; measured CI gate | 10.3, 16.1 B7 |
| W-03 global state | Caller-owned context | 9.3, 11.1 |
| W-04 oversized default codec | Pluggable codec; LZ4 default | 7.3, 10.3 |
| W-05 byte-at-a-time loop | Block-granular codec interface | 7.3 |
| W-06 64-bit arithmetic | 32-bit-clean engine; fields bounded by construction | 7.2 |
| W-07 platform dependencies | No stdio in public headers; encoder excluded from device build | 16.1 B3–B5 |
| W-08 namespace pollution | `mcf_` prefix on all exported symbols | 16.1 B6 |
| W-09 non-portable build | Toolchain files; explicit sources; 5-toolchain CI | 16 |
| W-10 unstructured header | Byte-table format; dual-language layout assertion | 13.2, 17.3 H5 |
| W-11 single point of failure | Open format + published tool + CI + MIT | 17, 20 |

### 24.3 Document conventions

- **MUST / SHOULD / MAY** carry their usual normative force.
- Section references (§) are to this document.
- Code excerpts are illustrative C99 and are not compilable without the surrounding headers;
  the authoritative interfaces are those in the corresponding headers, which are
  `static_assert`-ed against this document's byte tables.

---

*End of document. Microfoam — tiny bubbles, tiny footprint, full-strength upgrade.*
