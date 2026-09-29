# Ed25519 verifier — work in progress, deliberately not shipped

**Status: rejected for now. Not compiled into the library, not in the CMake build.**

The library's behaviour is unchanged and safe: a patch with `FLAG_SIGNED` is rejected with
`MCF_E_SIGNATURE` unless the integrator supplies `mcf_verify_fn`. That is *fail closed*, and
it is the correct default. See `docs/architecture.md` §14.3.

## What this directory contains

| File | Purpose |
|---|---|
| `mcf_ed25519.c` | A from-scratch Ed25519 **verify-only** implementation, portable C99, no `__int128`, no GNU extensions |
| `mcf_ed25519.h` | Its interface |
| `ed25519_test.c` | Conformance harness: reads vectors produced by Python's `cryptography` and checks the C against them |

The harness is the valuable part. It generates 32 vectors — valid signatures across
message lengths 0…4096 including every SHA-512 block boundary, negatives for a wrong key, a
wrong message, a tampered signature and a tampered key, plus NULL and all-zero degenerate
inputs — and asserts each returns its expected verdict. It is what any future implementation
should be validated against, and it is the test that caught most of the defects below.

## Why it is not shipped

A hand-written verifier was written and debugged extensively. Twelve distinct real defects
were found and fixed, including several that a structural test cannot catch:

| Defect | Why it mattered |
|---|---|
| SHA-512 wrote the message length into the *high* 8 bytes of the 16-byte length field | every digest wrong |
| SHA-512 `K` table had 64 entries instead of 80, declared `uint32_t` instead of `uint64_t` | read past the array; wrong round constants |
| `fe_carry` left limb 0 at roughly 2^22, so the limb bound was not maintained | error only appeared after enough rounds to accumulate |
| Square-root-of-a-ratio identity multiplied by `u` where it needs `v^4` | decompression of any point failed |
| Base point constants garbled — six-hex-digit limbs, wrong order | point not on the curve |
| `FE_EXP_P58` was `2^252 − 4`, not `2^252 − 3` | square roots wrong by a factor |
| `sc_reduce` read 64 bytes behind a 32-byte parameter, and loaded/stored the wrong endianness | wrong challenge scalar |
| `ge_0` returned all zeros instead of the identity `(0, 1, 1, 0)` | every scalar multiple degenerate, `Z = 0` |
| `ge_scalarmult` used an uninitialised accumulator | depended on the stack arriving zeroed |
| `ge_add` transposed `F` and `G` in `X3`/`Y3` | wrong group law; still on-curve, still satisfied `T·Z == X·Y` |
| The `S < L` malleability check was inverted (`!= 0x80` instead of `== 0`) | rejected every valid signature |
| `ge_double` used `D = A − B` where the curve needs `D = −A` | wrong doubling, indistinguishable from a correct one by self-consistency |

After all of that, every primitive tests correct in isolation — field multiplication against
random 255-bit inputs, the exponentiation against Fermat's theorem for three bases, point
decompression, point addition against an independent reference, the constant-time swap, and
the group invariant `T·Z == X·Y` — and the end-to-end verifier still rejects valid
signatures.

**The deciding factor is the failure direction.** Partway through, a transposed `ge_equal`
made every point comparison return true, and the suite reported *32 passed, 3 failed* — with
the three failures being **forged signatures that had been accepted**. That is the worst
possible outcome for this component: a verifier that is subtly wrong in the permissive
direction silently defeats the one control the architecture exists to provide. Shipping a
crypto component that cannot be shown to reject forgeries is worse than shipping none,
because shipping none fails closed and is visibly inert.

## What is needed to land it safely

1. Keep `mcf_verify_fn` and the fail-closed default. That is already correct and is what
   ships now.
2. Validate any implementation — this one or a vendored third-party one — against
   `ed25519_test.c` with vectors from an independent implementation. Extend the vector set to
   include the RFC 8032 published test vectors, which this directory does not yet carry.
3. Add a negative-path gate to CI: a known-good vector set must be rejected bit-for-bit
   identically by any candidate, and the `cross_test` case that asserts a signed patch is
   refused with no verifier configured must stay green.
4. Prefer vendoring a widely reviewed implementation (libsodium, Mbed TLS, or the
   `ed25519-donna` / TweetNaCl family) over a new one, accepting the licence and the flash
   cost. TweetNaCl is public domain, has no `__int128` dependency, and its verify path is
   short enough to audit by hand — the size objection that applies to a full library does not
   apply to the verify half.

The `mcf_ed25519_verify` signature in `include/microfoam.h` is already the one an integrator
needs, so swapping an implementation in requires no API change.

## Progress update: `sc_reduce` fixed and independently proven

The previous note concluded from pass/fail testing alone that "every primitive tests
correct in isolation yet verification fails". That was the wrong conclusion: the primitives
were not correct, it just was not possible to tell which one from a single bit of output.

`ed_stages.c` decomposes verification into five stages, each independently checkable
against a reference:

| Stage | Function | Status |
|---|---|---|
| 1 | `mcf_sha512(R?A?msg)` | **matches ground truth** |
| 2 | `mcf_ed25519_sc_reduce` | **matches ground truth** |
| 3 | `ge_unpackneg` | **wrong** - the remaining fault |
| 4 | `ge_scalarmult([S]B)` | not yet reached, gated on stage 3 |
| 5 | the assembled comparison | fails, because stage 3 does |

### Two defects found and fixed in `sc_reduce`

**`w[8]` where the loop indexes `w[15]`.** The reduction shifts a 512-bit value in one bit
at a time, and bit `i` lives in word `i / 32`, which reaches index 15. The array had eight
elements, so the second half of every reduction read past the end of it. That is undefined
behaviour, and it failed *permissively* roughly half the time - forged signatures were
accepted. **This was the dangerous defect, and it is why the implementation was rejected
rather than shipped.** The array is now `w[16]`.

**The 512 bits were fed in reversed order.** The accumulator shifts left, so a bit shifted in
early ends up near the top. Feeding the input's least significant bit first therefore
reverses the whole value. The signature of that reversal is unmistakable once seen: feeding
input `1` produced the remainder of `2^511`. Bits are now fed most significant first.

### `sc_reduce` is now proven, not just closer

`ed_reduce_test.c` feeds ten unambiguous 512-bit values and compares against Python's
`% L`. Ten of ten pass, including the cases that pin every part of the algorithm:

| Input | Expected | Meaning |
|---|---|---|
| `0` | `0` | zero |
| `1` | `1` | catches bit-order reversal |
| `L - 1` | `L - 1` | just below the modulus, no subtraction |
| `L` | `0` | exact reduction |
| `L + 1` | `1` | one subtraction |
| `2^511` | `2^511 mod L` | the case the reversal got wrong |
| `2^512 - 1` | `(2^512 - 1) mod L` | many subtractions |

### What remains, isolated to one function

`ge_unpackneg` produces the wrong x-coordinate. Its y-coordinate is correct, so the failure
is in the square root alone, not in the unpacking or the curve parameters. For the vector
above:

```
  y  correct  (1e97198c... matches)
  x  C        7357095c0d81552c795514a40adfd7de05aef6bb0c48d9bf79f7879077cea53a
  x  correct  4d92b6ad6619bdd0f8179fb33b609e6d8d9ee901a652191a3e2f0707727f6377
```

The C's value is neither the correct root nor its negation, so this is a faulty square root
rather than a root-selection mistake. `fe_sqrt_ratio` computes
`x = u�v� � (u�v7)^((p-5)/8)` and then tests `v�x� == u`. The exponent constant and the
identity have both been checked against the specification, so the next step is to test
`fe_sqrt_ratio` directly against a reference for a known quadratic residue, in the same way
`ed_reduce_test.c` does for `sc_reduce` - feed `(u, v)` pairs with known square roots and
compare. That is one bounded test, and it is the same technique that just found both
`sc_reduce` defects after months of pass/fail testing told me nothing.

The two `sc_reduce` defects are the clearest argument in this whole exercise for
stage-by-stage verification over pass/fail. Every earlier note - mine included - asserted
that individual primitives were correct because they appeared to be. They were not. The
only reason this was found is that a stage output could be compared to an independent
reference value.
