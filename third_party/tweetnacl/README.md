# TweetNaCl — vendored, unmodified

Upstream: <https://tweetnacl.cr.yp.to/20140427/tweetnacl.c> and `.../tweetnacl.h` (the
20140427 release).

| File | sha256 |
|---|---|
| `tweetnacl.c` | `02e65bc3013ff2168983365e55906bc783c4c7e0a60d8100f17bb303a17175c4` |
| `tweetnacl.h` | `43f29ad721d9927b747b0100ab4160c119e7bb180c7c98a66e4bf79d31244287` |

**Both files are byte-identical to upstream.** Nothing in this directory edits them. Verify with
`sha256sum third_party/tweetnacl/tweetnacl.*` against the table above; `.gitattributes` pins
them as binary so a Windows checkout cannot rewrite their line endings and invalidate the
comparison.

## Licence

TweetNaCl is **public domain** (released by its authors: Daniel J. Bernstein, Bernard van
Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe and Sjaak Smetsers). No notice is required;
it is recorded here and in the repository `LICENSE` because a vendored crypto primitive should
be traceable to its source.

## Why this library, and why only the primitives

`docs/architecture.md` §14.3 selected Ed25519 for signature verification. A from-scratch
verifier was written for this project and **rejected** (`contrib/ed25519-wip/`): after twelve
fixed defects, one of them permissive — a transposed point comparison that made forged
signatures verify — it could not be shown to reject forgeries reliably. Writing field and group
arithmetic is exactly the part that failed, so that part is now taken from a reviewed
implementation instead of written again.

TweetNaCl is ~700 lines of readable C99, in wide use, and has no `__int128` dependency, which
keeps the armclang/IAR portability target open. It does **not** implement Ed25519ph, which is
what MFP2 needs, and it has no streaming hash, which is what a firmware-sized signed message
needs. `src/mcf_tn_glue.c`, `src/mcf_sha512.c` and `src/mcf_ed25519.c` (all ours, MIT) supply
those on top of these primitives.

## How the primitives are reached, and why a bridge file exists

TweetNaCl keeps its field and group arithmetic in `static` functions, so no separate
translation unit can call them. `src/mcf_tn_glue.c` (ours, MIT, compiled with relaxed warnings
because it contains third-party code) resolves that by including `tweetnacl.c` **textually** and
re-exporting the four operations a verifier needs:

| Exported as | Is |
|---|---|
| `mcf_tn_sha512_init` | SHA-512's standard initial state |
| `mcf_tn_sha512_blocks` | SHA-512's compression function |
| `mcf_tn_sc_reduce` | reduction modulo the group order `L` |
| `mcf_tn_verify_equation` | the group equation `[S]B == R + [h]A`, with the challenge hash supplied by the caller |

Including the file rather than patching it is deliberate: it is the only arrangement that leaves
`tweetnacl.c` byte-identical to upstream while still reaching its internals.

**The bridge deliberately does not check `S < L`.** TweetNaCl's own `crypto_sign_open` omits
that check and libsodium enforces it, so a signature carrying `S + L` satisfies the group
equation and is accepted by one while the other rejects it. Both halves were confirmed by
execution. `src/mcf_ed25519.c` performs the check, and `tests/ed25519_test.c` pins the case.

## The `randombytes` definition

Including `tweetnacl.c` pulls in `crypto_box_keypair` and `crypto_sign_keypair`, which reference
TweetNaCl's `extern void randombytes(u8 *, u64)`. That symbol must resolve for the object to
link, so `src/mcf_tn_glue.c` renames it out of the global namespace with a `#define` before the
include, and defines a version that **fills nothing and returns**.

**It is a trap, deliberately.** This library verifies signatures; it does not generate keys. A
caller that somehow reached key generation through this object would derive a key from
uninitialised memory. Key generation belongs on the build host (the host tool already does it) or
in the application's own CSPRNG, never in the update path. Renaming rather than defining
`randombytes` outright also means a consumer linking its own TweetNaCl cannot hit a
duplicate-symbol error against ours.

## Measured footprint

The verifier path costs **~6.3 KB of flash** on Cortex-M4, not the "~2 KB" that
`docs/architecture.md` originally estimated — TweetNaCl's field arithmetic and the SHA-512
round-constant table are larger than that estimate assumed.

Measured by compiling `src/mcf_ed25519.c`, `src/mcf_sha512.c` and `src/mcf_tn_glue.c` for the
target and linking only the verifier path with `-Wl,--gc-sections`:

| Core | `.text` |
|---|---|
| Cortex-M0 | 6,350 B |
| Cortex-M3 | 6,262 B |
| Cortex-M4 | 6,270 B |
| Cortex-M7 | 6,266 B |

All of TweetNaCl's salsa20, poly1305, `crypto_box` and keypair code is discarded by
`--gc-sections`, so only the ed25519 verify path survives; the remaining bulk is the field
arithmetic (`M`, `modL`, `pack25519`, `car25519`, …) and `crypto_hashblocks`. `docs/architecture.md`
§14.3 and the README carry the corrected figure.
