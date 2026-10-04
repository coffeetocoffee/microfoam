/* SPDX-License-Identifier: MIT */
/*
 * Bridge to the vendored TweetNaCl. Compiled with warnings suppressed, because
 * it contains third-party code we do not edit: tweetnacl.c triggers
 * -Wsign-compare in its FOR macro and -Wunterminated-string-initialization on
 * its salsa20 sigma constant, and neither is ours to fix. Suppressing warnings
 * for this file alone is what keeps the project's build output clean, so a real
 * warning in our own code stays visible.
 *
 * Nothing but casts lives here. All verification logic is in src/mcf_ed25519.c,
 * which compiles under the full strict set.
 *
 * The vendored file is included textually and never modified; the sha256 of both
 * vendored files is in third_party/tweetnacl/README.md. Including it is the only
 * arrangement that reaches TweetNaCl's `static` primitives while leaving it
 * byte-identical to upstream.
 */
#include "mcf_tn_glue.h"

/* TweetNaCl declares `extern void randombytes(u8 *, u64)` and calls it from its
 * keypair functions. A verifier never calls those, but the symbol has to resolve
 * for this object to link. Renaming it before the include keeps it out of the
 * global namespace, so a consumer linking its own TweetNaCl cannot hit a
 * duplicate-symbol error against ours. */
#define randombytes mcf_tn_randombytes_unused

#include "tweetnacl.c"

/* Defined rather than left undefined so the object is self-contained even
 * without --gc-sections. It writes nothing, deliberately: reaching it would mean
 * something asked this library to GENERATE a key, which is not a thing a
 * verifier does and must not silently appear to succeed at. Key generation
 * belongs on the build host (the host tool does it) or in the application's own
 * CSPRNG. */
void mcf_tn_randombytes_unused(unsigned char *x, unsigned long long n)
{
    (void)x;
    (void)n;
}

void mcf_tn_iv(unsigned char state[64])
{
    int i;
    FOR(i, 64) {
        state[i] = iv[i];
    }
}

void mcf_tn_hashblocks(unsigned char state[64], const unsigned char *m,
                       unsigned long long n)
{
    (void)crypto_hashblocks(state, m, n);
}

void mcf_tn_reduce(unsigned char r[64])
{
    reduce(r);
}

int mcf_tn_unpackneg(mcf_tn_gf r[4], const unsigned char p[32])
{
    return unpackneg(r, p);
}

void mcf_tn_add(mcf_tn_gf p[4], mcf_tn_gf q[4])
{
    add(p, q);
}

void mcf_tn_scalarmult(mcf_tn_gf p[4], mcf_tn_gf q[4], const unsigned char *s)
{
    scalarmult(p, q, s);
}

void mcf_tn_scalarbase(mcf_tn_gf p[4], const unsigned char *s)
{
    scalarbase(p, s);
}

void mcf_tn_pack(unsigned char r[32], mcf_tn_gf p[4])
{
    pack(r, p);
}

int mcf_tn_verify32(const unsigned char *a, const unsigned char *b)
{
    return crypto_verify_32(a, b);
}
