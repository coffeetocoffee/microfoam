/* SPDX-License-Identifier: MIT */
/*
 * Bridge to the vendored TweetNaCl's field and group arithmetic.
 *
 * TweetNaCl keeps those operations in `static` functions, so no separate
 * translation unit can call them. src/mcf_tn_glue.c resolves that by including
 * the vendored source textually and re-exporting the operations below.
 * `third_party/tweetnacl/tweetnacl.c` is never modified; its sha256 is recorded
 * in the adjacent README.
 *
 * Only trivial casts live behind this header. Every line of verification logic
 * stays in src/mcf_ed25519.c, which compiles under the project's full strict
 * warning set - the glue file cannot, because it contains third-party code we do
 * not edit, so nothing that could hide a defect is left in it.
 *
 * `mcf_tn_gf` is deliberately declared `long long[16]` rather than int64_t[16]:
 * that is exactly TweetNaCl's `i64 gf[16]` on every target, so the arrays pass
 * without a cast and no strict-aliasing or type-confusion question arises.
 */
#ifndef MCF_TN_GLUE_H
#define MCF_TN_GLUE_H

#ifdef __cplusplus
extern "C" {
#endif

/*! TweetNaCl's field element: 16 signed 64-bit limbs, little-endian. Opaque to
 *  callers - only ever passed back to these functions. */
typedef long long mcf_tn_gf[16];

/*! SHA-512's standard initial state (64 bytes). */
void mcf_tn_iv(unsigned char state[64]);

/*! SHA-512's compression function: absorb `n` bytes (a multiple of 128) into
 *  `state`. Not a complete hash - padding is the caller's, in mcf_sha512.c. */
void mcf_tn_hashblocks(unsigned char state[64], const unsigned char *m,
                       unsigned long long n);

/*! Reduce a 64-byte little-endian value modulo the group order L in place,
 *  leaving the 32-byte result in r[0..31]. */
void mcf_tn_reduce(unsigned char r[64]);

/*! Decompress a 32-byte encoded point into `r`, negated. Non-zero when the
 *  encoding is not a valid curve point. */
int mcf_tn_unpackneg(mcf_tn_gf r[4], const unsigned char p[32]);

/*! r = p + q. */
void mcf_tn_add(mcf_tn_gf p[4], mcf_tn_gf q[4]);

/*! p = [s]q, then p = [s]B for the base point B. `s` is a 32-byte scalar. */
void mcf_tn_scalarmult(mcf_tn_gf p[4], mcf_tn_gf q[4], const unsigned char *s);
void mcf_tn_scalarbase(mcf_tn_gf p[4], const unsigned char *s);

/*! Encode a group element to 32 bytes. */
void mcf_tn_pack(unsigned char r[32], mcf_tn_gf p[4]);

/*! 0 when the two 32-byte strings are equal. Constant-time inside TweetNaCl. */
int mcf_tn_verify32(const unsigned char *a, const unsigned char *b);

#ifdef __cplusplus
}
#endif

#endif /* MCF_TN_GLUE_H */
