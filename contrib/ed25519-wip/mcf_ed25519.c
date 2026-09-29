/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - Ed25519 signature verification.
 *
 * Device-side verification for the patch container. The firmware authorises a
 * patch by checking its signature against a 32-byte public key shipped in the
 * device image; the private key never leaves the build host.
 *
 * Why this exists: a delta updater is a remote code execution surface. A 32-bit
 * CRC is trivially forgeable, so an update path without a signature is not a
 * finished design. See docs/architecture.md section 14.
 *
 * Design notes
 * ------------
 * Verify only. No signing, so there is no secret scalar to handle and no need
 * for a signing-time blinding path. That is roughly half the code of a full
 * implementation and a meaningful fraction of the flash.
 *
 * Field arithmetic is 16 limbs in radix 2^16, with products accumulated in
 * `int64_t`. Deliberately not 128-bit integers: GCC emits a libgcc call for
 * those, which is both larger and slower on a Cortex-M0, and this library
 * targets that part. Two 16-bit limbs multiply into 32 bits, which fits in
 * int64_t with room to accumulate.
 *
 * Inverses and square roots use a generic square-and-multiply over the
 * exponent rather than a hand-derived addition chain. A chain would be roughly
 * twice as fast, but a chain is exactly the kind of code that is subtly wrong
 * and impossible to review by eye. Here the exponent is a bit pattern and the
 * loop is obvious. The extra cost is a few milliseconds on a Cortex-M0, once
 * per firmware update, which is not a real budget.
 *
 * The point representation and the radix-2^16 field encoding follow the
 * technique popularised by TweetNaCl (public domain). The compression and
 * group equations are from the Ed25519 specification (RFC 8032).
 */

#include "mcf_ed25519.h"

#include <string.h>

/* ======================================================================== *
 * Field arithmetic modulo p = 2^255 - 19
 * ======================================================================== */

typedef int64_t fe[16];

static const fe FE_ONE = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
/* -121665/121666, the curve constant d. */
static const fe FE_D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
/* 2*d */
static const fe FE_D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
/* sqrt(-1) mod p */
static const fe FE_SQRTM1 = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};

static void fe_set(fe r, const fe a)
{
    memcpy(r, a, sizeof(fe));
}

static void fe_0(fe r)
{
    memset(r, 0, sizeof(fe));
}

static void fe_1(fe r)
{
    fe_set(r, FE_ONE);
}

static void fe_add(fe r, const fe a, const fe b)
{
    int i;
    for (i = 0; i < 16; i++) {
        r[i] = a[i] + b[i];
    }
}

static void fe_sub(fe r, const fe a, const fe b)
{
    int i;
    for (i = 0; i < 16; i++) {
        r[i] = a[i] - b[i];
    }
}

/* Constant-time conditional swap. */
static void fe_cswap(fe p, fe q, uint32_t b)
{
    int     i;
    int64_t mask = -((int64_t)(b & 1u));
    for (i = 0; i < 16; i++) {
        int64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/* Propagate carries so every limb fits in 16 bits and the result is below
 * 2^255, folded modulo p.
 *
 * After this, limbs 0..14 are in [0, 2^16) and limb 15 in [0, 2^15), so the
 * value is below 2^255 and congruent to the input modulo p. Keeping that bound
 * is what makes the next fe_mul's accumulation fit in int64_t; an earlier
 * version left limb 0 at around 2^22, and the error only appeared once an
 * exponentiation had accumulated enough rounds to matter.
 *
 * The masking of a possibly-negative value relies on two's complement, which
 * is universal on the targets this library supports. */
static void fe_carry(fe o)
{
    int     i;
    int64_t c, top;

    /* Stage 1: limbs 0..14 into 16-bit form, carrying upward. */
    c = 0;
    for (i = 0; i < 15; i++) {
        int64_t t = o[i] + c;
        o[i] = t & 0xFFFF;
        c = t >> 16;
    }

    /* Stage 2 and on: fold everything at or above 2^255 by 19, then ripple the
     * contribution back up, and repeat until nothing more needs folding.
     *
     * A single fixed number of passes is not enough. Folding pushes limb 0 up,
     * the ripple pushes the next limb up, and after the last pass the excess was
     * being masked off by `& 0x7FFF` - silently discarded rather than folded.
     * That is a slow leak: it leaves small values exact, so 1 and 9 come out
     * right, and corrupts 2 and 4, so a square root of a ratio returns a
     * plausible wrong answer instead of an obvious failure. The loop
     * terminates because each fold removes 19 units and adds back one. */
    for (;;) {
        top = o[15] + c;
        o[15] = top & 0x7FFF;
        c = top >> 15;
        if (c == 0) {
            break;
        }
        o[0] += 19 * c;
        c = 0;
        for (i = 0; i < 15; i++) {
            int64_t t = o[i] + c;
            o[i] = t & 0xFFFF;
            c = t >> 16;
        }
    }
}

static void fe_mul(fe r, const fe a, const fe b)
{
    int64_t t[31];
    int     i, j;

    for (i = 0; i < 31; i++) {
        t[i] = 0;
    }
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
            t[i + j] += a[i] * b[j];
        }
    }
    /* Fold the high half: 2^256 == 38 (mod p). */
    for (i = 0; i < 15; i++) {
        t[i] += 38 * t[i + 16];
    }
    for (i = 0; i < 16; i++) {
        r[i] = t[i];
    }
    fe_carry(r);
}

static void fe_sq(fe r, const fe a)
{
    fe_mul(r, a, a);
}

/* r = a^e, where e is given little-endian in `e[0..(ebits+7)/8)`.
 * Square-and-multiply, most significant bit first. */
static void fe_pow(fe r, const fe a, const uint8_t *e, int ebits)
{
    fe acc;
    int i;

    fe_1(acc);
    for (i = ebits - 1; i >= 0; i--) {
        fe_sq(acc, acc);
        if ((e[i / 8] >> (i & 7)) & 1u) {
            fe_mul(acc, acc, a);
        }
    }
    fe_set(r, acc);
}

/* (p - 5) / 8 = 2^252 - 3, little-endian. The exponent for a square root of a
 * ratio. Low byte 0xFD: 2^252 - 1 is ...FF, minus 2 gives ...FD. */
static const uint8_t FE_EXP_P58[32] = {
    0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F
};

/* r = a^(2^k) */
static void fe_pow22523(fe r, const fe a)
{
    fe_pow(r, a, FE_EXP_P58, 252);
}

/* Serialise to 32 little-endian bytes. */
static void fe_pack25519(uint8_t *o, const fe n)
{
    fe m, t;
    int i, j;

    fe_set(t, n);
    fe_carry(t);
    fe_carry(t);
    fe_carry(t);

    /* Conditionally subtract p twice so the value is canonical. */
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xFFED;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xFFFF;
        }
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
        {
            int64_t b = (m[15] >> 16) & 1;
            m[14] &= 0xFFFF;
            fe_cswap(t, m, (uint32_t)(1 - b));
        }
    }

    /* Mask every limb to 16 bits on the way out. The reduction above is
     * expected to leave them there, but `t[i] >> 8` is written into the next
     * output byte, so a limb one bit too wide corrupts the *following* byte
     * rather than its own - which is why this showed up as a wrong x coordinate
     * with a plausible-looking low byte. */
    for (i = 0; i < 16; i++) {
        uint16_t v = (uint16_t)(t[i] & 0xFFFF);
        o[2 * i]     = (uint8_t)(v & 0xFFu);
        o[2 * i + 1] = (uint8_t)(v >> 8);
    }
}

static void fe_unpack25519(fe o, const uint8_t *n)
{
    int i;
    for (i = 0; i < 16; i++) {
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7FFF;
}

static int fe_equal(const fe a, const fe b)
{
    uint8_t x[32];
    uint8_t y[32];
    int     i;
    uint8_t diff = 0u;

    fe_pack25519(x, a);
    fe_pack25519(y, b);
    for (i = 0; i < 32; i++) {
        diff = (uint8_t)(diff | (x[i] ^ y[i]));
    }
    return (int)(diff == 0u);
}

/* r = sqrt(u / v). Returns 1 on success, 0 when u/v is not a square.
 *
 * Uses  x = u v^3 (u v^7)^((p-5)/8),  which yields a square root of u/v up to
 * sign. The sign is settled by testing v x^2 == u and, if that fails, trying
 * x * sqrt(-1). The identity needs u v^7 = (u v^3) * v^4; multiplying by u
 * instead of v^4 gives a different value that happens to look plausible. */
static int fe_sqrt_ratio(fe r, const fe u, const fe v)
{
    fe v2, v3, v4, uv3, uv7, x, c, t;

    fe_sq(v2, v);
    fe_mul(v3, v2, v);        /* v^3 */
    fe_sq(v4, v2);            /* v^4 */

    fe_mul(uv3, u, v3);       /* u v^3 */
    fe_mul(uv7, uv3, v4);     /* u v^7 */

    fe_pow22523(x, uv7);      /* (u v^7)^((p-5)/8) */
    fe_mul(x, x, uv3);

    fe_sq(c, x);
    fe_mul(c, c, v);
    fe_sub(c, c, u);
    fe_0(t);
    if (!fe_equal(c, t)) {
        fe y;
        fe_mul(y, x, FE_SQRTM1);
        fe_sq(t, y);
        fe_mul(t, t, v);
        fe_sub(t, t, u);
        fe_0(c);
        if (!fe_equal(t, c)) {
            return 0; /* not a square */
        }
        fe_set(x, y);
    }

    fe_set(r, x);
    return 1;
}

/* ======================================================================== *
 * Group arithmetic: twisted Edwards curve, extended coordinates
 * ======================================================================== */

typedef struct {
    fe X, Y, Z, T;
} ge;

/* The standard Ed25519 base point, in 16-bit little-endian limbs.
 *
 *   x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
 *   y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
 *
 * T is x*y. These were generated from the coordinates above rather than
 * transcribed, after a hand-copied table turned out to be off by a shift. */
static const ge GE_BASE = {
    {0xD51A, 0x8F25, 0x2D60, 0xC956, 0xA7B2, 0x9525, 0xC760, 0x692C,
     0xDC5C, 0xFDD6, 0xE231, 0xC0A4, 0x53FE, 0xCD6E, 0x36D3, 0x2169},
    {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
     0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0xDDA3, 0xA5B7, 0x8AB3, 0x6DDE, 0x52F5, 0x7751, 0x9F80, 0x20F0,
     0xE37D, 0x64AB, 0x4E8E, 0x66EA, 0x7665, 0xD78B, 0x5F0F, 0x6787}
};

/* The neutral element in extended coordinates is (0, 1, 1, 0), not all zeros.
 * Getting this wrong does not fault; it makes every scalar multiple collapse
 * to a degenerate point with Z = 0, and a comparison between two such points
 * then succeeds for the wrong reason. */
static void ge_0(ge *r)
{
    int i;

    for (i = 0; i < 16; i++) {
        r->X[i] = 0;
        r->T[i] = 0;
    }
    for (i = 0; i < 16; i++) {
        r->Y[i] = 0;
        r->Z[i] = 0;
    }
    r->Y[0] = 1;
    r->Z[0] = 1;
    fe_carry(r->Y);
    fe_carry(r->Z);
}

static void ge_copy(ge *r, const ge *p)
{
    memcpy(r, p, sizeof(*r));
}

static void ge_cswap(ge *p, ge *q, uint32_t b)
{
    fe_cswap(p->X, q->X, b);
    fe_cswap(p->Y, q->Y, b);
    fe_cswap(p->Z, q->Z, b);
    fe_cswap(p->T, q->T, b);
}

/* r = p + q, extended coordinates, a = -1.
 *
 *   A = (Y1-X1)(Y2-X2)   B = (Y1+X1)(Y2+X2)   C = 2d*T1*T2   D = 2*Z1*Z2
 *   E = B-A   F = D-C   G = D+C   H = B+A
 *   X3 = E*F   Y3 = G*H   T3 = E*H   Z3 = F*G
 *
 * x3 = E/G (x's denominator is 1 + d*x1x2y1y2, which is proportional to G) and
 * y3 = H/F. With Z3 = F*G those become X3 = E*F and Y3 = G*H. Transposing the
 * F and G in the last line still yields a point that is on the curve and
 * satisfies T*Z == X*Y, so structural tests pass while the group law is wrong. */
static void ge_add(ge *r, const ge *p, const ge *q)
{
    fe a, b, c, d, e, f, g, h, t;

    fe_sub(a, p->Y, p->X);
    fe_sub(t, q->Y, q->X);
    fe_mul(a, a, t);

    fe_add(b, p->Y, p->X);
    fe_add(t, q->Y, q->X);
    fe_mul(b, b, t);

    fe_mul(c, p->T, q->T);
    fe_mul(c, c, FE_D2);

    fe_mul(d, p->Z, q->Z);
    fe_add(d, d, d);

    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);

    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

/* r = 2p.
 *
 * Defined in terms of ge_add rather than through a dedicated doubling formula.
 * The dedicated formulas are meaningfully faster, but they are a separate
 * derivation that has to agree with the addition formulas to the bit, and a
 * mistake in one of them produces a point that is still on the curve and still
 * satisfies T*Z == X*Y - so it passes every structural test while computing the
 * wrong group element. Sharing the addition path makes that class of bug
 * impossible.
 *
 * Cost: one extra point addition per doubling, roughly 20% on a scalar
 * multiplication. Verification runs once per firmware update, so this is
 * invisible next to the risk it removes. */
static void ge_double(ge *r, const ge *p)
{
    ge_add(r, p, p);
}

/* r = a * p, most significant bit first, with a constant-time select.
 *
 * The loop invariant is sum = (bits of a processed so far) * p, and each
 * iteration applies sum = 2*sum + bit*p. Computing both candidates and
 * selecting costs one addition more per bit than the textbook form, but the
 * textbook form needs an accumulator whose initial value is easy to leave
 * uninitialised, and a verifier must not depend on the stack arriving zeroed.
 *
 * Verification uses only public data, so a timing leak here would not expose a
 * secret; the select is kept anyway because it costs nothing and removes the
 * question. */
static void ge_scalarmult(ge *r, const uint8_t *a, const ge *p)
{
    ge sum;
    ge d;
    ge t;
    int i;

    ge_0(&sum);

    for (i = 255; i >= 0; i--) {
        uint32_t bit = (uint32_t)((a[i / 8] >> (i & 7)) & 1u);

        ge_double(&d, &sum);      /* d = 2*sum     */
        ge_add(&t, &d, p);        /* t = 2*sum + P */
        ge_cswap(&d, &t, bit);    /* d = bit ? t : d */
        ge_copy(&sum, &d);
    }

    ge_copy(r, &sum);
}

/* Projective equality: a == b iff X_a Z_b == X_b Z_a and Y_a Z_b == Y_b Z_a.
 * Avoids the field inversions that comparing serialised points would need. */
static int ge_equal(const ge *a, const ge *b)
{
    fe x1, x2, y1, y2;
    int ok;

    fe_mul(x1, a->X, b->Z);
    fe_mul(x2, b->X, a->Z);
    ok = fe_equal(x1, x2);
    fe_mul(y1, a->Y, b->Z);
    fe_mul(y2, b->Y, a->Z);
    ok &= fe_equal(y1, y2);
    return ok;
}

/* Decompress a 32-byte point encoding into r, with r negated so that callers
 * can use the cheap addition formulas. Returns 0 on success. */
static int ge_unpackneg(ge *r, const uint8_t p[32])
{
    fe t, chk, num, den;
    uint8_t sign;

    fe_unpack25519(r->Y, p);
    sign = (uint8_t)(p[31] >> 7);
    fe_1(r->Z);

    /* x^2 = (y^2 - 1) / (d y^2 + 1)
     *
     * fe_sub and fe_add deliberately do not reduce, so both results carry limbs
     * outside [0, 2^16) - a borrow from a zero limb makes them negative.
     * fe_sqrt_ratio is specified and tested on reduced operands, so reduce here
     * rather than pushing unreduced values into the exponentiation and hoping
     * every step tolerates them. */
    fe_sq(num, r->Y);
    fe_1(t);
    fe_sub(num, num, t);
    fe_carry(num);

    fe_sq(den, r->Y);
    fe_mul(den, den, FE_D);
    fe_1(t);
    fe_add(den, den, t);
    fe_carry(den);

    if (!fe_sqrt_ratio(chk, num, den)) {
        return -1; /* not a valid curve point */
    }
    fe_set(r->X, chk);

    /* If the computed x has the wrong parity, take the other root.
     *
     * The negation must be carried. fe_sub does not reduce, so 0 - X leaves
     * negative limbs, and fe_pack25519 - like the rest of the field layer - is
     * only correct on reduced input. Left unreduced, the negation reads back as
     * the same value, so the point comes out valid but with the wrong sign bit
     * and the signature then fails for no visible reason. */
    {
        uint8_t xb[32];
        fe_pack25519(xb, r->X);
        if (((xb[0] & 1u) ^ (uint32_t)sign) != 0u) {
            fe neg;
            fe_0(neg);
            fe_sub(neg, neg, r->X);
            fe_carry(neg);
            fe_set(r->X, neg);
        }
    }

    fe_mul(r->T, r->X, r->Y);
    return 0;
}

/* ======================================================================== *
 * SHA-512 (FIPS 180-4)
 * ======================================================================== */

static const uint64_t SHA512_K[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,

    0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,

    0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL,

    0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,

    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,

    0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,

    0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL,

    0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,

    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,

    0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,

    0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL,

    0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,

    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,

    0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,

    0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,

    0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,

    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,

    0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,

    0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL,

    0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,

    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,

    0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,

    0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL,

    0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,

    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,

    0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,

    0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL,
};

static uint64_t ror64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64u - n));
}

static void sha512_block(uint64_t h[8], const uint8_t *p)
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, hh;
    int      i, j;

    for (i = 0; i < 16; i++) {
        w[i] = 0;
        for (j = 0; j < 8; j++) {
            w[i] = (w[i] << 8) | (uint64_t)p[i * 8 + j];
        }
    }
    for (i = 16; i < 80; i++) {
        uint64_t s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 80; i++) {
        uint64_t S1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t t1 = hh + S1 + ch + SHA512_K[i] + w[i];
        uint64_t S0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
        uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + mj;

        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void mcf_sha512(uint8_t out[64], const uint8_t *msg, uint32_t len)
{
    uint64_t h[8];
    uint8_t  block[128];
    uint32_t full = len / 128u;
    uint32_t rem  = len % 128u;
    uint32_t i;
    uint8_t  j;
    uint64_t bits = (uint64_t)len * 8u;

    h[0] = 0x6A09E667F3BCC908ULL; h[1] = 0xBB67AE8584CAA73BULL;
    h[2] = 0x3C6EF372FE94F82BULL; h[3] = 0xA54FF53A5F1D36F1ULL;
    h[4] = 0x510E527FADE682D1ULL; h[5] = 0x9B05688C2B3E6C1FULL;
    h[6] = 0x1F83D9ABFB41BD6BULL; h[7] = 0x5BE0CD19137E2179ULL;

    for (i = 0; i < full; i++) {
        sha512_block(h, &msg[i * 128u]);
    }

    memset(block, 0, sizeof(block));
    if (rem > 0u) {
        memcpy(block, &msg[full * 128u], rem);
    }
    block[rem] = 0x80u;

    if (rem + 1u + 16u > 128u) {
        sha512_block(h, block);
        memset(block, 0, sizeof(block));
    }
    /* 128-bit big-endian bit length, written to the LOW 8 bytes of the field.
     * Bytes 112..119 hold the high word, which stays zero for any message this
     * library will ever hash: reaching it needs a message of 2^61 bytes. */
    for (j = 0; j < 8u; j++) {
        block[120u + j] = (uint8_t)(bits >> (56u - 8u * j));
    }
    sha512_block(h, block);

    for (i = 0; i < 8u; i++) {
        for (j = 0; j < 8u; j++) {
            out[i * 8u + j] = (uint8_t)(h[i] >> (56u - 8u * j));
        }
    }
}

/* ======================================================================== *
 * Scalar reduction modulo L, the group order
 *
 *     L = 2^252 + 27742317777372353535851937790883648493
 *
 * Schoolbook: shift the 512-bit value in one bit at a time, subtracting L
 * whenever the running remainder reaches it. 512 iterations of an eight-word
 * compare-and-subtract. Slower than a Barrett reduction by a wide margin, but
 * it is about fifteen lines, has no magic constants beyond L itself, and is
 * straightforward to verify. It runs once per signature check.
 *
 * The remainder always stays below L < 2^253, so after one shift it is below
 * 2^254 and the eight-word accumulator cannot overflow.
 * ======================================================================== */

static const uint32_t SC_L[8] = {
    0x5CF5D3EDu, 0x5812631Au, 0xA2F79CD6u, 0x14DEF9DEu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x10000000u
};

/* Non-zero when the eight-word value is >= L. */
static int ge_sc_ge_l_words(const uint32_t a[8])
{
    int32_t borrow = 0;
    int     i;

    for (i = 0; i < 8; i++) {
        int64_t d = (int64_t)a[i] - (int64_t)SC_L[i] - borrow;
        if (d < 0) {
            d += (int64_t)1 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
    }
    return (borrow == 0);
}

/* Non-zero when the 32-byte little-endian value is >= L. Used both to drive the
 * reduction and to reject a non-canonical signature scalar.
 *
 * Rejecting S >= L is what closes the classic Ed25519 malleability hole: since
 * L*B is the identity, (S + L, R) satisfies the same verification equation as
 * (S, R), so without this check a signed patch could be re-encoded endlessly. */
static int ge_sc_ge_l(const uint8_t s[32])
{
    uint32_t a[8];
    int32_t  borrow = 0;
    uint32_t i, b;

    for (i = 0; i < 8; i++) {
        uint32_t w = 0;
        for (b = 0; b < 4; b++) {
            w |= (uint32_t)s[i * 4u + b] << (8u * b);
        }
        a[i] = w;
    }

    for (i = 0; i < 8; i++) {
        int64_t d = (int64_t)a[i] - (int64_t)SC_L[i] - borrow;
        if (d < 0) {
            d += (int64_t)1 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
    }
    return (borrow == 0); /* a >= L */
}

static void ge_sc_sub_l(uint32_t a[8])
{
    int32_t borrow = 0;
    int     i;

    for (i = 0; i < 8; i++) {
        int64_t d = (int64_t)a[i] - (int64_t)SC_L[i] - borrow;
        if (d < 0) {
            d += (int64_t)1 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[i] = (uint32_t)d;
    }
}

void mcf_ed25519_sc_reduce(uint8_t out[32], const uint8_t in[64])
{
    uint32_t acc[8];
    uint32_t w[16];
    uint32_t i, k, b;

    /* Load the 64-byte little-endian input as sixteen 32-bit words.
     *
     * Sixteen, not eight: the reduction loop indexes w[i / 32] for i up to 511,
     * which reaches index 15. With only eight words the last half of the shift
     * read past the end of the array, so the challenge scalar came out of
     * whatever followed on the stack. That is undefined behaviour, and it fails
     * *permissively* roughly half the time, which is the worst possible failure
     * direction for a verifier: forged signatures were accepted. */
    for (k = 0; k < 16; k++) {
        uint32_t base = (uint32_t)k * 4u;
        uint64_t v    = 0;
        for (b = 0; b < 4; b++) {
            v |= (uint64_t)in[base + (uint32_t)b] << (8 * b);
        }
        w[k] = (uint32_t)v;
    }

    memset(acc, 0, sizeof(acc));

    /* Shift the 512-bit value in one bit at a time, subtracting L whenever
     * the running remainder reaches it. The remainder stays below L < 2^253,
     * so after one shift it is below 2^254 and the accumulator cannot overflow.
     *
     * Most significant bit first. The accumulator shifts left, so a bit shifted
     * in early ends up near the top: feeding the input's LSB first reverses the
     * entire 512-bit value. Feeding input 1 then produces the remainder of
     * 2^511, which is the signature of that reversal and looks like nothing
     * being wrong. */
    for (i = 512; i-- > 0; ) {
        uint32_t bit   = (w[i / 32u] >> (i % 32u)) & 1u;
        uint32_t carry = bit;
        uint32_t kk;

        for (kk = 0; kk < 8; kk++) {
            uint32_t next = acc[kk] >> 31;
            acc[kk] = (acc[kk] << 1) | carry;
            carry = next;
        }
        if (ge_sc_ge_l_words(acc)) {
            ge_sc_sub_l(acc);
        }
    }

    for (i = 0; i < 8; i++) {
        out[i * 4u + 0u] = (uint8_t)(acc[i]);
        out[i * 4u + 1u] = (uint8_t)(acc[i] >> 8);
        out[i * 4u + 2u] = (uint8_t)(acc[i] >> 16);
        out[i * 4u + 3u] = (uint8_t)(acc[i] >> 24);
    }
}

/* ======================================================================== *
 * Verification
 * ======================================================================== */

int mcf_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, uint32_t msg_len,
                       const uint8_t public_key[32])
{
    ge      A, R, sB, kA, sum;
    uint8_t hram[64];
    uint8_t buf[64];
    uint8_t acc;
    uint32_t i;

    if (sig == NULL || msg == NULL || public_key == NULL) {
        return 0;
    }

    /* All-zero signature or key is always invalid, and detecting it early keeps
     * the degenerate encodings out of the curve code. */
    acc = 0u;
    for (i = 0; i < 64u; i++) {
        acc = (uint8_t)(acc | sig[i]);
    }
    if (acc == 0u) {
        return 0;
    }
    acc = 0u;
    for (i = 0; i < 32u; i++) {
        acc = (uint8_t)(acc | public_key[i]);
    }
    if (acc == 0u) {
        return 0;
    }

    /* The scalar S must be canonical, i.e. S < L. Without this, (S + L, R) is
     * also a valid signature because L*B is the identity, which makes signed
     * patches infinitely malleable. */
    if (ge_sc_ge_l(sig + 32)) {
        return 0;
    }

    if (ge_unpackneg(&A, public_key) != 0) {
        return 0;
    }
    if (ge_unpackneg(&R, sig) != 0) {
        return 0;
    }

    /* k = SHA512(R || A || msg) mod L.
     *
     * R || A is exactly 64 bytes, so it is already one SHA-512 block; the
     * message is appended and the length covers 64 + msg_len. Streaming avoids
     * copying the patch into a scratch buffer. */
    {
        uint8_t  digest[64];
        uint64_t h[8];
        uint8_t  tail[128];
        uint32_t n     = msg_len;
        uint32_t off   = 0u;
        uint64_t bits;
        uint32_t j;

        memcpy(buf, sig, 32);
        memcpy(buf + 32, public_key, 32);

        h[0] = 0x6A09E667F3BCC908ULL; h[1] = 0xBB67AE8584CAA73BULL;
        h[2] = 0x3C6EF372FE94F82BULL; h[3] = 0xA54FF53A5F1D36F1ULL;
        h[4] = 0x510E527FADE682D1ULL; h[5] = 0x9B05688C2B3E6C1FULL;
        h[6] = 0x1F83D9ABFB41BD6BULL; h[7] = 0x5BE0CD19137E2179ULL;

        sha512_block(h, buf);

        while (n - off >= 128u) {
            sha512_block(h, &msg[off]);
            off += 128u;
        }

        memset(tail, 0, sizeof(tail));
        n -= off;
        if (n > 0u) {
            memcpy(tail, &msg[off], n);
        }
        tail[n] = 0x80u;
        if (n + 1u + 16u > 128u) {
            sha512_block(h, tail);
            memset(tail, 0, sizeof(tail));
        }
        bits = ((uint64_t)msg_len + 64u) * 8u;
        for (j = 0; j < 8u; j++) {
            tail[120u + j] = (uint8_t)(bits >> (56u - 8u * j));
        }
        sha512_block(h, tail);

        for (i = 0; i < 8u; i++) {
            for (j = 0; j < 8u; j++) {
                digest[i * 8u + j] = (uint8_t)(h[i] >> (56u - 8u * j));
            }
        }
        memcpy(hram, digest, 32u);
    }
    mcf_ed25519_sc_reduce(hram, hram);

    /* [S]B == R + [k]A */
    ge_scalarmult(&sB, sig + 32, &GE_BASE);
    ge_scalarmult(&kA, hram, &A);
    ge_add(&sum, &R, &kA);

    return ge_equal(&sB, &sum);
}
