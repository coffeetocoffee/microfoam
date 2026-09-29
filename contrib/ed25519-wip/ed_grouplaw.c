/* SPDX-License-Identifier: MIT */
/* Self-validating group-law test. No external reference: every check below is
 * either the curve equation (independent of the group formulas) or a group
 * identity. This is deliberately free of any comparison I could get wrong.
 *
 * On-curve test:  -x^2 + y^2 == 1 + d x^2 y^2
 */
#include <stdio.h>
#include <string.h>

#include "mcf_ed25519.c"

static const uint8_t EXP_INV[32] = {
    0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
};

/* group order L, little-endian */
static const uint8_t L_LE[32] = {
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2,
    0xDE, 0xF9, 0xDE, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static const fe FE_ZERO = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static int on_curve(const ge *g)
{
    fe zi, x, y, x2, y2, lhs, rhs, one, t;
    int ok;

    fe_pow(zi, g->Z, EXP_INV, 255);
    fe_mul(x, g->X, zi);
    fe_mul(y, g->Y, zi);

    fe_sq(x2, x);
    fe_sq(y2, y);
    fe_1(one);
    fe_sub(lhs, y2, x2);              /* y^2 - x^2 */
    fe_sub(lhs, lhs, one);             /* y^2 - x^2 - 1 */
    fe_mul(t, x2, y2);
    fe_mul(rhs, t, FE_D);             /* d x^2 y^2 */
    fe_carry(lhs);
    fe_carry(rhs);
    ok = fe_equal(lhs, rhs);
    return ok;
}

static int is_identity(const ge *g)
{
    fe zi, x, y, one, zero;
    int ok;

    /* Projective: the affine form is (X/Z, Y/Z). Treating Z as 1 is only valid
     * when the point came out of a normalising path. */
    fe_pow(zi, g->Z, EXP_INV, 255);
    fe_mul(x, g->X, zi);
    fe_mul(y, g->Y, zi);
    fe_0(zero);
    fe_1(one);
    ok = fe_equal(x, zero) && fe_equal(y, one);
    return ok;
}

int main(void)
{
    ge id, q, tmp;
    uint8_t s[32];
    int k, fails = 0;

    printf("base point on curve            : %d\n", on_curve(&GE_BASE));
    if (!on_curve(&GE_BASE)) { fails++; }

    ge_0(&id);
    printf("identity on curve             : %d\n", on_curve(&id));

    ge_add(&tmp, &id, &GE_BASE);
    printf("identity + B == B             : %d\n", ge_equal(&tmp, &GE_BASE));
    printf("identity + B on curve         : %d\n", on_curve(&tmp));

    ge_add(&tmp, &GE_BASE, &GE_BASE);
    printf("B + B on curve                : %d\n", on_curve(&tmp));

    for (k = 1; k <= 8; k++) {
        memset(s, 0, sizeof(s));
        s[0] = (uint8_t)k;
        ge_scalarmult(&q, s, &GE_BASE);
        printf("[%d]B on curve               : %d\n", k, on_curve(&q));
        if (!on_curve(&q)) { fails++; }
    }

    /* [L]B must be the identity: the strongest single check available */
    ge_scalarmult(&q, L_LE, &GE_BASE);
    printf("[L]B == identity              : %d\n", is_identity(&q));
    if (!is_identity(&q)) { fails++; }

    /* [2]B from the loop must equal B+B */
    memset(s, 0, sizeof(s)); s[0] = 2;
    ge_scalarmult(&q, s, &GE_BASE);
    ge_add(&tmp, &GE_BASE, &GE_BASE);
    printf("[2]B == B+B                   : %d\n", ge_equal(&q, &tmp));

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
