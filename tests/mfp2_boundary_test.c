/* SPDX-License-Identifier: MIT */
/* MFP2 producer-to-session integration test using direct libsodium callbacks. */
#include "microfoam.h"
#include "microfoam_v2.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLASH_SIZE (128u * 1024u)
#define FLASH_BASE 0x08010000u
#define BLOCK_SIZE 1024u

static uint8_t flash[FLASH_SIZE];
static uint8_t workspace[FLASH_SIZE];
static unsigned mutations;

typedef struct crypto_ctx {
    uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
    uint8_t symmetric_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t key_id[MCF_V2_KEY_ID_SIZE];
} crypto_ctx_t;

static int flash_range(uint32_t addr, uint32_t len, uint32_t *off)
{
    if (addr < FLASH_BASE || addr - FLASH_BASE > FLASH_SIZE ||
        len > FLASH_SIZE - (addr - FLASH_BASE)) return 0;
    *off = addr - FLASH_BASE;
    return 1;
}
static int32_t flash_erase(void *ctx, uint32_t addr, uint32_t len)
{
    uint32_t off; (void)ctx;
    if (!flash_range(addr, len, &off)) return MCF_E_FLASH;
    memset(&flash[off], 0xFF, len); mutations++; return MCF_OK;
}
static int32_t flash_write(void *ctx, uint32_t addr, const uint8_t *p, uint32_t len)
{
    uint32_t off; (void)ctx;
    if (p == NULL || !flash_range(addr, len, &off)) return MCF_E_FLASH;
    memcpy(&flash[off], p, len); mutations++; return MCF_OK;
}
static int32_t flash_read(void *ctx, uint32_t addr, uint8_t *p, uint32_t len)
{
    uint32_t off; (void)ctx;
    if (p == NULL || !flash_range(addr, len, &off)) return MCF_E_FLASH;
    memcpy(p, &flash[off], len); return (int32_t)len;
}
static uint32_t block_size(void *ctx) { (void)ctx; return BLOCK_SIZE; }
static uint32_t product(void *ctx) { (void)ctx; return 0x1234u; }
static uint32_t version(void *ctx) { (void)ctx; return 0x00010000u; }
static void *alloc_ram(void *ctx, uint32_t n) { (void)ctx; return malloc(n); }
static void free_ram(void *ctx, void *p) { (void)ctx; free(p); }

static const mcf_hal_t hal = {
    flash_erase, flash_write, flash_read, block_size, NULL,
    alloc_ram, free_ram, product, version, NULL, NULL, NULL
};

static mcf_status_t provide_key(void *ctx, const uint8_t id[MCF_V2_KEY_ID_SIZE],
                                uint8_t out[MCF_V2_KEY_SIZE])
{
    crypto_ctx_t *c = (crypto_ctx_t *)ctx;
    if (memcmp(id, c->key_id, MCF_V2_KEY_ID_SIZE) != 0) return MCF_E_AUTH;
    memcpy(out, c->symmetric_key, MCF_V2_KEY_SIZE); return MCF_OK;
}
static int32_t verify_ed25519ph(void *ctx, const uint8_t *sig, uint32_t sig_len,
                                const uint8_t *a, uint32_t an, const uint8_t *b,
                                uint32_t bn, const uint8_t *c, uint32_t cn)
{
    crypto_ctx_t *x = (crypto_ctx_t *)ctx;
    crypto_sign_ed25519ph_state st;
    if (sig == NULL || sig_len != crypto_sign_BYTES ||
        (a == NULL && an) || (b == NULL && bn) || (c == NULL && cn)) return MCF_E_PARAM;
    if (crypto_sign_ed25519ph_init(&st) != 0 ||
        (an && crypto_sign_ed25519ph_update(&st, a, an) != 0) ||
        (bn && crypto_sign_ed25519ph_update(&st, b, bn) != 0) ||
        (cn && crypto_sign_ed25519ph_update(&st, c, cn) != 0)) return MCF_E_SIGNATURE;
    return crypto_sign_ed25519ph_final_verify(&st, sig, x->public_key) == 0
           ? MCF_OK : MCF_E_SIGNATURE;
}
static int32_t decrypt_aead(void *ctx, const uint8_t *key, const uint8_t nonce[24],
                            const uint8_t *cipher, uint32_t n, const uint8_t *tag,
                            uint32_t tag_n, const uint8_t *ad, uint32_t ad_n,
                            uint8_t *plain)
{
    (void)ctx;
    if (tag_n != crypto_aead_xchacha20poly1305_ietf_ABYTES) return MCF_E_PARAM;
    return crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        plain, NULL, cipher, (unsigned long long)n, tag, ad,
        (unsigned long long)ad_n, nonce, key) == 0 ? MCF_OK : MCF_E_AUTH;
}

static uint8_t *read_file(const char *path, uint32_t *size)
{
    FILE *f = fopen(path, "rb"); long n; uint8_t *p;
    if (!f || fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) { if (f) fclose(f); return NULL; }
    p = (uint8_t *)malloc((size_t)n);
    if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) { free(p); fclose(f); return NULL; }
    fclose(f); *size = (uint32_t)n; return p;
}
static int run_patch(const uint8_t *patch, uint32_t patch_len, const uint8_t *old, uint32_t old_len,
                     crypto_ctx_t *crypto)
{
    mcf_v2_config_t cfg; mcf_v2_session_t s; mcf_status_t st;
    memset(&cfg, 0, sizeof(cfg));
    cfg.hal = &hal; cfg.patch = patch; cfg.patch_size = patch_len;
    cfg.old = old; cfg.old_size = old_len; cfg.dst_addr = FLASH_BASE;
    cfg.block_size = BLOCK_SIZE; cfg.ram_budget = sizeof(workspace);
    cfg.workspace = workspace; cfg.workspace_size = sizeof(workspace);
    cfg.key_provider = provide_key; cfg.key_ctx = crypto;
    cfg.verify = verify_ed25519ph; cfg.verify_ctx = crypto;
    cfg.aead = decrypt_aead; cfg.aead_ctx = crypto;
    st = mcf_v2_session_open(&s, &cfg);
    if (st == MCF_OK) st = mcf_v2_session_run(&s);
    mcf_v2_session_close(&s);
    return st;
}

/* Differential proof of the streaming design: the same patch must apply
 * byte-exact in a workspace far smaller than the whole decrypted payload,
 * which the pre-streaming "decrypt every record into scratch" design
 * required. The computed `old_need` is the size that design needed. */
static int streaming_workspace_case(const uint8_t *patch, uint32_t patch_len,
                                    const uint8_t *old, uint32_t old_len,
                                    const uint8_t *expected, uint32_t new_len,
                                    crypto_ctx_t *crypto)
{
    static uint8_t small[4096];
    mcf_v2_view_t view;
    mcf_v2_config_t cfg; mcf_v2_session_t s; mcf_status_t st;
    uint32_t win, ad, inner_ws, need, old_need;

    if (mcf_v2_parse(patch, patch_len, &view) != MCF_OK) return 0;
    win      = (2u * (1u << view.record_log2)) + 4u;
    ad       = 8u + (uint32_t)view.header_len + 8u;
    inner_ws = (2u * (1u << view.record_log2)) + 16u;
    need     = 124u + win + ad + inner_ws;
    old_need = 124u + view.payload_size + inner_ws;
    if (need >= old_need) {
        fprintf(stderr, "streaming workspace %u is not below whole-payload %u\n",
                (unsigned)need, (unsigned)old_need);
        return 0;
    }
    if (need > sizeof(small) || old_need <= sizeof(small)) {
        fprintf(stderr, "workspace case not discriminating (need=%u old=%u buf=%u)\n",
                (unsigned)need, (unsigned)old_need, (unsigned)sizeof(small));
        return 0;
    }

    memset(flash, 0xFF, sizeof(flash)); mutations = 0;
    memset(&cfg, 0, sizeof(cfg));
    cfg.hal = &hal; cfg.patch = patch; cfg.patch_size = patch_len;
    cfg.old = old; cfg.old_size = old_len; cfg.dst_addr = FLASH_BASE;
    cfg.block_size = BLOCK_SIZE;
    cfg.ram_budget = (uint32_t)sizeof(small);
    cfg.workspace = small; cfg.workspace_size = (uint32_t)sizeof(small);
    cfg.key_provider = provide_key; cfg.key_ctx = crypto;
    cfg.verify = verify_ed25519ph; cfg.verify_ctx = crypto;
    cfg.aead = decrypt_aead; cfg.aead_ctx = crypto;
    st = mcf_v2_session_open(&s, &cfg);
    if (st == MCF_OK) st = mcf_v2_session_run(&s);
    mcf_v2_session_close(&s);
    if (st != MCF_OK) {
        fprintf(stderr, "streaming-workspace run failed: status %d\n", (int)st);
        return 0;
    }
    if (memcmp(flash, expected, new_len) != 0) {
        fprintf(stderr, "streaming-workspace image is not byte-exact\n");
        return 0;
    }
    /* The streaming feed is a separate apply route from run_patch(), so it has
     * to prove it programs flash too - otherwise its tamper assertions would be
     * as vacuous as a counter that cannot move. */
    if (mutations == 0u) {
        fprintf(stderr, "streaming path programmed no flash\n");
        return 0;
    }
    printf("  ok  applies in %u-byte workspace (whole-payload design needed %u)\n",
           (unsigned)need, (unsigned)old_need);
    return 1;
}

static int expect_case(const char *name, const uint8_t *patch, uint32_t patch_len,
                       const uint8_t *flash_fill, mcf_status_t want, crypto_ctx_t *crypto,
                       const uint8_t *old, uint32_t old_len)
{
    mcf_status_t st;
    memset(flash, 0xFF, sizeof(flash));
    if (flash_fill) memcpy(flash, flash_fill, sizeof(flash));
    mutations = 0;
    st = run_patch(patch, patch_len, old, old_len, crypto);
    if (st == MCF_OK) {
        fprintf(stderr, "%s: expected rejection, session succeeded\n", name);
        return 0;
    }
    /* The status is pinned exactly. Accepting any non-OK status is how a case
     * that dies for the wrong reason keeps reporting ok, which is exactly what
     * the re-signed fixtures below exist to prevent. */
    if ((int32_t)st != (int32_t)want) {
        fprintf(stderr, "%s: status %d, expected %d\n", name, (int)st, (int)want);
        return 0;
    }
    if (mutations != 0u) {
        fprintf(stderr, "%s: %u flash mutations on a pre-application failure\n",
                name, mutations);
        return 0;
    }
    printf("  ok  %-24s (status %d)\n", name, (int)st);
    return 1;
}

/* ---------------------------------------------------------------------- *
 * Resume. A run is interrupted on a checkpoint boundary; a fresh session then
 * probes the journal and continues. The journal region is a separate NVM area
 * outside the destination, mirroring a real part.
 * ---------------------------------------------------------------------- */

#define JOURNAL_BASE 0x08100000u
#define JOURNAL_SIZE 256u

static uint8_t journal[JOURNAL_SIZE];
static unsigned journal_mutations;

/* Wrappers around the main flash HAL that divert the journal region. The
 * destination and journal are disjoint address ranges, so the split is by
 * address and the shared `flash` array is untouched by journal traffic. */
static int32_t j_erase(void *ctx, uint32_t addr, uint32_t len)
{
    (void)ctx;
    if (addr >= JOURNAL_BASE && addr < JOURNAL_BASE + JOURNAL_SIZE) {
        if (len > JOURNAL_SIZE) return MCF_E_FLASH;
        memset(journal, 0xFF, JOURNAL_SIZE);
        journal_mutations++;
        return MCF_OK;
    }
    return flash_erase(ctx, addr, len);
}
static int32_t j_write(void *ctx, uint32_t addr, const uint8_t *p, uint32_t len)
{
    (void)ctx;
    if (addr >= JOURNAL_BASE && addr < JOURNAL_BASE + JOURNAL_SIZE) {
        if (len > JOURNAL_SIZE) return MCF_E_FLASH;
        memcpy(journal, p, len);
        journal_mutations++;
        return MCF_OK;
    }
    return flash_write(ctx, addr, p, len);
}
static int32_t j_read(void *ctx, uint32_t addr, uint8_t *p, uint32_t len)
{
    (void)ctx;
    if (addr >= JOURNAL_BASE && addr < JOURNAL_BASE + JOURNAL_SIZE) {
        if (len > JOURNAL_SIZE) return MCF_E_IO;
        memcpy(p, journal, len);
        return (int32_t)len;
    }
    return flash_read(ctx, addr, p, len);
}

static const mcf_hal_t jhal = {
    j_erase, j_write, j_read, block_size, NULL,
    alloc_ram, free_ram, product, version, NULL, NULL, NULL
};

static void v2_cfg(mcf_v2_config_t *cfg, const uint8_t *patch, uint32_t patch_len,
                   const uint8_t *old, uint32_t old_len, crypto_ctx_t *crypto,
                   uint32_t journal_addr)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->hal = &jhal; cfg->patch = patch; cfg->patch_size = patch_len;
    cfg->old = old; cfg->old_size = old_len; cfg->dst_addr = FLASH_BASE;
    cfg->block_size = BLOCK_SIZE; cfg->ram_budget = sizeof(workspace);
    cfg->workspace = workspace; cfg->workspace_size = sizeof(workspace);
    cfg->key_provider = provide_key; cfg->key_ctx = crypto;
    cfg->verify = verify_ed25519ph; cfg->verify_ctx = crypto;
    cfg->aead = decrypt_aead; cfg->aead_ctx = crypto;
    cfg->journal_addr = journal_addr;
    cfg->journal_interval = 1u;
}

/* Run `steps` inner steps, then abandon the session as a power cut would.
 * `out_flags` receives the session flags at the moment of the cut (may be
 * NULL); the advancing-journal case below needs to see whether checkpointing
 * degraded. */
static int run_partial(const uint8_t *patch, uint32_t patch_len,
                       const uint8_t *old, uint32_t old_len, crypto_ctx_t *crypto,
                       unsigned steps, uint32_t *progress, uint32_t *out_flags)
{
    mcf_v2_config_t cfg; mcf_v2_session_t s; mcf_status_t st; unsigned i;
    v2_cfg(&cfg, patch, patch_len, old, old_len, crypto, JOURNAL_BASE);
    st = mcf_v2_session_open(&s, &cfg);
    if (st == MCF_OK) st = mcf_v2_session_begin(&s);
    if (st != MCF_OK) { mcf_v2_session_close(&s); return 0; }
    for (i = 0; i < steps; i++) {
        st = mcf_v2_session_step(&s);
        if (st != MCF_OK) break;
        if (mcf_v2_session_state(&s) == MCF_ST_VERIFY) break;
    }
    *progress = mcf_v2_session_progress(&s);
    if (out_flags) *out_flags = mcf_v2_session_flags(&s);
    mcf_v2_session_close(&s);
    return 1;
}

/* Reboot: probe the journal, resume, finish, and check the image.
 *
 * `want_probe` is the exact status the probe must return, not a boolean. Every
 * rejection mcf_v2_resume_probe() makes is MCF_E_NOT_FOUND, and accepting "any
 * non-MCF_OK" would let an unrelated failure - a parameter error, a HAL fault -
 * masquerade as the rejection under test. The MFP1 counterpart pins the code
 * exactly for the same reason. */
static int run_resume(const uint8_t *patch, uint32_t patch_len,
                      const uint8_t *old, uint32_t old_len, crypto_ctx_t *crypto,
                      const uint8_t *expected, uint32_t new_len,
                      mcf_status_t want_probe, uint32_t *out_progress)
{
    mcf_v2_config_t cfg; mcf_v2_session_t s; mcf_status_t st;
    v2_cfg(&cfg, patch, patch_len, old, old_len, crypto, JOURNAL_BASE);
    st = mcf_v2_session_open(&s, &cfg);
    if (st != MCF_OK) return 0;
    st = mcf_v2_resume_probe(&s);
    if (st != want_probe) {
        fprintf(stderr, "resume probe status %d (expected %d)\n",
                (int)st, (int)want_probe);
        mcf_v2_session_close(&s);
        return 0;
    }
    st = mcf_v2_session_run(&s);
    if (st != MCF_OK) {
        fprintf(stderr, "resumed run failed: %d\n", (int)st);
        mcf_v2_session_close(&s);
        return 0;
    }
    if (out_progress) *out_progress = mcf_v2_session_progress(&s);
    mcf_v2_session_close(&s);
    if (memcmp(flash, expected, new_len) != 0) {
        fprintf(stderr, "resumed image is not byte-exact\n");
        return 0;
    }
    return 1;
}

/* A small image whose new_size is below the record framing. The device's decode
 * window is min(record_size, new_size) - clamped to the image - so a producer
 * that framed at the full record size emits a patch no configuration can apply:
 * the delta is always larger than new_size (every BSDIFF43 control triple adds
 * to it), so its single block overruns the clamped window at every
 * cfg.block_size. The host producer caps its framing at the image; this case
 * applies that patch through the real session.
 *
 * It is falsifiable, not merely passing: the fixture is produced by the host
 * tool, so deleting the producer's cap regenerates it with a full-size frame
 * and this case fails with MCF_E_CORRUPT (site 17), which is exactly how the
 * gap was found. The large fixture cannot see it - there new_size is far above
 * the framing - so this case is the only device-side coverage of the regime. */
static int small_image_case(const uint8_t *patch, uint32_t patch_len,
                            const uint8_t *old, uint32_t old_len,
                            const uint8_t *expected, uint32_t new_len,
                            crypto_ctx_t *crypto)
{
    mcf_status_t st;
    memset(flash, 0xFF, sizeof(flash));
    mutations = 0;
    st = run_patch(patch, patch_len, old, old_len, crypto);
    if (st != MCF_OK) {
        fprintf(stderr, "small-image patch rejected: status %d\n", (int)st);
        return 0;
    }
    if (memcmp(flash, expected, new_len) != 0) {
        fprintf(stderr, "small-image reconstruction is not byte-exact\n");
        return 0;
    }
    if (mutations == 0u) {
        fprintf(stderr, "small-image apply programmed no flash\n");
        return 0;
    }
    printf("  ok  small-image patch applies byte-exact (%u-byte image)\n",
           (unsigned)new_len);
    return 1;
}

/* Many-triples fixture: the delta stream is LONGER than the image, because
 * every BSDIFF43 control triple adds 24 bytes on top of the output it
 * produces. On a patch with many small triples a legitimate checkpoint's
 * decompressed offset (d_off) therefore exceeds new_size, and a cut on the
 * final block boundary lands with out_off == new_size.
 *
 * Two bounds in mcf_v2_resume_probe used to reject exactly those two
 * checkpoints (`d_off <= new_size`, `out_off < new_size`). Both rejections
 * were silent - the probe returns MCF_E_NOT_FOUND and the update restarts
 * from zero, indistinguishable from "no journal" - and both turned a real
 * power cut into a full re-transfer. This case sweeps the interrupt point
 * across the whole run and resumes from every checkpoint captured, so either
 * bound reintroduced fails here.
 *
 * It also asserts the two regimes were actually reached: at least one
 * checkpoint with d_off > new_size, and at least one with out_off ==
 * new_size. A sweep that stopped capturing either would hide the defect this
 * case exists for. The fixture is generated by the host tool, so a device
 * regression and a producer change are both visible. */
static int dense_resume_case(const uint8_t *patch, uint32_t patch_len,
                             const uint8_t *old, uint32_t old_len,
                             const uint8_t *expected, uint32_t new_len,
                             crypto_ctx_t *crypto)
{
    unsigned steps;
    unsigned seen_doff_gt = 0u, seen_final = 0u;
    int ok = 1;

    for (steps = 4u; steps <= 40u; steps++) {
        mcf_v2_journal_t j;
        uint32_t prog = 0u, flags = 0u;

        memset(journal, 0, sizeof(journal));
        memset(flash, 0xFF, sizeof(flash));
        if (!run_partial(patch, patch_len, old, old_len, crypto, steps,
                         &prog, &flags)) {
            fprintf(stderr, "dense-resume: run_partial failed at %u steps\n",
                    steps);
            return 0;
        }
        memcpy(&j, journal, sizeof(j));
        if (j.magic != MCF_V2_JOURNAL_MAGIC) continue;

        if (j.d_off > new_len) seen_doff_gt = 1u;
        if (j.out_off == new_len) seen_final = 1u;

        if (!run_resume(patch, patch_len, old, old_len, crypto,
                        expected, new_len, MCF_OK, NULL)) {
            fprintf(stderr, "dense-resume: resume from out_off %u (d_off %u) "
                    "failed\n", j.out_off, j.d_off);
            return 0;
        }
    }
    if (!seen_doff_gt) {
        fprintf(stderr, "dense-resume: no checkpoint with d_off > new_size was "
                        "captured; the many-triples regime is not exercised\n");
        ok = 0;
    }
    if (!seen_final) {
        fprintf(stderr, "dense-resume: no checkpoint at out_off == new_size "
                        "was captured; the final-boundary resume is not "
                        "exercised\n");
        ok = 0;
    }
    if (ok) puts("  ok  dense-triple patch resumes from every checkpoint byte-exact");
    return ok;
}

int main(int argc, char **argv)
{
    uint32_t patch_len, old_len, new_len, pub_len, key_len = 0;
    uint32_t reord_len = 0, wrong_nonce_len = 0, off;
    uint32_t tag_tamper_len = 0, ct_tamper_len = 0, bad_key_id_len = 0;
    uint32_t dupe_len = 0;
    uint32_t small_len = 0, small_old_len = 0, small_new_len = 0;
    uint32_t dense_len = 0, dense_old_len = 0, dense_new_len = 0;
    uint8_t *patch, *old, *expected, *pub, *key;
    uint8_t *reord = NULL, *wrong_nonce = NULL, *tag_tamper = NULL;
    uint8_t *ct_tamper = NULL, *bad_key_id = NULL, *dupe = NULL;
    uint8_t *small = NULL, *small_old = NULL, *small_new = NULL;
    uint8_t *dense = NULL, *dense_old = NULL, *dense_new = NULL;
    mcf_v2_view_t view; crypto_ctx_t crypto;
    int ok = 1;
    /* argv: patch old new pub key reordered wrong_nonce tag_tamper ct_tamper
     * bad_key_id duplicated small_patch small_old small_new dense_patch
     * dense_old dense_new — the six variants come from
     * tests/mfp2_fixtures.py, the small trio from a second host make run over a
     * small image, and the dense trio from a third over a many-triples patch
     * whose delta stream is longer than the image. All eighteen are required: a
     * case that can quietly disappear is not a case. */
    if (argc != 18 || sodium_init() < 0) return 2;
    patch = read_file(argv[1], &patch_len); old = read_file(argv[2], &old_len);
    expected = read_file(argv[3], &new_len); pub = read_file(argv[4], &pub_len);
    key = read_file(argv[5], &key_len);
    if (!patch || !old || !expected || !pub || !key || pub_len != sizeof(crypto.public_key)) return 2;
    /* The symmetric key is supplied separately from the Ed25519 public key. */
    if (key_len != sizeof(crypto.symmetric_key)) return 2;
    if (!(reord = read_file(argv[6], &reord_len))) return 2;
    if (!(wrong_nonce = read_file(argv[7], &wrong_nonce_len))) return 2;
    if (!(tag_tamper = read_file(argv[8], &tag_tamper_len))) return 2;
    if (!(ct_tamper = read_file(argv[9], &ct_tamper_len))) return 2;
    if (!(bad_key_id = read_file(argv[10], &bad_key_id_len))) return 2;
    if (!(dupe = read_file(argv[11], &dupe_len))) return 2;
    if (!(small = read_file(argv[12], &small_len))) return 2;
    if (!(small_old = read_file(argv[13], &small_old_len))) return 2;
    if (!(small_new = read_file(argv[14], &small_new_len))) return 2;
    if (!(dense = read_file(argv[15], &dense_len))) return 2;
    if (!(dense_old = read_file(argv[16], &dense_old_len))) return 2;
    if (!(dense_new = read_file(argv[17], &dense_new_len))) return 2;
    memcpy(crypto.public_key, pub, sizeof(crypto.public_key));
    memcpy(crypto.symmetric_key, key, sizeof(crypto.symmetric_key));
    /* Fixture key id is 00112233445566778899aabbccddeeff. */
    { static const uint8_t id[16] = {0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff}; memcpy(crypto.key_id,id,16); }

    /* Positive path: the host-produced patch applies byte-exact. */
    memset(flash, 0xFF, sizeof(flash)); mutations = 0;
    if (run_patch(patch, patch_len, old, old_len, &crypto) != MCF_OK ||
        memcmp(flash, expected, new_len) != 0) {
        fprintf(stderr, "MFP2 positive path failed\n"); return 1;
    }
    puts("  ok  valid patch applies byte-exact");

    /* The counter every tamper case leans on must be able to move. Every
     * rejection below asserts `mutations == 0`, and that assertion is only
     * meaningful if a successful run drives the counter above zero: a counter
     * that can never increment would make all of them pass vacuously. Removing
     * the increments from the HAL callbacks must break this, not the suite. */
    if (mutations == 0u) {
        fprintf(stderr, "flash-mutation counter never incremented on a "
                        "successful apply: the zero-mutation assertions are "
                        "vacuous\n");
        return 1;
    }
    printf("  ok  a successful apply programs flash (%u mutations)\n", mutations);

    /* The same patch in a workspace far smaller than the decrypted payload. */
    if (!streaming_workspace_case(patch, patch_len, old, old_len, expected, new_len, &crypto)) {
        return 1;
    }

    /* Wrong symmetric key: signature passes, key provider matches the id,
     * every record AEAD must fail authentication. */
    { uint8_t saved[MCF_V2_KEY_SIZE];
      memcpy(saved, crypto.symmetric_key, sizeof(saved));
      crypto.symmetric_key[0] ^= 1u;
      ok &= expect_case("wrong symmetric key", patch, patch_len, NULL,
                        MCF_E_AUTH, &crypto, old, old_len);
      memcpy(crypto.symmetric_key, saved, sizeof(saved)); }

    /* ---- Tampering that is NOT re-signed: each must die at a cheap gate.
     * The status is pinned, so a case that fails for an unexpected reason
     * fails the suite instead of quietly reporting ok. ---- */

    /* The key id sits inside the signed span, so flipping it is a signature
     * test. Reaching the key provider is a different test, and it is the
     * re-signed `unknown key id` fixture below that reaches it. */
    { uint8_t *tampered = (uint8_t *)malloc(patch_len);
      if (tampered) {
          memcpy(tampered, patch, patch_len);
          tampered[MCF_V2_OFF_KEY_ID] ^= 1u;
          ok &= expect_case("tampered key id", tampered, patch_len, NULL,
                            MCF_E_SIGNATURE, &crypto, old, old_len);
          free(tampered);
      } else ok = 0; }

    /* new_crc32 is covered by the signature but checked by no structural rule
     * before it, so the signature is what has to reject this. Flipping
     * payload_size instead trips MCF_E_FORMAT first — see below. */
    { uint8_t *tampered = (uint8_t *)malloc(patch_len);
      if (tampered) {
          memcpy(tampered, patch, patch_len);
          tampered[MCF_V2_OFF_NEW_CRC] ^= 1u;
          ok &= expect_case("tampered header field", tampered, patch_len, NULL,
                            MCF_E_SIGNATURE, &crypto, old, old_len);
          free(tampered);
      } else ok = 0; }

    { uint8_t *tampered = (uint8_t *)malloc(patch_len);
      if (tampered) {
          memcpy(tampered, patch, patch_len); tampered[MCF_V2_OFF_SIGNATURE] ^= 1u;
          ok &= expect_case("flipped signature byte", tampered, patch_len, NULL,
                            MCF_E_SIGNATURE, &crypto, old, old_len);
          free(tampered);
      } else ok = 0; }

    /* A header field contradicting the actual patch length is a structural
     * rejection, reached before any cryptographic gate. */
    { uint8_t *tampered = (uint8_t *)malloc(patch_len);
      if (tampered) {
          memcpy(tampered, patch, patch_len);
          tampered[MCF_V2_OFF_PAYLOAD_SIZE] ^= 0x10u;
          ok &= expect_case("inconsistent payload size", tampered, patch_len, NULL,
                            MCF_E_FORMAT, &crypto, old, old_len);
          free(tampered);
      } else ok = 0; }

    /* Truncation mid-payload: cut the last record's tail off. */
    { uint32_t cut = patch_len - 8u;
      if (cut > (mcf_v2_parse(patch, patch_len, &view), view.header_len)) {
          ok &= expect_case("truncated payload", patch, cut, NULL,
                            MCF_E_TRUNCATED, &crypto, old, old_len);
      } else ok = 0; }

    /* In-place corruption of the record area is caught by the payload CRC,
     * which is computed over the framed ciphertext — tags included — before
     * anything is decrypted. A bit flip here therefore always dies at
     * MCF_E_CORRUPT and can never reach the AEAD tag check. The AEAD-layer
     * equivalents need the CRC recomputed and are the re-signed fixtures
     * further down. */
    { uint8_t *tampered = (uint8_t *)malloc(patch_len);
      if (tampered && mcf_v2_parse(patch, patch_len, &view) == MCF_OK) {
          memcpy(tampered, patch, patch_len);
          tampered[patch_len - 1u] ^= 1u;           /* last byte is the final tag */
          ok &= expect_case("corrupted AEAD tag", tampered, patch_len, NULL,
                            MCF_E_CORRUPT, &crypto, old, old_len);
          memcpy(tampered, patch, patch_len);
          off = view.header_len + 4u;               /* first ciphertext byte */
          if (off < patch_len) tampered[off] ^= 1u;
          ok &= expect_case("flipped ciphertext byte", tampered, patch_len, NULL,
                            MCF_E_CORRUPT, &crypto, old, old_len);
          free(tampered);
      } else ok = 0; }

    /* ---- Re-signed variants: signature and payload CRC are both valid, so
     * every cheap gate is satisfied and the device has to reject on the
     * binding under test. tests/mfp2_fixtures.py --self-check proves each one
     * parses and verifies before the host rejects it, which is what stops a
     * variant from silently degrading into a parse failure. ---- */

    /* Units swapped verbatim: only the AAD record index ties a ciphertext to
     * its position. */
    if (reord) ok &= expect_case("reordered records", reord, reord_len, NULL,
                                 MCF_E_AUTH, &crypto, old, old_len);
    else ok = 0;

    /* The header declares a nonce prefix the ciphertexts were not sealed
     * under, so the device derives a different per-record nonce. */
    if (wrong_nonce) ok &= expect_case("wrong nonce prefix", wrong_nonce, wrong_nonce_len,
                                       NULL, MCF_E_AUTH, &crypto, old, old_len);
    else ok = 0;

    /* One bit of a record's AEAD tag, payload CRC recomputed. */
    if (tag_tamper) ok &= expect_case("tampered AEAD tag", tag_tamper, tag_tamper_len,
                                      NULL, MCF_E_AUTH, &crypto, old, old_len);
    else ok = 0;

    /* One bit of record 0's ciphertext, payload CRC recomputed. */
    if (ct_tamper) ok &= expect_case("tampered ciphertext", ct_tamper, ct_tamper_len,
                                     NULL, MCF_E_AUTH, &crypto, old, old_len);
    else ok = 0;

    /* Validly signed, but the key id names a key the provider does not hold:
     * the provider rejects before a single record is decrypted. */
    if (bad_key_id) ok &= expect_case("unknown key id", bad_key_id, bad_key_id_len,
                                      NULL, MCF_E_AUTH, &crypto, old, old_len);
    else ok = 0;

    /* One record's unit replayed in another's slot. Distinct from reordering,
     * which swaps two units so each position holds a different authentic
     * record; here one authentic unit appears twice, so the device must refuse
     * to accept the same authenticated record a second time. The AAD index is
     * the only thing that can catch it. */
    if (dupe) ok &= expect_case("duplicated record", dupe, dupe_len,
                                NULL, MCF_E_AUTH, &crypto, old, old_len);
    else ok = 0;

    /* ---------------- Resume scenarios ---------------- */
    {
        uint32_t partial = 0u, resumed = 0u, expected_ckpt;
        unsigned steps;
        int found = 0;

        /* Interrupt mid-run at a checkpoint boundary. interval=1 block, so the
         * engine stops on every 1024-byte output boundary. */
        memset(journal, 0, sizeof(journal));
        journal_mutations = 0;
        memset(flash, 0xFF, sizeof(flash));
        mutations = 0;
        ok &= run_partial(patch, patch_len, old, old_len, &crypto, 7u, &partial, NULL);
        {
            mcf_v2_journal_t j;
            memcpy(&j, journal, sizeof(j));
            if (j.magic == MCF_V2_JOURNAL_MAGIC && j.out_off > 0u &&
                (j.out_off % BLOCK_SIZE) == 0u) {
                found = 1;
            }
        }
        if (!found) {
            fprintf(stderr, "resume: no checkpoint was written after 7 steps\n");
            ok = 0;
        }

        /* The resume must do strictly less work than the interrupted run had
         * left to do: the decoder starts at the checkpoint's record, so the
         * total decoded bytes (feed length + everything re-derived) excludes
         * the prefix records. This is the property that distinguishes a
         * positioned resume from a replay. */
        {
            mcf_v2_config_t cfg; mcf_v2_session_t s; mcf_status_t st;
            mcf_v2_journal_t j;
            memcpy(&j, journal, sizeof(j));
            v2_cfg(&cfg, patch, patch_len, old, old_len, &crypto, JOURNAL_BASE);
            st = mcf_v2_session_open(&s, &cfg);
            ok &= (st == MCF_OK);
            st = mcf_v2_resume_probe(&s);
            ok &= (st == MCF_OK);
            st = mcf_v2_session_begin(&s);
            ok &= (st == MCF_OK);
            if (st == MCF_OK && mcf_v2_session_progress(&s) != j.out_off) {
                fprintf(stderr, "resume: begin() progress %u != journal out_off %u\n",
                        mcf_v2_session_progress(&s), j.out_off);
                ok = 0;
            }
            /* The feed starts at record j.record_index, not record 0. */
            if (st == MCF_OK && j.record_index == 0u && j.out_off > 0u) {
                fprintf(stderr, "resume: checkpoint at out_off %u still names record 0\n",
                        j.out_off);
                ok = 0;
            }
            mcf_v2_session_close(&s);
            if (ok) puts("  ok  resumed session starts at the checkpoint, not zero");
        }

        /* A fresh session probes the journal and continues; the image must be
         * byte-exact and the resume must have started past the checkpoint. */
        ok &= run_resume(patch, patch_len, old, old_len, &crypto,
                         expected, new_len, MCF_OK, &resumed);
        if (resumed < partial) {
            fprintf(stderr, "resume: progress regressed (%u -> %u)\n", partial, resumed);
            ok = 0;
        }
        (void)expected_ckpt;
        (void)steps;
        if (ok) puts("  ok  interrupted run resumes and completes byte-exact");

        /* The journal must ADVANCE. A single checkpoint proves only that the
         * first one was written; the ring that names the record containing the
         * engine position holds four entries, so if the feed ever runs far
         * ahead of the engine the containing record is evicted, every later
         * checkpoint is missed, and the run continues silently unresumable with
         * RESUME_DEGRADED set. Measured before the feed fix: on this fixture
         * the journal froze at out_off=1024 and the flag was set from step 8.
         *
         * Two independent assertions, each of which that behaviour fails:
         *   - a checkpoint from a longer run names a LATER out_off;
         *   - the longer run never degrades. */
        {
            mcf_v2_journal_t j7, j24;
            uint32_t prog7 = 0u, prog24 = 0u, flags7 = 0u, flags24 = 0u;

            memset(journal, 0, sizeof(journal));
            memset(flash, 0xFF, sizeof(flash));
            ok &= run_partial(patch, patch_len, old, old_len, &crypto, 7u,
                              &prog7, &flags7);
            memcpy(&j7, journal, sizeof(j7));
            if (j7.magic != MCF_V2_JOURNAL_MAGIC) {
                fprintf(stderr, "resume-advance: no checkpoint at 7 steps\n");
                ok = 0;
            }

            memset(journal, 0, sizeof(journal));
            memset(flash, 0xFF, sizeof(flash));
            ok &= run_partial(patch, patch_len, old, old_len, &crypto, 24u,
                              &prog24, &flags24);
            memcpy(&j24, journal, sizeof(j24));
            if (j24.magic != MCF_V2_JOURNAL_MAGIC) {
                fprintf(stderr, "resume-advance: no checkpoint at 24 steps\n");
                ok = 0;
            }
            if (j24.out_off <= j7.out_off) {
                fprintf(stderr, "resume-advance: journal did not advance "
                        "(%u -> %u)\n", j7.out_off, j24.out_off);
                ok = 0;
            }
            if ((flags24 & MCF_V2_SESSION_FLAG_RESUME_DEGRADED) != 0u) {
                fprintf(stderr, "resume-advance: checkpointing degraded by 24 "
                        "steps: every checkpoint after the first was missed\n");
                ok = 0;
            }
            /* Resume from the LATER checkpoint and finish byte-exact. */
            ok &= run_resume(patch, patch_len, old, old_len, &crypto,
                             expected, new_len, MCF_OK, &resumed);
            if (ok) puts("  ok  journal advances across checkpoints, no degrade");
        }

        /* A checkpoint taken mid-DIFF must resume byte-exact. The engine can
         * halt on a block boundary inside a triple's diff run; the journal then
         * carries diff_remaining > 0 and resume must restore it - a resume that
         * dropped the count would misapply every remaining delta. A nonzero
         * diff_remaining identifies a mid-DIFF capture: DIFF decrements it to
         * zero before handing over to EXTRA, so no other phase can carry one.
         *
         * The "found" assertion is deliberate falsifiability. If the feed ever
         * regresses to prefetching so far ahead that these captures disappear
         * (or degrade), the coverage this case exists for vanishes; a test that
         * quietly skipped would hide exactly the defect that was there. */
        {
            unsigned step_counts[5] = {8u, 12u, 16u, 20u, 24u};
            unsigned k, found_diff = 0u;

            for (k = 0u; k < 5u; k++) {
                mcf_v2_journal_t j;
                uint32_t prog = 0u, flags = 0u;
                memset(journal, 0, sizeof(journal));
                memset(flash, 0xFF, sizeof(flash));
                ok &= run_partial(patch, patch_len, old, old_len, &crypto,
                                  step_counts[k], &prog, &flags);
                memcpy(&j, journal, sizeof(j));
                if (j.magic != MCF_V2_JOURNAL_MAGIC) continue;
                if (j.diff_remaining == 0u) continue;
                found_diff = 1u;
                ok &= run_resume(patch, patch_len, old, old_len, &crypto,
                                 expected, new_len, MCF_OK, NULL);
            }
            if (!found_diff) {
                fprintf(stderr, "resume-mid-diff: no checkpoint with "
                        "diff_remaining > 0 was captured; the mid-DIFF resume "
                        "path is no longer exercised\n");
                ok = 0;
            } else if (ok) {
                puts("  ok  mid-DIFF checkpoint resumes byte-exact");
            }
        }

        /* A stale journal (foreign session id) is rejected: cold start.
         *
         * A checkpoint must be primed first. The case above completed an update,
         * which clears the journal, so mutating whatever record is left would be
         * rejected for having no magic at all - never reaching the session-id
         * binding this case is named for. */
        {
            mcf_v2_journal_t j;
            uint32_t primed = 0u;
            memset(journal, 0, sizeof(journal));
            journal_mutations = 0;
            memset(flash, 0xFF, sizeof(flash));
            ok &= run_partial(patch, patch_len, old, old_len, &crypto, 7u, &primed, NULL);
            memcpy(&j, journal, sizeof(j));
            if (j.magic != MCF_V2_JOURNAL_MAGIC) {
                fprintf(stderr, "resume: no checkpoint to make foreign\n");
                ok = 0;
            }
            j.session_id ^= 0xFFFFFFFFu;
            j.record_crc = 0u;
            /* The library computes the CRC over the record with record_crc
             * zeroed, so rebuild it the same way. */
            {
                mcf_v2_journal_t t = j; t.record_crc = 0u;
                t.record_crc = mcf_crc32((const uint8_t *)&t, (uint32_t)sizeof(t));
                j = t;
            }
            memcpy(journal, &j, sizeof(j));
            ok &= run_resume(patch, patch_len, old, old_len, &crypto,
                             expected, new_len, MCF_E_NOT_FOUND, NULL);
            if (ok) puts("  ok  foreign journal rejected, cold start completes");
        }

        /* Corrupted prefix on flash: the journal claims a prefix that is not
         * what flash holds. */
        memset(journal, 0, sizeof(journal));
        journal_mutations = 0;
        memset(flash, 0xFF, sizeof(flash));
        ok &= run_partial(patch, patch_len, old, old_len, &crypto, 7u, &partial, NULL);
        flash[0] ^= 0xFFu; /* damage the programmed prefix */
        ok &= run_resume(patch, patch_len, old, old_len, &crypto,
                         expected, new_len, MCF_E_NOT_FOUND, NULL);
        if (ok) puts("  ok  damaged prefix rejected, cold start completes");

        /* Journal disabled (addr 0): probe is a no-op, run still works. */
        {
            mcf_v2_config_t cfg; mcf_v2_session_t s; mcf_status_t st;
            v2_cfg(&cfg, patch, patch_len, old, old_len, &crypto, 0u);
            st = mcf_v2_session_open(&s, &cfg);
            ok &= (st == MCF_OK);
            ok &= (mcf_v2_resume_probe(&s) == MCF_E_NOT_FOUND);
            memset(flash, 0xFF, sizeof(flash));
            st = mcf_v2_session_run(&s);
            ok &= (st == MCF_OK);
            ok &= (memcmp(flash, expected, new_len) == 0);
            mcf_v2_session_close(&s);
            if (ok) puts("  ok  journal disabled: probe no-op, run byte-exact");
        }

        /* A completed run clears the journal. The journal is primed with a
         * checkpoint first, so "cleared" means a written record was removed -
         * without that precondition the assertion below is satisfied by a
         * journal that was never written at all. */
        {
            mcf_v2_journal_t j;
            uint32_t primed = 0u;
            memset(journal, 0, sizeof(journal));
            journal_mutations = 0;
            memset(flash, 0xFF, sizeof(flash));
            ok &= run_partial(patch, patch_len, old, old_len, &crypto, 7u, &primed, NULL);
            memcpy(&j, journal, sizeof(j));
            if (j.magic != MCF_V2_JOURNAL_MAGIC) {
                fprintf(stderr, "resume: no checkpoint to clear\n");
                ok = 0;
            }
            ok &= run_resume(patch, patch_len, old, old_len, &crypto,
                             expected, new_len, MCF_OK, NULL);
            memcpy(&j, journal, sizeof(j));
            if (j.magic == MCF_V2_JOURNAL_MAGIC) {
                fprintf(stderr, "resume: journal not cleared after success\n");
                ok = 0;
            } else if (ok) {
                puts("  ok  journal cleared after a completed update");
            }
        }
    }

    /* Small image: the producer must cap its framing at the image, because the
     * device's window is min(record_size, new_size). The large fixture above
     * never enters this regime, so without this case the cap is untested on the
     * device. */
    ok &= small_image_case(small, small_len, small_old, small_old_len,
                           small_new, small_new_len, &crypto);

    /* Many-triples image: the delta stream is longer than the image, so
     * legitimate checkpoints carry d_off > new_size and a cut on the final
     * boundary lands at out_off == new_size. Both were rejected by the probe
     * before this case existed. */
    ok &= dense_resume_case(dense, dense_len, dense_old, dense_old_len,
                            dense_new, dense_new_len, &crypto);

    (void)view;
    free(reord); free(wrong_nonce); free(tag_tamper); free(ct_tamper);
    free(bad_key_id); free(dupe);
    free(small); free(small_old); free(small_new);
    free(dense); free(dense_old); free(dense_new);
    free(patch); free(old); free(expected); free(pub); free(key);
    if (!ok) { fprintf(stderr, "MFP2 session integration test FAILED\n"); return 1; }
    puts("MFP2 session success, Ed25519ph/AEAD tamper tests passed"); return 0;
}

