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
/* MCF_E_ANY: accept any rejection status (used when several gates could fire
 * first and pinning one would over-specify the implementation). */
#define MCF_E_ANY 0

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
    if (want != MCF_E_ANY && (int32_t)st != (int32_t)want) {
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

int main(int argc, char **argv)
{
    uint32_t patch_len, old_len, new_len, pub_len, key_len = 0;
    uint32_t reord_len = 0, wrong_nonce_len = 0, off;
    uint8_t *patch, *old, *expected, *pub, *key;
    uint8_t *reord = NULL, *wrong_nonce = NULL;
    mcf_v2_view_t view; crypto_ctx_t crypto;
    int ok = 1;
    if (argc < 6 || argc > 8 || sodium_init() < 0) return 2;
    patch = read_file(argv[1], &patch_len); old = read_file(argv[2], &old_len);
    expected = read_file(argv[3], &new_len); pub = read_file(argv[4], &pub_len);
    key = read_file(argv[5], &key_len);
    if (!patch || !old || !expected || !pub || !key || pub_len != sizeof(crypto.public_key)) return 2;
    /* The symmetric key is supplied separately from the Ed25519 public key. */
    if (key_len != sizeof(crypto.symmetric_key)) return 2;
    if (argc > 6 && !(reord = read_file(argv[6], &reord_len))) return 2;
    if (argc > 7 && !(wrong_nonce = read_file(argv[7], &wrong_nonce_len))) return 2;
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

    /* Wrong symmetric key: signature passes, key provider matches the id,
     * every record AEAD must fail authentication. */
    { uint8_t saved[MCF_V2_KEY_SIZE];
      memcpy(saved, crypto.symmetric_key, sizeof(saved));
      crypto.symmetric_key[0] ^= 1u;
      ok &= expect_case("wrong symmetric key", patch, patch_len, NULL,
                        MCF_E_AUTH, &crypto, old, old_len);
      memcpy(crypto.symmetric_key, saved, sizeof(saved)); }

    /* Wrong key id: header CRC gates first, then the provider rejects. */
    { uint8_t *tampered = (uint8_t *)malloc(patch_len);
      if (tampered) {
          memcpy(tampered, patch, patch_len);
          tampered[MCF_V2_OFF_KEY_ID] ^= 1u;
          ok &= expect_case("wrong key id", tampered, patch_len, NULL,
                            MCF_E_ANY, &crypto, old, old_len);
          free(tampered);
      } else ok = 0; }

    /* Corrupted AEAD tag: payload CRC (over the ciphertext) fails first. */
    { uint8_t *tampered = (uint8_t *)malloc(patch_len);
      if (tampered && mcf_v2_parse(patch, patch_len, &view) == MCF_OK) {
          memcpy(tampered, patch, patch_len);
          off = view.header_len + 4u; /* length prefix of record 0 */
          if (off + view.record_max_block + MCF_V2_RECORD_TAG_SIZE <= patch_len)
              tampered[off + view.record_max_block + (MCF_V2_RECORD_TAG_SIZE - 1u)] ^= 1u;
          ok &= expect_case("corrupted AEAD tag", tampered, patch_len, NULL,
                            MCF_E_CORRUPT, &crypto, old, old_len);
          free(tampered);
      } else ok = 0; }

    /* Truncation mid-payload: cut the last record's tail off. */
    { uint32_t cut = patch_len - 8u;
      if (cut > (mcf_v2_parse(patch, patch_len, &view), view.header_len)) {
          ok &= expect_case("truncated payload", patch, cut, NULL,
                            MCF_E_TRUNCATED, &crypto, old, old_len);
      } else ok = 0; }

    /* Modified header byte outside signature/CRC: payload size. */
    { uint8_t *tampered = (uint8_t *)malloc(patch_len);
      if (tampered) {
          memcpy(tampered, patch, patch_len);
          tampered[MCF_V2_OFF_PAYLOAD_SIZE] ^= 0x10u;
          ok &= expect_case("modified header field", tampered, patch_len, NULL,
                            MCF_E_ANY, &crypto, old, old_len);
          free(tampered);
      } else ok = 0; }

    /* Reordered records: re-signed by the host, so signature, key id, key and
     * nonce prefix are all genuinely valid — only the AAD record index binds
     * the ciphertexts to their positions. */
    if (reord) ok &= expect_case("reordered records", reord, reord_len, NULL,
                                 MCF_E_ANY, &crypto, old, old_len);
    else ok = 0;

    /* Mismatched nonce prefix: re-signed, everything valid except the device
     * derives a different per-record nonce than the producer used. */
    if (wrong_nonce) ok &= expect_case("wrong nonce prefix", wrong_nonce, wrong_nonce_len,
                                       NULL, MCF_E_ANY, &crypto, old, old_len);
    else ok = 0;

    /* Original bit-flip cases, kept for regression parity. */
    { uint8_t *tampered = (uint8_t *)malloc(patch_len);
      if (tampered) {
          memcpy(tampered, patch, patch_len); tampered[MCF_V2_OFF_SIGNATURE] ^= 1u;
          ok &= expect_case("flipped signature byte", tampered, patch_len, NULL,
                            MCF_E_SIGNATURE, &crypto, old, old_len);
          memcpy(tampered, patch, patch_len);
          if (mcf_v2_parse(patch, patch_len, &view) == MCF_OK) {
              off = view.header_len + 4u; /* first ciphertext byte */
              if (off < patch_len) tampered[off] ^= 1u;
              ok &= expect_case("flipped ciphertext byte", tampered, patch_len, NULL,
                                MCF_E_CORRUPT, &crypto, old, old_len);
          } else ok = 0;
          free(tampered);
      } else ok = 0; }

    (void)view;
    free(reord); free(wrong_nonce);
    free(patch); free(old); free(expected); free(pub); free(key);
    if (!ok) { fprintf(stderr, "MFP2 session integration test FAILED\n"); return 1; }
    puts("MFP2 session success, Ed25519ph/AEAD tamper tests passed"); return 0;
}
