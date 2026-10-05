/*
 * Cryptographic primitives: thin wrappers over mbedTLS. See crypto.h.
 */
#include "crypto.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/bignum.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

static const char *TAG_SELFTEST = "SELFTEST";

static const uint8_t DH_P[] = MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
static const uint8_t DH_G[] = MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;

_Static_assert(sizeof(DH_P) == CRYPTO_DH_LEN, "group 14 prime must be 2048 bits");

/* mbedTLS-style RNG callback over the ESP32 hardware RNG. Its output is
 * true random while Wi-Fi is running, which is always the case before a
 * handshake starts. */
static int hw_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

void crypto_zeroize(void *buf, size_t len)
{
    mbedtls_platform_zeroize(buf, len);
}

/* ------------------------------------------------------------------------ */
/* Diffie-Hellman                                                            */
/* ------------------------------------------------------------------------ */

void crypto_dh_clear(crypto_dh_t *dh)
{
    if (dh->active) {
        mbedtls_dhm_free(&dh->ctx); /* zeroizes the private key */
        dh->active = false;
    }
}

int crypto_dh_keygen(crypto_dh_t *dh, uint8_t pub[CRYPTO_DH_LEN])
{
    crypto_dh_clear(dh);
    mbedtls_dhm_init(&dh->ctx);
    dh->active = true;

    mbedtls_mpi p, g;
    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&g);

    int ret = mbedtls_mpi_read_binary(&p, DH_P, sizeof(DH_P));
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&g, DH_G, sizeof(DH_G));
    }
    if (ret == 0) {
        ret = mbedtls_dhm_set_group(&dh->ctx, &p, &g);
    }
    if (ret == 0) {
        /* A private-key size equal to the prime size makes mbedTLS draw x
         * uniformly from [2, p-2]; the public value is written left-padded. */
        ret = mbedtls_dhm_make_public(&dh->ctx, CRYPTO_DH_LEN, pub, CRYPTO_DH_LEN, hw_rng, NULL);
    }

    mbedtls_mpi_free(&p);
    mbedtls_mpi_free(&g);
    if (ret != 0) {
        crypto_dh_clear(dh);
    }
    return ret;
}

bool crypto_dh_public_is_valid(const uint8_t pub[CRYPTO_DH_LEN])
{
    mbedtls_mpi y, p_minus_1;
    mbedtls_mpi_init(&y);
    mbedtls_mpi_init(&p_minus_1);

    bool valid = mbedtls_mpi_read_binary(&y, pub, CRYPTO_DH_LEN) == 0 &&
                 mbedtls_mpi_read_binary(&p_minus_1, DH_P, sizeof(DH_P)) == 0 &&
                 mbedtls_mpi_sub_int(&p_minus_1, &p_minus_1, 1) == 0 &&
                 mbedtls_mpi_cmp_int(&y, 1) > 0 &&
                 mbedtls_mpi_cmp_mpi(&y, &p_minus_1) < 0;

    mbedtls_mpi_free(&y);
    mbedtls_mpi_free(&p_minus_1);
    return valid;
}

int crypto_dh_shared(crypto_dh_t *dh, const uint8_t peer_pub[CRYPTO_DH_LEN],
                     uint8_t secret[CRYPTO_DH_LEN])
{
    if (!dh->active) {
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    }

    uint8_t raw[CRYPTO_DH_LEN];
    size_t raw_len = 0;
    int ret = mbedtls_dhm_read_public(&dh->ctx, peer_pub, CRYPTO_DH_LEN);
    if (ret == 0) {
        ret = mbedtls_dhm_calc_secret(&dh->ctx, raw, sizeof(raw), &raw_len, hw_rng, NULL);
    }
    if (ret == 0) {
        /* mbedTLS drops leading zero bytes (about 1 secret in 256 is
         * shorter). Pad back to the full size so both sides feed exactly
         * the same bytes into the key derivation. */
        size_t pad = CRYPTO_DH_LEN - raw_len;
        memset(secret, 0, pad);
        memcpy(secret + pad, raw, raw_len);
    }

    crypto_zeroize(raw, sizeof(raw));
    crypto_dh_clear(dh);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Random, HMAC, HKDF and AES-GCM                                            */
/* ------------------------------------------------------------------------ */

void crypto_random(uint8_t *buf, size_t len)
{
    esp_fill_random(buf, len);
}

int crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len,
                       uint8_t out[CRYPTO_HMAC_LEN])
{
    const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_md_hmac(sha256, key, key_len, data, len, out);
}

bool crypto_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

int crypto_hkdf_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
    const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf(sha256, salt, salt_len, ikm, ikm_len, info, info_len, out, out_len);
}

int crypto_aead_encrypt(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                        const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t len,
                        uint8_t *ct, uint8_t tag[CRYPTO_AEAD_TAG_LEN])
{
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, CRYPTO_AEAD_KEY_LEN * 8);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, nonce, CRYPTO_AEAD_NONCE_LEN,
                                        aad, aad_len, pt, ct, CRYPTO_AEAD_TAG_LEN, tag);
    }
    mbedtls_gcm_free(&gcm);
    return ret;
}

int crypto_aead_decrypt(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                        const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t len,
                        const uint8_t tag[CRYPTO_AEAD_TAG_LEN], uint8_t *pt)
{
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, CRYPTO_AEAD_KEY_LEN * 8);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, len, nonce, CRYPTO_AEAD_NONCE_LEN, aad, aad_len,
                                       tag, CRYPTO_AEAD_TAG_LEN, ct, pt);
    }
    mbedtls_gcm_free(&gcm);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Fingerprints                                                              */
/* ------------------------------------------------------------------------ */

void crypto_fingerprint(const char *label, const uint8_t *data, size_t len,
                        char out[CRYPTO_FP_HEX_LEN])
{
    uint8_t digest[32];
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, (const unsigned char *)label, strlen(label));
    mbedtls_sha256_update(&sha, data, len);
    mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);

    snprintf(out, CRYPTO_FP_HEX_LEN, "%02x%02x%02x%02x", digest[0], digest[1], digest[2], digest[3]);
}

/* ------------------------------------------------------------------------ */
/* Self-test                                                                 */
/* ------------------------------------------------------------------------ */

static bool report(const char *name, bool pass)
{
    if (pass) {
        ESP_LOGI(TAG_SELFTEST, "%s PASS", name);
    } else {
        ESP_LOGE(TAG_SELFTEST, "%s FAIL", name);
    }
    return pass;
}

static bool all_zero(const uint8_t *buf, size_t len)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc |= buf[i];
    }
    return acc == 0;
}

/* RFC 4231, Test Case 2 (HMAC-SHA-256 with a short key). */
static bool test_hmac_rfc4231(void)
{
    static const uint8_t key[] = "Jefe";
    static const uint8_t data[] = "what do ya want for nothing?";
    static const uint8_t expected[CRYPTO_HMAC_LEN] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    uint8_t mac[CRYPTO_HMAC_LEN];
    /* sizeof - 1: the vectors do not include the string terminator. */
    return crypto_hmac_sha256(key, sizeof(key) - 1, data, sizeof(data) - 1, mac) == 0 &&
           crypto_ct_equal(mac, expected, sizeof(mac));
}

/* RFC 5869, Appendix A.1 (Test Case 1, SHA-256). */
static bool test_hkdf_rfc5869(void)
{
    static const uint8_t ikm[22] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    static const uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    };
    static const uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    };
    static const uint8_t expected[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
        0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
        0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    };
    uint8_t okm[sizeof(expected)];
    int ret = crypto_hkdf_sha256(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info),
                                 okm, sizeof(okm));
    return ret == 0 && memcmp(okm, expected, sizeof(expected)) == 0;
}

/* GCM specification (McGrew & Viega), test case 4: AES-128, 60-byte
 * plaintext, 20-byte AAD. Checks encryption and decryption. */
static bool test_gcm_known_answer(void)
{
    static const uint8_t key[16] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    };
    static const uint8_t iv[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
    };
    static const uint8_t aad[20] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
        0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
    };
    static const uint8_t pt[60] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26,
        0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
        0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
        0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
    };
    static const uint8_t expected_ct[60] = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4,
        0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
        0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac,
        0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91,
    };
    static const uint8_t expected_tag[16] = {
        0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47,
    };
    uint8_t ct[sizeof(pt)];
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    uint8_t back[sizeof(pt)];

    bool ok = crypto_aead_encrypt(key, iv, aad, sizeof(aad), pt, sizeof(pt), ct, tag) == 0 &&
              memcmp(ct, expected_ct, sizeof(ct)) == 0 &&
              memcmp(tag, expected_tag, sizeof(tag)) == 0;
    ok = ok && crypto_aead_decrypt(key, iv, aad, sizeof(aad), expected_ct, sizeof(expected_ct),
                                   expected_tag, back) == 0 &&
         memcmp(back, pt, sizeof(pt)) == 0;
    return ok;
}

/* Encrypting then decrypting a message gives it back unchanged. */
static bool test_gcm_roundtrip(void)
{
    static const uint8_t key[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    static const uint8_t nonce[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const uint8_t aad[] = "header";
    static const uint8_t msg[] = "Hola Bob";
    uint8_t ct[sizeof(msg)];
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    uint8_t back[sizeof(msg)];

    return crypto_aead_encrypt(key, nonce, aad, sizeof(aad), msg, sizeof(msg), ct, tag) == 0 &&
           memcmp(ct, msg, sizeof(msg)) != 0 &&
           crypto_aead_decrypt(key, nonce, aad, sizeof(aad), ct, sizeof(ct), tag, back) == 0 &&
           memcmp(back, msg, sizeof(msg)) == 0;
}

/* Flipping one bit of the ciphertext, the tag or the AAD must make
 * decryption fail with an authentication error and wipe the output. */
static bool test_gcm_tamper(void)
{
    static const uint8_t key[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    static const uint8_t nonce[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    static const uint8_t msg[] = "Hola Bob";
    uint8_t aad[] = "header";
    uint8_t ct[sizeof(msg)];
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    uint8_t out[sizeof(msg)];

    if (crypto_aead_encrypt(key, nonce, aad, sizeof(aad), msg, sizeof(msg), ct, tag) != 0) {
        return false;
    }

    bool ok = true;
    for (int target = 0; target < 3; target++) {
        uint8_t *byte = target == 0 ? &ct[0] : target == 1 ? &tag[0] : &aad[0];
        *byte ^= 0x01;
        memset(out, 0xAA, sizeof(out));
        int ret = crypto_aead_decrypt(key, nonce, aad, sizeof(aad), ct, sizeof(ct), tag, out);
        ok = ok && ret == MBEDTLS_ERR_GCM_AUTH_FAILED && all_zero(out, sizeof(out));
        *byte ^= 0x01; /* restore for the next case */
    }
    return ok;
}

bool crypto_selftest(void)
{
    bool ok = true;
    ok = report("hmac_rfc4231", test_hmac_rfc4231()) && ok;
    ok = report("hkdf_rfc5869", test_hkdf_rfc5869()) && ok;
    ok = report("gcm_known_answer", test_gcm_known_answer()) && ok;
    ok = report("gcm_roundtrip", test_gcm_roundtrip()) && ok;
    ok = report("gcm_tamper_rejected", test_gcm_tamper()) && ok;
    return ok;
}
