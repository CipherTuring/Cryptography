/*
 * Cryptographic primitives: thin wrappers over mbedTLS.
 *
 * Knows nothing about the protocol or the network. Functions that can fail
 * return 0 on success or an mbedTLS error code.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mbedtls/dhm.h"

/* Diffie-Hellman over RFC 3526 group 14 (2048-bit MODP prime, generator 2).
 * Public values and the shared secret are always exactly this many bytes,
 * big-endian and left-padded with zeros. */
#define CRYPTO_DH_LEN 256

/* Fingerprint for logs: first 4 bytes of SHA-256(label || value), as hex. */
#define CRYPTO_FP_HEX_LEN 9

/* AES-128-GCM. 128-bit keys already exceed the ~112-bit strength of the
 * 2048-bit DH group, so a longer key would not raise the overall level. */
#define CRYPTO_AEAD_KEY_LEN   16
#define CRYPTO_AEAD_NONCE_LEN 12
#define CRYPTO_AEAD_TAG_LEN   16

#define CRYPTO_HMAC_LEN 32 /* HMAC-SHA-256 */

typedef struct {
    mbedtls_dhm_context ctx;
    bool active; /* true while it holds a private key */
} crypto_dh_t;

/* Creates a fresh ephemeral private key (uniform in [2, p-2], from the
 * hardware RNG) and writes the matching public value g^x mod p. */
int crypto_dh_keygen(crypto_dh_t *dh, uint8_t pub[CRYPTO_DH_LEN]);

/* A received public value is acceptable only if 1 < y < p-1; 0, 1 and p-1
 * would force the shared secret into a tiny, predictable set. */
bool crypto_dh_public_is_valid(const uint8_t pub[CRYPTO_DH_LEN]);

/* Computes K_DH = peer_pub^x mod p into exactly CRYPTO_DH_LEN bytes, then
 * destroys the private key (it is never needed again: forward secrecy). */
int crypto_dh_shared(crypto_dh_t *dh, const uint8_t peer_pub[CRYPTO_DH_LEN],
                     uint8_t secret[CRYPTO_DH_LEN]);

/* Destroys the private key, if any. Safe to call more than once. */
void crypto_dh_clear(crypto_dh_t *dh);

/* Fills buf with bytes from the hardware RNG (for nonces). */
void crypto_random(uint8_t *buf, size_t len);

/* HMAC-SHA-256 (RFC 2104). */
int crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len,
                       uint8_t out[CRYPTO_HMAC_LEN]);

/* Compares two buffers in time independent of where they differ, so a
 * forger cannot learn a valid MAC byte by byte from response timing. */
bool crypto_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* HKDF-SHA-256 (RFC 5869): extract with salt, expand with info. */
int crypto_hkdf_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

/* AES-128-GCM. Encrypt writes len bytes of ciphertext plus a 16-byte tag
 * that authenticates both the ciphertext and the AAD. */
int crypto_aead_encrypt(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                        const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t len,
                        uint8_t *ct, uint8_t tag[CRYPTO_AEAD_TAG_LEN]);

/* Returns MBEDTLS_ERR_GCM_AUTH_FAILED if the ciphertext, tag or AAD were
 * altered; in that case pt is wiped, so nothing unverified is ever used.
 * The tag comparison runs in constant time. */
int crypto_aead_decrypt(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                        const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t len,
                        const uint8_t tag[CRYPTO_AEAD_TAG_LEN], uint8_t *pt);

void crypto_fingerprint(const char *label, const uint8_t *data, size_t len,
                        char out[CRYPTO_FP_HEX_LEN]);

/* Known-answer tests (RFC 4231, RFC 5869, GCM spec test case 4) plus
 * round-trip and tamper checks. Logs one SELFTEST line per test; true if
 * all pass. */
bool crypto_selftest(void);

/* Overwrites secret material in a way the compiler cannot optimize away. */
void crypto_zeroize(void *buf, size_t len);
