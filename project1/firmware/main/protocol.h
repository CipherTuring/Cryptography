/*
 * Protocol layer: message formats and the handshake state machine.
 *
 * Works on byte buffers only. It never touches sockets: frames are handed
 * in by the caller and replies leave through the send callback, so the
 * same logic runs on both roles.
 *
 * Handshake (one per TCP connection, A leads):
 *   HS1  A -> B   type | version | ID_A | DH_A (256) | N_A (16)                 275 B
 *   HS2  B -> A   type | version | ID_B | DH_B (256) | N_B (16) | HMAC_B (32)   307 B
 *   HS3  A -> B   type | version | ID_A | HMAC_A (32)                            35 B
 *
 *   T      = version | ID_A | DH_A | N_A | ID_B | DH_B | N_B   (fixed lengths)
 *   HMAC_B = HMAC-SHA-256(PSK, "hs-B" | T)
 *   HMAC_A = HMAC-SHA-256(PSK, "hs-A" | T | HMAC_B)
 * The MACs cover both DH public values, so a man in the middle cannot swap
 * them, and the fresh nonces make every transcript unique, so recorded
 * handshake messages cannot be replayed. Distinct labels stop a MAC from
 * one role being reflected back as the other's.
 *
 * Session keys, with the PSK as HKDF salt so they depend on both the DH
 * secret and the pre-shared key:
 *   K_AB       = HKDF(salt=PSK, ikm=K_DH, info="esp32-sm v1 key A->B", 16)
 *   K_BA       = HKDF(salt=PSK, ikm=K_DH, info="esp32-sm v1 key B->A", 16)
 *   session_id = HKDF(salt=PSK, ikm=K_DH, info="esp32-sm v1 session-id", 8)
 * One key per direction, so A->B and B->A never share a (key, nonce) pair.
 *
 * Secure messages (READY only):
 *   DATA   type | version | sender_id | session_id (8) | counter (8, BE) | ciphertext | tag (16)
 *          AAD   = the 19-byte header (type .. counter)
 *          nonce = 00 00 00 00 | counter   (derived, never sent)
 *          key   = the sender's direction key (K_AB or K_BA)
 *   Counters are per direction and start at 1. A receiver accepts a counter
 *   only if it is larger than the last accepted one, and records it only
 *   after the tag verifies, so a forged high counter cannot desynchronize
 *   the session. Altering any header byte breaks the tag (it is in the AAD).
 *
 * Baseline (test builds, `mode plain` on both boards, for latency only):
 *   PLAIN  type | text   accepted only while this board is in plain mode.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

#define PROTO_VERSION 1
#define PROTO_ID_A    0x0A
#define PROTO_ID_B    0x0B

#define PROTO_NONCE_LEN      16
#define PROTO_SESSION_ID_LEN 8

/* Largest frame payload; must match NET_MAX_FRAME. */
#define PROTO_MAX_FRAME 512

/* type | version | sender_id | session_id | counter */
#define PROTO_DATA_HEADER_LEN (3 + PROTO_SESSION_ID_LEN + 8)
#define PROTO_DATA_OVERHEAD   (PROTO_DATA_HEADER_LEN + CRYPTO_AEAD_TAG_LEN)
#define PROTO_MAX_TEXT        (PROTO_MAX_FRAME - PROTO_DATA_OVERHEAD)

/* A connection must reach READY within this time or it is closed. */
#define PROTO_HANDSHAKE_TIMEOUT_MS 5000

typedef enum {
    MSG_HS1 = 0x01,
    MSG_HS2 = 0x02,
    MSG_HS3 = 0x03,
    MSG_DATA = 0x10,
    MSG_PLAIN = 0x20,
} proto_msg_type_t;

typedef enum {
    PROTO_ROLE_A, /* starts the handshake as soon as a client connects */
    PROTO_ROLE_B,
} proto_role_t;

typedef enum {
    HS_IDLE,          /* connection open, no handshake message exchanged yet */
    HS_DH_SENT,       /* our DH value is out; waiting for the peer's next message */
    HS_AUTHENTICATED, /* the peer's HMAC checked out (transient) */
    HS_READY,         /* handshake complete: session keys may be used */
} proto_state_t;

/* Sends one frame to the peer; returns false if the connection failed. */
typedef bool (*proto_send_fn)(void *ctx, const uint8_t *data, size_t len);

typedef struct {
    proto_role_t role;
    uint8_t my_id;
    uint8_t peer_id;
    proto_state_t state;
    proto_send_fn send;
    void *send_ctx;

    /* Handshake material, kept until the transcript MACs are checked. */
    crypto_dh_t dh;
    uint8_t dh_a[CRYPTO_DH_LEN];
    uint8_t dh_b[CRYPTO_DH_LEN];
    uint8_t n_a[PROTO_NONCE_LEN];
    uint8_t n_b[PROTO_NONCE_LEN];
    uint8_t hmac_b[CRYPTO_HMAC_LEN];
    int64_t hs_start_us;
    int64_t hs_deadline_us;

    /* Session keys, usable only in READY. */
    uint8_t k_send[CRYPTO_AEAD_KEY_LEN]; /* A: K_AB, B: K_BA */
    uint8_t k_recv[CRYPTO_AEAD_KEY_LEN]; /* A: K_BA, B: K_AB */
    uint8_t session_id[PROTO_SESSION_ID_LEN];
    uint64_t send_ctr; /* counter of the last message sent */
    uint64_t recv_ctr; /* counter of the last message accepted */

    /* Copy of the last DATA frame sent, for the test-only replay/tamper commands. */
    uint8_t last_tx[PROTO_MAX_FRAME];
    size_t last_tx_len;
} proto_session_t;

void proto_init(proto_session_t *s, proto_role_t role);

/* Starts a new connection: forgets all key material, binds the session to
 * a send callback and starts the handshake timer. Pass send = NULL when the
 * connection closes. */
void proto_reset(proto_session_t *s, proto_send_fn send, void *send_ctx);

/* Role A: generates a fresh key pair and nonce and sends HS1. Returns NULL
 * on success, or the reason the connection must be closed. */
const char *proto_start_handshake(proto_session_t *s);

/* Processes one received frame; replies go out via the callback. Returns
 * NULL to keep the connection, or the reason it must be closed (a failed
 * handshake never leaves a half-open session behind). */
const char *proto_handle_frame(proto_session_t *s, const uint8_t *frame, size_t len);

/* Call periodically: returns "handshake_timeout" once the deadline passes
 * without reaching READY, NULL otherwise. */
const char *proto_poll(proto_session_t *s);

/* Sends a text message: encrypted DATA, or PLAIN while in plain mode.
 * Refused before READY and above PROTO_MAX_TEXT bytes. */
bool proto_send_text(proto_session_t *s, const uint8_t *text, size_t len);

const char *proto_state_str(proto_state_t state);

/* Test builds only. */
void proto_set_plain_mode(bool plain); /* latency baseline: no protection at all */
bool proto_plain_mode(void);
void proto_debug_use_wrong_psk(bool wrong); /* play an unauthorized device */
bool proto_debug_replay(proto_session_t *s); /* resend the last DATA frame as-is */
/* Man in the middle: send a new DATA frame (next counter) with one field
 * altered in transit: "ct", "tag", "ctr", "sid" or "sender". */
bool proto_debug_tamper(proto_session_t *s, const char *field);

/* Checks the key derivation and the handshake MACs against vectors
 * computed independently in Python (same labels, fixed inputs). */
bool proto_selftest(void);
