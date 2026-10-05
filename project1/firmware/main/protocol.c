/*
 * Protocol layer: message formats and the handshake state machine.
 * See protocol.h for the wire messages and the key schedule.
 */
#include "protocol.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "secrets.h"

static const char *TAG_HS = "HS";
static const char *TAG_AUTH = "AUTH";
static const char *TAG_TX = "TX";
static const char *TAG_RX = "RX";
static const char *TAG_SELFTEST = "SELFTEST";

/* HKDF info labels: one per derived value, versioned with the protocol. */
static const char LABEL_KEY_AB[] = "esp32-sm v1 key A->B";
static const char LABEL_KEY_BA[] = "esp32-sm v1 key B->A";
static const char LABEL_SESSION_ID[] = "esp32-sm v1 session-id";

/* Domain-separation prefixes for the two handshake MACs. */
#define MAC_LABEL_LEN 4
static const char LABEL_MAC_A[MAC_LABEL_LEN + 1] = "hs-A";
static const char LABEL_MAC_B[MAC_LABEL_LEN + 1] = "hs-B";

/* Every handshake message starts with type | version | sender_id. */
#define HS_HEADER_LEN 3
#define HS1_LEN (HS_HEADER_LEN + CRYPTO_DH_LEN + PROTO_NONCE_LEN)
#define HS2_LEN (HS1_LEN + CRYPTO_HMAC_LEN)
#define HS3_LEN (HS_HEADER_LEN + CRYPTO_HMAC_LEN)

/* version | ID_A | DH_A | N_A | ID_B | DH_B | N_B */
#define TRANSCRIPT_LEN (2 + CRYPTO_DH_LEN + PROTO_NONCE_LEN + 1 + CRYPTO_DH_LEN + PROTO_NONCE_LEN)
#define MAC_INPUT_MAX  (MAC_LABEL_LEN + TRANSCRIPT_LEN + CRYPTO_HMAC_LEN)

#define LOG_TEXT_MAX 96 /* longest message text shown in a log line */

/* ------------------------------------------------------------------------ */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------ */

const char *proto_state_str(proto_state_t state)
{
    switch (state) {
    case HS_IDLE:          return "IDLE";
    case HS_DH_SENT:       return "DH_SENT";
    case HS_AUTHENTICATED: return "AUTHENTICATED";
    case HS_READY:         return "READY";
    }
    return "?";
}

static const char *msg_name(uint8_t type)
{
    switch (type) {
    case MSG_HS1:   return "HS1";
    case MSG_HS2:   return "HS2";
    case MSG_HS3:   return "HS3";
    case MSG_DATA:  return "DATA";
    case MSG_PLAIN: return "PLAIN";
    }
    return "UNKNOWN";
}

/* Copies a payload into a log-safe string: non-printable bytes become '.',
 * long texts are cut and end in "...". */
static void to_log_text(const uint8_t *data, size_t len, char *out, size_t cap)
{
    size_t shown = len < cap - 4 ? len : cap - 4;
    size_t i;
    for (i = 0; i < shown; i++) {
        out[i] = (data[i] >= 0x20 && data[i] < 0x7f && data[i] != '"') ? (char)data[i] : '.';
    }
    if (shown < len) {
        memcpy(out + i, "...", 3);
        i += 3;
    }
    out[i] = '\0';
}

static int64_t elapsed_us(const proto_session_t *s)
{
    return esp_timer_get_time() - s->hs_start_us;
}

static void set_state(proto_session_t *s, proto_state_t next)
{
    ESP_LOGI(TAG_HS, "state from=%s to=%s", proto_state_str(s->state), proto_state_str(next));
    s->state = next;
}

/* Keys and counters live and die together: a new session restarts both. */
static void wipe_keys(proto_session_t *s)
{
    crypto_zeroize(s->k_send, sizeof(s->k_send));
    crypto_zeroize(s->k_recv, sizeof(s->k_recv));
    crypto_zeroize(s->session_id, sizeof(s->session_id));
    s->send_ctr = 0;
    s->recv_ctr = 0;
    s->last_tx_len = 0;
}

/* Drops every trace of the current handshake and session. */
static void abandon(proto_session_t *s)
{
    crypto_dh_clear(&s->dh);
    wipe_keys(s);
    if (s->state != HS_IDLE) {
        set_state(s, HS_IDLE);
    }
}

/* Rejects a handshake message. While a handshake is in progress this aborts
 * it and asks the caller to close the connection; once the session is READY
 * a stray or replayed handshake message is dropped and the session lives on. */
static const char *fail(proto_session_t *s, const char *tag, uint8_t type, const char *reason)
{
    ESP_LOGE(tag, "reject type=%s reason=%s state=%s", msg_name(type), reason,
             proto_state_str(s->state));
    if (s->state == HS_READY) {
        return NULL;
    }
    abandon(s);
    return "handshake_failed";
}

/* ------------------------------------------------------------------------ */
/* Pre-shared key                                                            */
/* ------------------------------------------------------------------------ */

static bool s_wrong_psk;

static const uint8_t *active_psk(void)
{
    static uint8_t wrong[SM_PSK_LEN];
    if (!s_wrong_psk) {
        return SM_PSK;
    }
    memcpy(wrong, SM_PSK, SM_PSK_LEN);
    wrong[0] ^= 0xFF;
    return wrong;
}

void proto_debug_use_wrong_psk(bool wrong)
{
    s_wrong_psk = wrong;
    ESP_LOGW(TAG_AUTH, "debug psk=%s", wrong ? "wrong" : "correct");
}

/* ------------------------------------------------------------------------ */
/* Key schedule and transcript MACs                                          */
/* ------------------------------------------------------------------------ */

/* Derives K_AB, K_BA and the session id from K_DH (see protocol.h). */
static int derive_keys(const uint8_t k_dh[CRYPTO_DH_LEN], const uint8_t *psk, size_t psk_len,
                       uint8_t k_ab[CRYPTO_AEAD_KEY_LEN], uint8_t k_ba[CRYPTO_AEAD_KEY_LEN],
                       uint8_t session_id[PROTO_SESSION_ID_LEN])
{
    int ret = crypto_hkdf_sha256(psk, psk_len, k_dh, CRYPTO_DH_LEN,
                                 (const uint8_t *)LABEL_KEY_AB, strlen(LABEL_KEY_AB),
                                 k_ab, CRYPTO_AEAD_KEY_LEN);
    if (ret == 0) {
        ret = crypto_hkdf_sha256(psk, psk_len, k_dh, CRYPTO_DH_LEN,
                                 (const uint8_t *)LABEL_KEY_BA, strlen(LABEL_KEY_BA),
                                 k_ba, CRYPTO_AEAD_KEY_LEN);
    }
    if (ret == 0) {
        ret = crypto_hkdf_sha256(psk, psk_len, k_dh, CRYPTO_DH_LEN,
                                 (const uint8_t *)LABEL_SESSION_ID, strlen(LABEL_SESSION_ID),
                                 session_id, PROTO_SESSION_ID_LEN);
    }
    return ret;
}

/* label | version | ID_A | DH_A | N_A | ID_B | DH_B | N_B [| HMAC_B] */
static size_t build_mac_input(const proto_session_t *s, const char *label, bool with_hmac_b,
                              uint8_t out[MAC_INPUT_MAX])
{
    uint8_t *p = out;
    memcpy(p, label, MAC_LABEL_LEN);
    p += MAC_LABEL_LEN;
    *p++ = PROTO_VERSION;
    *p++ = PROTO_ID_A;
    memcpy(p, s->dh_a, CRYPTO_DH_LEN);
    p += CRYPTO_DH_LEN;
    memcpy(p, s->n_a, PROTO_NONCE_LEN);
    p += PROTO_NONCE_LEN;
    *p++ = PROTO_ID_B;
    memcpy(p, s->dh_b, CRYPTO_DH_LEN);
    p += CRYPTO_DH_LEN;
    memcpy(p, s->n_b, PROTO_NONCE_LEN);
    p += PROTO_NONCE_LEN;
    if (with_hmac_b) {
        memcpy(p, s->hmac_b, CRYPTO_HMAC_LEN);
        p += CRYPTO_HMAC_LEN;
    }
    return (size_t)(p - out);
}

/* HMAC_B = HMAC(PSK, "hs-B" | T) */
static int compute_hmac_b(const proto_session_t *s, const uint8_t *psk, size_t psk_len,
                          uint8_t out[CRYPTO_HMAC_LEN])
{
    uint8_t input[MAC_INPUT_MAX];
    size_t len = build_mac_input(s, LABEL_MAC_B, false, input);
    return crypto_hmac_sha256(psk, psk_len, input, len, out);
}

/* HMAC_A = HMAC(PSK, "hs-A" | T | HMAC_B) */
static int compute_hmac_a(const proto_session_t *s, const uint8_t *psk, size_t psk_len,
                          uint8_t out[CRYPTO_HMAC_LEN])
{
    uint8_t input[MAC_INPUT_MAX];
    size_t len = build_mac_input(s, LABEL_MAC_A, true, input);
    return crypto_hmac_sha256(psk, psk_len, input, len, out);
}

/* Checks a received MAC against the expected one, in constant time. */
static bool verify_mac(const uint8_t expected[CRYPTO_HMAC_LEN], const uint8_t *received,
                       const char *peer)
{
    bool ok = crypto_ct_equal(expected, received, CRYPTO_HMAC_LEN);
    if (ok) {
        ESP_LOGI(TAG_AUTH, "hmac_verify peer=%s ok=1", peer);
    } else {
        ESP_LOGE(TAG_AUTH, "hmac_verify peer=%s ok=0", peer);
    }
    return ok;
}

/* ------------------------------------------------------------------------ */
/* Handshake steps                                                           */
/* ------------------------------------------------------------------------ */

/* Fresh ephemeral DH key pair and nonce for this session. */
static bool make_ephemeral(proto_session_t *s, uint8_t pub[CRYPTO_DH_LEN],
                           uint8_t nonce[PROTO_NONCE_LEN])
{
    char fp[CRYPTO_FP_HEX_LEN];
    int64_t t0 = esp_timer_get_time();
    int ret = crypto_dh_keygen(&s->dh, pub);
    int64_t keygen_us = esp_timer_get_time() - t0;
    if (ret != 0) {
        ESP_LOGE(TAG_HS, "keygen failed err=-0x%04x", (unsigned)-ret);
        return false;
    }
    crypto_random(nonce, PROTO_NONCE_LEN);
    crypto_fingerprint("pub", pub, CRYPTO_DH_LEN, fp);
    ESP_LOGI(TAG_HS, "keygen fp_pub=%s us=%lld", fp, keygen_us);
    return true;
}

static bool send_msg(proto_session_t *s, const uint8_t *msg, size_t len)
{
    if (!s->send(s->send_ctx, msg, len)) {
        return false;
    }
    ESP_LOGI(TAG_HS, "sent type=%s len=%u", msg_name(msg[0]), (unsigned)len);
    return true;
}

static void put_header(proto_session_t *s, uint8_t *msg, uint8_t type)
{
    msg[0] = type;
    msg[1] = PROTO_VERSION;
    msg[2] = s->my_id;
}

/* Length, version and sender identity of a handshake message. */
static bool header_ok(proto_session_t *s, const uint8_t *msg, size_t len, size_t expected,
                      const char **close)
{
    if (len != expected) {
        *close = fail(s, TAG_HS, msg[0], "bad_length");
        return false;
    }
    if (msg[1] != PROTO_VERSION) {
        *close = fail(s, TAG_HS, msg[0], "bad_version");
        return false;
    }
    if (msg[2] != s->peer_id) {
        ESP_LOGE(TAG_AUTH, "identity id=0x%02X expected=0x%02X", msg[2], s->peer_id);
        *close = fail(s, TAG_AUTH, msg[0], "unknown_id");
        return false;
    }
    return true;
}

/* The peer's DH public value must satisfy 1 < y < p-1. */
static bool public_ok(proto_session_t *s, uint8_t type, const uint8_t *pub, const char **close)
{
    char fp[CRYPTO_FP_HEX_LEN];
    bool valid = crypto_dh_public_is_valid(pub);
    crypto_fingerprint("pub", pub, CRYPTO_DH_LEN, fp);
    ESP_LOGI(TAG_HS, "pub_recv type=%s from=0x%02X fp_pub=%s valid=%d", msg_name(type),
             s->peer_id, fp, valid);
    if (!valid) {
        *close = fail(s, TAG_HS, type, "bad_public");
        return false;
    }
    return true;
}

/* Computes K_DH (destroying our private key), derives the session keys
 * from it, then wipes K_DH: only the derived keys outlive this function. */
static bool derive_session(proto_session_t *s)
{
    const uint8_t *peer_pub = s->role == PROTO_ROLE_A ? s->dh_b : s->dh_a;
    uint8_t k_dh[CRYPTO_DH_LEN];
    uint8_t k_ab[CRYPTO_AEAD_KEY_LEN];
    uint8_t k_ba[CRYPTO_AEAD_KEY_LEN];
    char fp[CRYPTO_FP_HEX_LEN];
    char fp_ab[CRYPTO_FP_HEX_LEN];
    char fp_ba[CRYPTO_FP_HEX_LEN];
    bool ok = false;

    int64_t t0 = esp_timer_get_time();
    int ret = crypto_dh_shared(&s->dh, peer_pub, k_dh);
    int64_t shared_us = esp_timer_get_time() - t0;
    if (ret != 0) {
        ESP_LOGE(TAG_HS, "shared failed err=-0x%04x", (unsigned)-ret);
        goto out;
    }
    crypto_fingerprint("kdh", k_dh, sizeof(k_dh), fp);
    ESP_LOGI(TAG_HS, "shared fp_kdh=%s us=%lld", fp, shared_us);

    t0 = esp_timer_get_time();
    ret = derive_keys(k_dh, active_psk(), SM_PSK_LEN, k_ab, k_ba, s->session_id);
    int64_t kdf_us = esp_timer_get_time() - t0;
    if (ret != 0) {
        ESP_LOGE(TAG_HS, "kdf failed err=-0x%04x", (unsigned)-ret);
        goto out;
    }
    memcpy(s->k_send, s->role == PROTO_ROLE_A ? k_ab : k_ba, CRYPTO_AEAD_KEY_LEN);
    memcpy(s->k_recv, s->role == PROTO_ROLE_A ? k_ba : k_ab, CRYPTO_AEAD_KEY_LEN);

    /* Same field order on both boards, so the two panels can be compared. */
    crypto_fingerprint("key", k_ab, sizeof(k_ab), fp_ab);
    crypto_fingerprint("key", k_ba, sizeof(k_ba), fp_ba);
    ESP_LOGI(TAG_HS, "kdf fp_kab=%s fp_kba=%s sid=%02x%02x%02x%02x%02x%02x%02x%02x us=%lld",
             fp_ab, fp_ba, s->session_id[0], s->session_id[1], s->session_id[2],
             s->session_id[3], s->session_id[4], s->session_id[5], s->session_id[6],
             s->session_id[7], kdf_us);
    ok = true;

out:
    crypto_zeroize(k_dh, sizeof(k_dh));
    crypto_zeroize(k_ab, sizeof(k_ab));
    crypto_zeroize(k_ba, sizeof(k_ba));
    if (!ok) {
        wipe_keys(s);
    }
    return ok;
}

static void complete(proto_session_t *s)
{
    set_state(s, HS_READY);
    ESP_LOGI(TAG_HS, "complete total_us=%lld", elapsed_us(s));
}

/* A: open the handshake with HS1. */
const char *proto_start_handshake(proto_session_t *s)
{
    if (s->role != PROTO_ROLE_A || !s->send || s->state != HS_IDLE) {
        return "bad_state";
    }
    if (!make_ephemeral(s, s->dh_a, s->n_a)) {
        return fail(s, TAG_HS, MSG_HS1, "internal_error");
    }

    uint8_t msg[HS1_LEN];
    put_header(s, msg, MSG_HS1);
    memcpy(msg + HS_HEADER_LEN, s->dh_a, CRYPTO_DH_LEN);
    memcpy(msg + HS_HEADER_LEN + CRYPTO_DH_LEN, s->n_a, PROTO_NONCE_LEN);
    if (!send_msg(s, msg, sizeof(msg))) {
        abandon(s);
        return "send_failed";
    }
    set_state(s, HS_DH_SENT);
    return NULL;
}

/* B: answer HS1 with our DH value and HMAC_B, then derive the session keys
 * (they stay unused until A proves knowledge of the PSK in HS3). */
static const char *handle_hs1(proto_session_t *s, const uint8_t *msg, size_t len)
{
    const char *close = NULL;
    if (s->role != PROTO_ROLE_B || s->state != HS_IDLE) {
        return fail(s, TAG_HS, MSG_HS1, "bad_state");
    }
    if (!header_ok(s, msg, len, HS1_LEN, &close)) {
        return close;
    }
    memcpy(s->dh_a, msg + HS_HEADER_LEN, CRYPTO_DH_LEN);
    memcpy(s->n_a, msg + HS_HEADER_LEN + CRYPTO_DH_LEN, PROTO_NONCE_LEN);
    if (!public_ok(s, MSG_HS1, s->dh_a, &close)) {
        return close;
    }
    if (!make_ephemeral(s, s->dh_b, s->n_b) ||
        compute_hmac_b(s, active_psk(), SM_PSK_LEN, s->hmac_b) != 0) {
        return fail(s, TAG_HS, MSG_HS1, "internal_error");
    }

    uint8_t reply[HS2_LEN];
    put_header(s, reply, MSG_HS2);
    memcpy(reply + HS_HEADER_LEN, s->dh_b, CRYPTO_DH_LEN);
    memcpy(reply + HS_HEADER_LEN + CRYPTO_DH_LEN, s->n_b, PROTO_NONCE_LEN);
    memcpy(reply + HS1_LEN, s->hmac_b, CRYPTO_HMAC_LEN);
    if (!send_msg(s, reply, sizeof(reply))) {
        abandon(s);
        return "send_failed";
    }
    if (!derive_session(s)) {
        return fail(s, TAG_HS, MSG_HS1, "internal_error");
    }
    set_state(s, HS_DH_SENT);
    return NULL;
}

/* A: check HMAC_B before doing any expensive DH work, then derive the
 * session keys and confirm with HMAC_A. */
static const char *handle_hs2(proto_session_t *s, const uint8_t *msg, size_t len)
{
    const char *close = NULL;
    if (s->role != PROTO_ROLE_A || s->state != HS_DH_SENT) {
        return fail(s, TAG_HS, MSG_HS2, "bad_state");
    }
    if (!header_ok(s, msg, len, HS2_LEN, &close)) {
        return close;
    }
    memcpy(s->dh_b, msg + HS_HEADER_LEN, CRYPTO_DH_LEN);
    memcpy(s->n_b, msg + HS_HEADER_LEN + CRYPTO_DH_LEN, PROTO_NONCE_LEN);
    if (!public_ok(s, MSG_HS2, s->dh_b, &close)) {
        return close;
    }

    uint8_t expected[CRYPTO_HMAC_LEN];
    if (compute_hmac_b(s, active_psk(), SM_PSK_LEN, expected) != 0) {
        return fail(s, TAG_HS, MSG_HS2, "internal_error");
    }
    if (!verify_mac(expected, msg + HS1_LEN, "B")) {
        return fail(s, TAG_AUTH, MSG_HS2, "bad_hmac");
    }
    memcpy(s->hmac_b, msg + HS1_LEN, CRYPTO_HMAC_LEN);

    if (!derive_session(s)) {
        return fail(s, TAG_HS, MSG_HS2, "internal_error");
    }
    set_state(s, HS_AUTHENTICATED);

    uint8_t reply[HS3_LEN];
    put_header(s, reply, MSG_HS3);
    if (compute_hmac_a(s, active_psk(), SM_PSK_LEN, reply + HS_HEADER_LEN) != 0) {
        return fail(s, TAG_HS, MSG_HS2, "internal_error");
    }
    if (!send_msg(s, reply, sizeof(reply))) {
        abandon(s);
        return "send_failed";
    }
    complete(s);
    return NULL;
}

/* B: A proved it knows the PSK and saw our exact DH value and nonce. */
static const char *handle_hs3(proto_session_t *s, const uint8_t *msg, size_t len)
{
    const char *close = NULL;
    if (s->role != PROTO_ROLE_B || s->state != HS_DH_SENT) {
        return fail(s, TAG_HS, MSG_HS3, "bad_state");
    }
    if (!header_ok(s, msg, len, HS3_LEN, &close)) {
        return close;
    }

    uint8_t expected[CRYPTO_HMAC_LEN];
    if (compute_hmac_a(s, active_psk(), SM_PSK_LEN, expected) != 0) {
        return fail(s, TAG_HS, MSG_HS3, "internal_error");
    }
    if (!verify_mac(expected, msg + HS_HEADER_LEN, "A")) {
        return fail(s, TAG_AUTH, MSG_HS3, "bad_hmac");
    }
    set_state(s, HS_AUTHENTICATED);
    complete(s);
    return NULL;
}

/* ------------------------------------------------------------------------ */
/* Session lifecycle                                                         */
/* ------------------------------------------------------------------------ */

void proto_init(proto_session_t *s, proto_role_t role)
{
    memset(s, 0, sizeof(*s));
    s->role = role;
    s->my_id = role == PROTO_ROLE_A ? PROTO_ID_A : PROTO_ID_B;
    s->peer_id = role == PROTO_ROLE_A ? PROTO_ID_B : PROTO_ID_A;
    s->state = HS_IDLE;
}

void proto_reset(proto_session_t *s, proto_send_fn send, void *send_ctx)
{
    crypto_dh_clear(&s->dh);
    wipe_keys(s);
    s->state = HS_IDLE;
    s->send = send;
    s->send_ctx = send_ctx;
    s->hs_start_us = esp_timer_get_time();
    s->hs_deadline_us = s->hs_start_us + (int64_t)PROTO_HANDSHAKE_TIMEOUT_MS * 1000;
}

const char *proto_poll(proto_session_t *s)
{
    if (!s->send || s->state == HS_READY || esp_timer_get_time() < s->hs_deadline_us) {
        return NULL;
    }
    ESP_LOGW(TAG_HS, "timeout state=%s after_ms=%lld", proto_state_str(s->state),
             elapsed_us(s) / 1000);
    abandon(s);
    return "handshake_timeout";
}

/* ------------------------------------------------------------------------ */
/* Secure messages                                                           */
/* ------------------------------------------------------------------------ */

#define DATA_SESSION_OFFSET 3
#define DATA_COUNTER_OFFSET (DATA_SESSION_OFFSET + PROTO_SESSION_ID_LEN)

static void put_u64_be(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static uint64_t get_u64_be(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

/* 12-byte GCM nonce: four zero bytes, then the 64-bit counter. Unique per
 * key because each direction has its own key and counters never repeat. */
static void make_nonce(uint64_t counter, uint8_t nonce[CRYPTO_AEAD_NONCE_LEN])
{
    memset(nonce, 0, CRYPTO_AEAD_NONCE_LEN - 8);
    put_u64_be(nonce + CRYPTO_AEAD_NONCE_LEN - 8, counter);
}

/* Hex for logs: at most max_bytes, then "..". */
static void to_hex(const uint8_t *data, size_t len, size_t max_bytes, char *out, size_t cap)
{
    size_t shown = len < max_bytes ? len : max_bytes;
    size_t n = 0;
    for (size_t i = 0; i < shown && n + 3 <= cap; i++) {
        n += snprintf(out + n, cap - n, "%02x", data[i]);
    }
    if (shown < len && n + 3 <= cap) {
        n += snprintf(out + n, cap - n, "..");
    }
    out[n] = '\0';
}

static bool s_plain_mode;

void proto_set_plain_mode(bool plain)
{
    s_plain_mode = plain;
    ESP_LOGW(TAG_TX, "mode=%s", plain ? "plain (NO protection, baseline only)" : "secure");
}

bool proto_plain_mode(void)
{
    return s_plain_mode;
}

static bool send_plain(proto_session_t *s, const uint8_t *text, size_t len)
{
    uint8_t msg[1 + PROTO_MAX_TEXT];
    msg[0] = MSG_PLAIN;
    memcpy(msg + 1, text, len);
    if (!s->send(s->send_ctx, msg, 1 + len)) {
        return false;
    }
    char shown[LOG_TEXT_MAX];
    to_log_text(text, len, shown, sizeof(shown));
    ESP_LOGI(TAG_TX, "send mode=plain len=%u pt=\"%s\"", (unsigned)len, shown);
    return true;
}

/* Builds a DATA frame for text into out (PROTO_DATA_OVERHEAD + len bytes),
 * consuming the next send counter. The counter is consumed first, so it is
 * never reused even if encryption or sending fails afterwards. */
static bool seal_data(proto_session_t *s, const uint8_t *text, size_t len, uint8_t *out,
                      uint64_t *ctr_out, int64_t *enc_us)
{
    if (s->send_ctr == UINT64_MAX) {
        ESP_LOGE(TAG_TX, "send rejected reason=counter_exhausted");
        return false;
    }
    uint64_t ctr = ++s->send_ctr;
    out[0] = MSG_DATA;
    out[1] = PROTO_VERSION;
    out[2] = s->my_id;
    memcpy(out + DATA_SESSION_OFFSET, s->session_id, PROTO_SESSION_ID_LEN);
    put_u64_be(out + DATA_COUNTER_OFFSET, ctr);

    uint8_t nonce[CRYPTO_AEAD_NONCE_LEN];
    make_nonce(ctr, nonce);
    uint8_t *ct = out + PROTO_DATA_HEADER_LEN;
    int64_t t0 = esp_timer_get_time();
    int ret = crypto_aead_encrypt(s->k_send, nonce, out, PROTO_DATA_HEADER_LEN, text, len, ct, ct + len);
    *enc_us = esp_timer_get_time() - t0;
    if (ret != 0) {
        ESP_LOGE(TAG_TX, "send failed reason=encrypt_error err=-0x%04x", (unsigned)-ret);
        return false;
    }
    *ctr_out = ctr;
    return true;
}

bool proto_send_text(proto_session_t *s, const uint8_t *text, size_t len)
{
    if (s->state != HS_READY || !s->send) {
        ESP_LOGW(TAG_TX, "send rejected reason=handshake_incomplete state=%s",
                 proto_state_str(s->state));
        return false;
    }
    if (len == 0 || len > PROTO_MAX_TEXT) {
        ESP_LOGW(TAG_TX, "send rejected reason=bad_length len=%u max=%d", (unsigned)len,
                 PROTO_MAX_TEXT);
        return false;
    }
    if (s_plain_mode) {
        return send_plain(s, text, len);
    }

    uint64_t ctr = 0;
    int64_t enc_us = 0;
    s->last_tx_len = 0;
    if (!seal_data(s, text, len, s->last_tx, &ctr, &enc_us)) {
        return false;
    }
    s->last_tx_len = PROTO_DATA_OVERHEAD + len;
    if (!s->send(s->send_ctx, s->last_tx, s->last_tx_len)) {
        return false;
    }

    const uint8_t *ct = s->last_tx + PROTO_DATA_HEADER_LEN;
    char shown[LOG_TEXT_MAX];
    char ct_hex[2 * 16 + 3];
    char tag_hex[2 * CRYPTO_AEAD_TAG_LEN + 1];
    to_log_text(text, len, shown, sizeof(shown));
    to_hex(ct, len, 16, ct_hex, sizeof(ct_hex));
    to_hex(ct + len, CRYPTO_AEAD_TAG_LEN, CRYPTO_AEAD_TAG_LEN, tag_hex, sizeof(tag_hex));
    ESP_LOGI(TAG_TX, "send ctr=%llu len=%u frame=%u pt=\"%s\" ct=%s tag=%s us=%lld", ctr,
             (unsigned)len, (unsigned)s->last_tx_len, shown, ct_hex, tag_hex, enc_us);
    return true;
}

/* Every check a received DATA message goes through, in order. */
enum { CHK_FRAME, CHK_STATE, CHK_SENDER, CHK_SESSION, CHK_COUNTER, CHK_TAG, CHK_COUNT };
static const char *const CHECK_NAMES[CHK_COUNT] = {
    "frame", "state", "sender", "session", "counter", "tag",
};

static void handle_data(proto_session_t *s, const uint8_t *msg, size_t len)
{
    const char *res[CHK_COUNT] = { "-", "-", "-", "-", "-", "-" }; /* "-" = not reached */
    const char *reason = NULL;
    uint64_t ctr = len >= PROTO_DATA_HEADER_LEN ? get_u64_be(msg + DATA_COUNTER_OFFSET) : 0;
    size_t ct_len = len >= PROTO_DATA_OVERHEAD ? len - PROTO_DATA_OVERHEAD : 0;
    uint8_t pt[PROTO_MAX_TEXT];
    int64_t dec_us = 0;
    int i = 0;

#define CHECK(ok, why) \
    do { \
        if (!(ok)) { res[i] = "FAIL"; reason = (why); goto done; } \
        res[i++] = "ok"; \
    } while (0)

    CHECK(len >= PROTO_DATA_OVERHEAD && msg[1] == PROTO_VERSION,
          len < PROTO_DATA_OVERHEAD ? "malformed" : "bad_version");
    CHECK(s->state == HS_READY, "bad_state");
    CHECK(msg[2] == s->peer_id, "bad_sender");
    CHECK(crypto_ct_equal(msg + DATA_SESSION_OFFSET, s->session_id, PROTO_SESSION_ID_LEN),
          "bad_session");
    CHECK(ctr > s->recv_ctr, "replay");

    uint8_t nonce[CRYPTO_AEAD_NONCE_LEN];
    make_nonce(ctr, nonce);
    int64_t t0 = esp_timer_get_time();
    int ret = crypto_aead_decrypt(s->k_recv, nonce, msg, PROTO_DATA_HEADER_LEN,
                                  msg + PROTO_DATA_HEADER_LEN, ct_len,
                                  msg + PROTO_DATA_HEADER_LEN + ct_len, pt);
    dec_us = esp_timer_get_time() - t0;
    CHECK(ret == 0, "tag_fail");
#undef CHECK

    /* Only an authentic message may move the replay window forward. */
    s->recv_ctr = ctr;

done:;
    char checks[96];
    size_t n = 0;
    for (int c = 0; c < CHK_COUNT; c++) {
        n += snprintf(checks + n, sizeof(checks) - n, "%s%s=%s", c ? " " : "", CHECK_NAMES[c], res[c]);
    }
    if (!reason) {
        char shown[LOG_TEXT_MAX];
        to_log_text(pt, ct_len, shown, sizeof(shown));
        ESP_LOGI(TAG_RX, "recv ctr=%llu len=%u %s -> ACCEPT pt=\"%s\" us=%lld", ctr,
                 (unsigned)ct_len, checks, shown, dec_us);
    } else {
        ESP_LOGE(TAG_RX, "recv ctr=%llu len=%u %s -> REJECT reason=%s last=%llu", ctr,
                 (unsigned)ct_len, checks, reason, s->recv_ctr);
    }
    crypto_zeroize(pt, sizeof(pt));
}

static void handle_plain(proto_session_t *s, const uint8_t *msg, size_t len)
{
    /* In secure mode a plaintext message is an injection attempt. */
    if (!s_plain_mode || s->state != HS_READY) {
        ESP_LOGE(TAG_RX, "recv mode=plain len=%u -> REJECT reason=%s", (unsigned)(len - 1),
                 !s_plain_mode ? "plain_disabled" : "bad_state");
        return;
    }
    char shown[LOG_TEXT_MAX];
    to_log_text(msg + 1, len - 1, shown, sizeof(shown));
    ESP_LOGI(TAG_RX, "recv mode=plain len=%u pt=\"%s\"", (unsigned)(len - 1), shown);
}

/* ------------------------------------------------------------------------ */
/* Test-only injection (replay / tamper with the real boards)               */
/* ------------------------------------------------------------------------ */

bool proto_debug_replay(proto_session_t *s)
{
    if (s->state != HS_READY || s->last_tx_len == 0) {
        ESP_LOGW(TAG_TX, "debug inject=replay skipped reason=no_message_sent_yet");
        return false;
    }
    ESP_LOGW(TAG_TX, "debug inject=replay ctr=%llu",
             get_u64_be(s->last_tx + DATA_COUNTER_OFFSET));
    return s->send(s->send_ctx, s->last_tx, s->last_tx_len);
}

/* Simulates a man in the middle: seals a brand-new message (next counter,
 * so the receiver has not seen it) and alters one field in transit. */
bool proto_debug_tamper(proto_session_t *s, const char *field)
{
    static const uint8_t text[] = "tampered in transit";
    const size_t len = sizeof(text) - 1;
    if (strcmp(field, "ct") != 0 && strcmp(field, "tag") != 0 && strcmp(field, "ctr") != 0 &&
        strcmp(field, "sid") != 0 && strcmp(field, "sender") != 0) {
        return false;
    }
    if (s->state != HS_READY) {
        ESP_LOGW(TAG_TX, "debug inject=tamper skipped reason=handshake_incomplete");
        return false;
    }

    uint8_t frame[PROTO_DATA_OVERHEAD + sizeof(text)];
    size_t n = PROTO_DATA_OVERHEAD + len;
    uint64_t ctr = 0;
    int64_t enc_us = 0;
    if (!seal_data(s, text, len, frame, &ctr, &enc_us)) {
        return false;
    }

    if (strcmp(field, "ct") == 0) {
        frame[PROTO_DATA_HEADER_LEN] ^= 0x01; /* first ciphertext byte */
    } else if (strcmp(field, "tag") == 0) {
        frame[n - 1] ^= 0x01; /* last tag byte */
    } else if (strcmp(field, "ctr") == 0) {
        put_u64_be(frame + DATA_COUNTER_OFFSET, ctr + 100); /* jump the counter ahead */
    } else if (strcmp(field, "sid") == 0) {
        frame[DATA_SESSION_OFFSET] ^= 0x01;
    } else {
        frame[2] = s->peer_id; /* pretend the receiver itself sent it */
    }
    ESP_LOGW(TAG_TX, "debug inject=tamper field=%s ctr=%llu", field, ctr);
    return s->send(s->send_ctx, frame, n);
}

/* ------------------------------------------------------------------------ */
/* Dispatch                                                                  */
/* ------------------------------------------------------------------------ */

const char *proto_handle_frame(proto_session_t *s, const uint8_t *frame, size_t len)
{
    switch (frame[0]) {
    case MSG_HS1:
        return handle_hs1(s, frame, len);
    case MSG_HS2:
        return handle_hs2(s, frame, len);
    case MSG_HS3:
        return handle_hs3(s, frame, len);
    case MSG_DATA:
        handle_data(s, frame, len);
        return NULL;
    case MSG_PLAIN:
        handle_plain(s, frame, len);
        return NULL;
    default:
        ESP_LOGE(TAG_RX, "recv type=0x%02x -> REJECT reason=unknown_type", frame[0]);
        return NULL;
    }
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

/* All expected values were computed with Python (`cryptography` HKDF and
 * the standard hmac module) from the same fixed inputs and labels, so a
 * pass also proves the laptop tools build byte-identical messages. */
static const uint8_t TEST_PSK[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
};

/* Inputs: K_DH = 00 01 02 ... ff, PSK = 32 x 0x11. */
static bool test_key_schedule(void)
{
    static const uint8_t expected_ab[CRYPTO_AEAD_KEY_LEN] = {
        0x30, 0x93, 0xcd, 0x54, 0x4b, 0x3f, 0x9f, 0x99, 0x98, 0x31, 0xe2, 0xa7, 0x72, 0xfb, 0xfa, 0xa3,
    };
    static const uint8_t expected_ba[CRYPTO_AEAD_KEY_LEN] = {
        0x47, 0x3d, 0xdb, 0x3a, 0x14, 0x0c, 0x52, 0x6a, 0x72, 0x64, 0xd0, 0x80, 0x51, 0x7a, 0x24, 0x9f,
    };
    static const uint8_t expected_sid[PROTO_SESSION_ID_LEN] = {
        0xbb, 0x18, 0x17, 0x5a, 0x87, 0xac, 0x9a, 0x7e,
    };

    uint8_t k_dh[CRYPTO_DH_LEN];
    for (size_t i = 0; i < sizeof(k_dh); i++) {
        k_dh[i] = (uint8_t)i;
    }
    uint8_t k_ab[CRYPTO_AEAD_KEY_LEN];
    uint8_t k_ba[CRYPTO_AEAD_KEY_LEN];
    uint8_t sid[PROTO_SESSION_ID_LEN];

    return derive_keys(k_dh, TEST_PSK, sizeof(TEST_PSK), k_ab, k_ba, sid) == 0 &&
           memcmp(k_ab, expected_ab, sizeof(k_ab)) == 0 &&
           memcmp(k_ba, expected_ba, sizeof(k_ba)) == 0 &&
           memcmp(sid, expected_sid, sizeof(sid)) == 0 &&
           memcmp(k_ab, k_ba, sizeof(k_ab)) != 0;
}

/* Inputs: DH_A = 256 x 0xA1, N_A = 00..0f, DH_B = 256 x 0xB2, N_B = 10..1f. */
static bool test_handshake_macs(void)
{
    static const uint8_t expected_b[CRYPTO_HMAC_LEN] = {
        0xdd, 0x64, 0xae, 0x5b, 0xba, 0x0d, 0xb8, 0x5e, 0x84, 0xcc, 0xab, 0x7b, 0x10, 0xb1, 0x5b, 0xc4,
        0x12, 0x6d, 0x12, 0xe4, 0x22, 0x10, 0x29, 0x39, 0x4c, 0x19, 0xd9, 0x9f, 0xe4, 0xa8, 0x9e, 0x8e,
    };
    static const uint8_t expected_a[CRYPTO_HMAC_LEN] = {
        0x65, 0xae, 0x24, 0x3b, 0x52, 0x67, 0x40, 0xb1, 0x93, 0xad, 0xd8, 0x48, 0xe7, 0xa0, 0xce, 0x82,
        0x2b, 0x61, 0x7e, 0x25, 0x8e, 0x12, 0x6e, 0xd5, 0x78, 0x95, 0x5f, 0xfb, 0x4f, 0x52, 0xec, 0x37,
    };
    static proto_session_t t; /* static: the session struct is too big for the stack */
    memset(&t, 0, sizeof(t));
    memset(t.dh_a, 0xA1, sizeof(t.dh_a));
    memset(t.dh_b, 0xB2, sizeof(t.dh_b));
    for (int i = 0; i < PROTO_NONCE_LEN; i++) {
        t.n_a[i] = (uint8_t)i;
        t.n_b[i] = (uint8_t)(0x10 + i);
    }

    uint8_t mac_a[CRYPTO_HMAC_LEN];
    bool ok = compute_hmac_b(&t, TEST_PSK, sizeof(TEST_PSK), t.hmac_b) == 0 &&
              memcmp(t.hmac_b, expected_b, sizeof(expected_b)) == 0 &&
              compute_hmac_a(&t, TEST_PSK, sizeof(TEST_PSK), mac_a) == 0 &&
              memcmp(mac_a, expected_a, sizeof(expected_a)) == 0;

    /* A transcript differing in one bit of DH_B must give a different HMAC_B. */
    uint8_t mac_b2[CRYPTO_HMAC_LEN];
    t.dh_b[0] ^= 0x01;
    ok = ok && compute_hmac_b(&t, TEST_PSK, sizeof(TEST_PSK), mac_b2) == 0 &&
         !crypto_ct_equal(mac_b2, expected_b, sizeof(mac_b2));
    return ok;
}

bool proto_selftest(void)
{
    bool ok = true;
    ok = report("kdf_session_keys", test_key_schedule()) && ok;
    ok = report("handshake_macs", test_handshake_macs()) && ok;
    return ok;
}
