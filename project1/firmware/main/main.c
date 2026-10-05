/*
 * Secure messaging between two ESP32 boards: entry point.
 *
 * Role A: Wi-Fi access point + TCP server (newest connection wins).
 * Role B: Wi-Fi station + TCP client that reconnects on its own.
 * Both: a serial console (`help` lists the commands).
 *
 * This file owns the sockets and the console; message formats and the
 * handshake live in protocol.c, cryptography in crypto.c.
 */
#include <stdio.h>
#include <string.h>

#include "esp_console.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_rom_uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "net.h"
#include "nvs_flash.h"
#include "protocol.h"
#include "sdkconfig.h"

#if CONFIG_SM_ROLE_A
#define ROLE_NAME "A"
#define NODE_ID   0x0A
#else
#define ROLE_NAME "B"
#define NODE_ID   0x0B
#endif

/* DH-2048 and mbedTLS bignum work need more stack than the defaults. */
#define TASK_STACK      8192
#define TASK_PRIORITY   5
#define RECONNECT_MS    2000

static const char *TAG = "MAIN";
static const char *TAG_NET = "NET";
static const char *TAG_HS = "HS";
static const char *TAG_TX = "TX";
static const char *TAG_SELFTEST = "SELFTEST";

/* Active connection and its protocol session, shared by the network task
 * and the console task. Every use of s_sock or s_session happens under
 * s_lock, and the network task clears s_sock under the lock before closing
 * it, so nothing ever sends on a closed socket. */
static SemaphoreHandle_t s_lock;
static int s_sock = -1;
static char s_peer[16];
static char s_target[16] = CONFIG_SM_TARGET_IP; /* role B only */
static proto_session_t s_session;
/* Set when a console command drops the connection on purpose, so the log
 * shows why instead of the resulting socket error. */
static const char *s_close_reason;

_Static_assert(NET_MAX_FRAME == PROTO_MAX_FRAME, "network and protocol frame limits must match");

/* ------------------------------------------------------------------------ */
/* Connection lifecycle                                                      */
/* ------------------------------------------------------------------------ */

/* Send callback handed to the protocol layer; ctx carries the socket. */
static bool send_to_peer(void *ctx, const uint8_t *data, size_t len)
{
    net_status_t st = net_send_frame((int)(intptr_t)ctx, data, len);
    if (st != NET_OK) {
        ESP_LOGE(TAG_NET, "send_failed reason=%s", net_status_str(st));
        return false;
    }
    return true;
}

/* Returns NULL, or the reason the new connection must be closed at once. */
static const char *connection_opened(int sock, const char *peer)
{
    const char *reason = NULL;
    ESP_LOGI(TAG_NET, "tcp state=connected peer=%s", peer);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_sock = sock;
    strlcpy(s_peer, peer, sizeof(s_peer));
    proto_reset(&s_session, send_to_peer, (void *)(intptr_t)sock);
#if CONFIG_SM_ROLE_A
    /* A leads: every new connection starts with a fresh handshake. */
    reason = proto_start_handshake(&s_session);
#endif
    xSemaphoreGive(s_lock);
    return reason;
}

static void connection_closed(int sock, const char *reason)
{
    char peer[sizeof(s_peer)];
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_sock == sock) {
        s_sock = -1;
        proto_reset(&s_session, NULL, NULL); /* keys die with the connection */
        if (s_close_reason) {
            reason = s_close_reason;
            s_close_reason = NULL;
        }
    }
    strlcpy(peer, s_peer, sizeof(peer));
    xSemaphoreGive(s_lock);
    net_tcp_close(sock);
    ESP_LOGW(TAG_NET, "tcp state=closed peer=%s reason=%s", peer, reason);
}

/* Checks the handshake deadline. Returns NULL or the reason to close. */
static const char *poll_session(void)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    const char *reason = proto_poll(&s_session);
    xSemaphoreGive(s_lock);
    return reason;
}

/* Reads at most one frame. Returns NULL to keep the connection, or the
 * reason it must be closed. */
static const char *service_connection(int sock)
{
    static uint8_t buf[NET_MAX_FRAME];
    size_t len = 0;
    const char *reason;

    net_status_t st = net_recv_frame(sock, buf, sizeof(buf), &len);
    switch (st) {
    case NET_OK:
        xSemaphoreTake(s_lock, portMAX_DELAY);
        reason = proto_handle_frame(&s_session, buf, len);
        xSemaphoreGive(s_lock);
        return reason ? reason : poll_session();
    case NET_IDLE:
        return poll_session();
    case NET_ERR_TRUNCATED:
    case NET_ERR_BAD_LENGTH:
        /* Malformed input from the peer (or an attacker): shown in red. */
        ESP_LOGE(TAG_NET, "frame_error reason=%s len=%u", net_status_str(st), (unsigned)len);
        return net_status_str(st);
    default:
        /* Connection lost (peer closed, Wi-Fi dropped): logged by connection_closed. */
        return net_status_str(st);
    }
}

/* ------------------------------------------------------------------------ */
/* Role A: TCP server                                                        */
/* ------------------------------------------------------------------------ */

#if CONFIG_SM_ROLE_A
static void server_task(void *arg)
{
    net_wifi_wait_ready(portMAX_DELAY);

    int listen_sock = net_tcp_listen(CONFIG_SM_TCP_PORT);
    if (listen_sock < 0) {
        ESP_LOGE(TAG_NET, "tcp state=listen_failed port=%d", CONFIG_SM_TCP_PORT);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG_NET, "tcp state=listening port=%d", CONFIG_SM_TCP_PORT);

    int client = -1;
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_sock, &rfds);
        int max_fd = listen_sock;
        if (client >= 0) {
            FD_SET(client, &rfds);
            max_fd = client > max_fd ? client : max_fd;
        }
        struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
        if (select(max_fd + 1, &rfds, NULL, NULL, &timeout) < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        /* A new client replaces the current one: if B rebooted, its old
         * connection is dead anyway, and the attack proxy can take over. */
        if (FD_ISSET(listen_sock, &rfds)) {
            char peer[16];
            int sock = net_tcp_accept(listen_sock, peer, sizeof(peer));
            if (sock >= 0) {
                if (client >= 0) {
                    connection_closed(client, "replaced");
                }
                client = sock;
                const char *reason = connection_opened(client, peer);
                if (reason) {
                    connection_closed(client, reason);
                    client = -1;
                }
            }
        }

        if (client >= 0) {
            /* Without data, still enforce the handshake deadline. */
            const char *reason = FD_ISSET(client, &rfds) ? service_connection(client) : poll_session();
            if (reason) {
                connection_closed(client, reason);
                client = -1;
            }
        }
    }
}
#endif

/* ------------------------------------------------------------------------ */
/* Role B: TCP client                                                        */
/* ------------------------------------------------------------------------ */

#if CONFIG_SM_ROLE_B
static void client_task(void *arg)
{
    for (;;) {
        net_wifi_wait_ready(portMAX_DELAY);

        char target[sizeof(s_target)];
        xSemaphoreTake(s_lock, portMAX_DELAY);
        strlcpy(target, s_target, sizeof(target));
        xSemaphoreGive(s_lock);

        int sock = net_tcp_connect(target, CONFIG_SM_TCP_PORT);
        if (sock < 0) {
            ESP_LOGW(TAG_NET, "tcp state=connect_failed target=%s port=%d retry_ms=%d",
                     target, CONFIG_SM_TCP_PORT, RECONNECT_MS);
            vTaskDelay(pdMS_TO_TICKS(RECONNECT_MS));
            continue;
        }
        const char *reason = connection_opened(sock, target);
        while (!reason) {
            reason = service_connection(sock);
            if (!reason && !net_wifi_is_ready()) {
                reason = "wifi_lost";
            }
        }
        connection_closed(sock, reason);
        vTaskDelay(pdMS_TO_TICKS(RECONNECT_MS));
    }
}
#endif

/* ------------------------------------------------------------------------ */
/* Console commands                                                          */
/* ------------------------------------------------------------------------ */

static int cmd_send(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: send <text>\n");
        return 1;
    }

    /* The console splits on spaces; join the words back into one message. */
    char msg[NET_MAX_FRAME + 1];
    size_t len = 0;
    for (int i = 1; i < argc; i++) {
        int n = snprintf(msg + len, sizeof(msg) - len, "%s%s", i > 1 ? " " : "", argv[i]);
        if (n < 0 || (size_t)n >= sizeof(msg) - len) {
            printf("message longer than %d bytes\n", NET_MAX_FRAME);
            return 1;
        }
        len += (size_t)n;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool connected = s_sock >= 0;
    bool sent = connected && proto_send_text(&s_session, (const uint8_t *)msg, len);
    xSemaphoreGive(s_lock);

    if (!connected) {
        ESP_LOGW(TAG_TX, "send rejected reason=not_connected");
        return 1;
    }
    return sent ? 0 : 1;
}

/* Runs every known-answer and tamper test; logs a final verdict line. */
static bool run_selftest(void)
{
    bool ok = crypto_selftest();
    ok = proto_selftest() && ok;
    if (ok) {
        ESP_LOGI(TAG_SELFTEST, "result=PASS");
    } else {
        ESP_LOGE(TAG_SELFTEST, "result=FAIL");
    }
    return ok;
}

static int cmd_selftest(int argc, char **argv)
{
    return run_selftest() ? 0 : 1;
}

/* One handshake per TCP connection: a new session means a new connection.
 * Dropping it makes B reconnect, and A runs a fresh handshake on accept. */
static int cmd_handshake(int argc, char **argv)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool connected = s_sock >= 0;
    if (connected) {
        ESP_LOGI(TAG_HS, "restart requested by=console action=reconnect");
        s_close_reason = "restart_requested";
        shutdown(s_sock, SHUT_RDWR);
    }
    xSemaphoreGive(s_lock);

    if (!connected) {
        ESP_LOGW(TAG_HS, "restart rejected reason=not_connected");
        return 1;
    }
    return 0;
}

#if CONFIG_SM_TEST_COMMANDS
/* Test-only switches used to stage attacks with the real boards. */
static int cmd_debug(int argc, char **argv)
{
    bool handled = true;
    bool ok = false;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (argc == 3 && strcmp(argv[1], "psk") == 0 &&
        (strcmp(argv[2], "wrong") == 0 || strcmp(argv[2], "ok") == 0)) {
        proto_debug_use_wrong_psk(strcmp(argv[2], "wrong") == 0);
        ok = true;
    } else if (argc == 2 && strcmp(argv[1], "replay") == 0) {
        ok = s_sock >= 0 && proto_debug_replay(&s_session);
    } else if (argc == 3 && strcmp(argv[1], "tamper") == 0) {
        ok = s_sock >= 0 && proto_debug_tamper(&s_session, argv[2]);
    } else {
        handled = false;
    }
    xSemaphoreGive(s_lock);

    if (!handled || (strcmp(argv[1], "tamper") == 0 && !ok)) {
        printf("usage: debug psk wrong|ok\n"
               "       debug replay                         resend the last message as-is\n"
               "       debug tamper ct|tag|ctr|sid|sender   resend it with one field altered\n");
    }
    return ok ? 0 : 1;
}

/* Latency baseline: `mode plain` on both boards sends text unprotected. */
static int cmd_mode(int argc, char **argv)
{
    if (argc == 2 && (strcmp(argv[1], "plain") == 0 || strcmp(argv[1], "secure") == 0)) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        proto_set_plain_mode(strcmp(argv[1], "plain") == 0);
        xSemaphoreGive(s_lock);
        return 0;
    }
    printf("usage: mode plain|secure\n");
    return 1;
}
#endif

static int cmd_connect(int argc, char **argv)
{
#if CONFIG_SM_ROLE_B
    esp_ip4_addr_t ip;
    if (argc != 2 || esp_netif_str_to_ip4(argv[1], &ip) != ESP_OK) {
        printf("usage: connect <ipv4>   e.g. connect 192.168.4.1\n");
        return 1;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    strlcpy(s_target, argv[1], sizeof(s_target));
    if (s_sock >= 0) {
        /* Makes the client task's recv() return, so it reconnects to the new target. */
        s_close_reason = "target_changed";
        shutdown(s_sock, SHUT_RDWR);
    }
    xSemaphoreGive(s_lock);

    ESP_LOGI(TAG_NET, "target ip=%s port=%d", argv[1], CONFIG_SM_TCP_PORT);
    return 0;
#else
    printf("connect is only available on board B\n");
    return 1;
#endif
}

static int cmd_status(int argc, char **argv)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool connected = s_sock >= 0;
    char peer[sizeof(s_peer)];
    char target[sizeof(s_target)];
    strlcpy(peer, s_peer, sizeof(peer));
    strlcpy(target, s_target, sizeof(target));
    const char *hs = proto_state_str(s_session.state);
    unsigned long long tx = s_session.send_ctr;
    unsigned long long rx = s_session.recv_ctr;
    const char *mode = proto_plain_mode() ? "plain" : "secure";
    xSemaphoreGive(s_lock);

#if CONFIG_SM_ROLE_A
    ESP_LOGI(TAG, "status role=%s wifi=%s tcp=%s peer=%s hs=%s mode=%s tx_ctr=%llu rx_ctr=%llu",
             ROLE_NAME, net_wifi_is_ready() ? "up" : "down", connected ? "connected" : "waiting",
             connected ? peer : "-", hs, mode, tx, rx);
#else
    ESP_LOGI(TAG, "status role=%s wifi=%s tcp=%s target=%s hs=%s mode=%s tx_ctr=%llu rx_ctr=%llu",
             ROLE_NAME, net_wifi_is_ready() ? "up" : "down", connected ? "connected" : "connecting",
             target, hs, mode, tx, rx);
#endif
    return 0;
}

static void start_console(void)
{
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = ROLE_NAME ">";
    repl_config.task_stack_size = TASK_STACK; /* `handshake` on A runs DH here */

    ESP_ERROR_CHECK(esp_console_register_help_command());
    const esp_console_cmd_t commands[] = {
        { .command = "send", .help = "Send a text message to the peer", .hint = "<text>", .func = cmd_send },
        { .command = "handshake", .help = "Start a new session (reconnects; A runs a fresh handshake)",
          .func = cmd_handshake },
        { .command = "connect", .help = "(B only) Reconnect to another server, e.g. the laptop proxy",
          .hint = "<ip>", .func = cmd_connect },
        { .command = "status", .help = "Show role, Wi-Fi, TCP and handshake state", .func = cmd_status },
        { .command = "selftest", .help = "Run the cryptographic self-tests again", .func = cmd_selftest },
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        ESP_ERROR_CHECK(esp_console_cmd_register(&commands[i]));
    }
#if CONFIG_SM_TEST_COMMANDS
    const esp_console_cmd_t test_commands[] = {
        { .command = "debug",
          .help = "(test builds) psk wrong|ok: act as an unauthorized device; "
                  "replay / tamper ct|tag|ctr|sid|sender: attack the peer with the last message",
          .hint = "psk wrong|ok | replay | tamper <field>", .func = cmd_debug },
        { .command = "mode", .help = "(test builds) plain = no protection, latency baseline only",
          .hint = "plain|secure", .func = cmd_mode },
    };
    for (size_t i = 0; i < sizeof(test_commands) / sizeof(test_commands[0]); i++) {
        ESP_ERROR_CHECK(esp_console_cmd_register(&test_commands[i]));
    }
#endif

#if defined(CONFIG_ESP_CONSOLE_UART_DEFAULT) || defined(CONFIG_ESP_CONSOLE_UART_CUSTOM)
    esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&hw_config, &repl_config, &repl));
#elif defined(CONFIG_ESP_CONSOLE_USB_CDC)
    esp_console_dev_usb_cdc_config_t hw_config = ESP_CONSOLE_DEV_CDC_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_cdc(&hw_config, &repl_config, &repl));
#elif defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG)
    esp_console_dev_usb_serial_jtag_config_t hw_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&hw_config, &repl_config, &repl));
#else
#error Unsupported console type
#endif
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}

/* ------------------------------------------------------------------------ */
/* Entry point                                                               */
/* ------------------------------------------------------------------------ */

static void init_nvs(void)
{
    /* The Wi-Fi driver keeps calibration data in NVS. */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

void app_main(void)
{
    /* First line on every boot: tells at a glance which board is which. */
    ESP_LOGI(TAG, "role=%s id=0x%02X", ROLE_NAME, NODE_ID);

    s_lock = xSemaphoreCreateMutex();
#if CONFIG_SM_ROLE_A
    proto_init(&s_session, PROTO_ROLE_A);
#else
    proto_init(&s_session, PROTO_ROLE_B);
#endif
    init_nvs();

    /* Installing the console's UART driver drops whatever is still in the
     * TX FIFO, so start it before Wi-Fi begins logging, and only after the
     * line above has fully left the UART. */
#ifdef CONFIG_ESP_CONSOLE_UART_NUM
    fflush(stdout);
    esp_rom_output_tx_wait_idle(CONFIG_ESP_CONSOLE_UART_NUM);
#endif
    start_console();

    /* Fail closed: a board whose cryptography is broken never joins the network. */
    if (!run_selftest()) {
        ESP_LOGE(TAG, "network disabled reason=selftest_failed");
        return;
    }

#if CONFIG_SM_ROLE_A
    net_wifi_start_ap();
    xTaskCreate(server_task, "server", TASK_STACK, NULL, TASK_PRIORITY, NULL);
#else
    net_wifi_start_sta();
    xTaskCreate(client_task, "client", TASK_STACK, NULL, TASK_PRIORITY, NULL);
#endif
}
