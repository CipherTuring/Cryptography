/*
 * Network layer: Wi-Fi bring-up, TCP sockets and length-prefixed framing.
 * See net.h for the frame format.
 */
#include "net.h"

#include <errno.h>
#include <string.h>

#include "dhcpserver/dhcpserver.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"
#include "sdkconfig.h"

static const char *TAG = "NET";

_Static_assert(sizeof(CONFIG_SM_WIFI_PASSWORD) > 8, "WPA2 needs a Wi-Fi password of at least 8 characters");

/* DHCP pool on A, kept away from B's static address. */
#define DHCP_POOL_START "192.168.4.100"
#define DHCP_POOL_END   "192.168.4.120"

#define WIFI_CHANNEL     1
#define AP_MAX_STATIONS  4

/* recv() wakes up this often so the caller can notice idle links;
 * a frame that stalls longer than this halfway through is truncated. */
#define RECV_POLL_SEC 1

/* Detect a peer that vanished without closing (e.g. rebooted): first probe
 * after 5 s of silence, then every 2 s, give up after 3 missed probes. */
#define KEEPALIVE_IDLE_SEC  5
#define KEEPALIVE_INTVL_SEC 2
#define KEEPALIVE_COUNT     3

#define WIFI_READY_BIT BIT0

static EventGroupHandle_t s_wifi_events;

const char *net_status_str(net_status_t status)
{
    switch (status) {
    case NET_OK:             return "ok";
    case NET_IDLE:           return "idle";
    case NET_CLOSED:         return "peer_closed";
    case NET_ERR_TRUNCATED:  return "truncated";
    case NET_ERR_BAD_LENGTH: return "bad_length";
    case NET_ERR_IO:         return "io_error";
    }
    return "unknown";
}

/* ------------------------------------------------------------------------ */
/* Wi-Fi                                                                     */
/* ------------------------------------------------------------------------ */

static void wifi_common_init(void)
{
    s_wifi_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
}

static void wifi_driver_init(void)
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
}

static void ap_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_AP_START) {
        xEventGroupSetBits(s_wifi_events, WIFI_READY_BIT);
        ESP_LOGI(TAG, "wifi state=ap_started ip=%s ssid=%s", NET_AP_IP, CONFIG_SM_WIFI_SSID);
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED) {
        const wifi_event_ap_staconnected_t *e = data;
        ESP_LOGI(TAG, "wifi state=station_joined mac=" MACSTR, MAC2STR(e->mac));
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STADISCONNECTED) {
        const wifi_event_ap_stadisconnected_t *e = data;
        ESP_LOGW(TAG, "wifi state=station_left mac=" MACSTR " reason=%u", MAC2STR(e->mac), e->reason);
    } else if (base == IP_EVENT && id == IP_EVENT_AP_STAIPASSIGNED) {
        /* Only DHCP clients (the laptop) show up here; B uses a static IP. */
        const ip_event_ap_staipassigned_t *e = data;
        ESP_LOGI(TAG, "wifi state=dhcp_assigned ip=" IPSTR " mac=" MACSTR, IP2STR(&e->ip), MAC2STR(e->mac));
    }
}

static void ap_set_dhcp_pool(esp_netif_t *ap)
{
    dhcps_lease_t lease = { .enable = true };
    lease.start_ip.addr = esp_ip4addr_aton(DHCP_POOL_START);
    lease.end_ip.addr = esp_ip4addr_aton(DHCP_POOL_END);

    esp_err_t err = esp_netif_dhcps_stop(ap);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        ESP_ERROR_CHECK(err);
    }
    ESP_ERROR_CHECK(esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_REQUESTED_IP_ADDRESS,
                                           &lease, sizeof(lease)));
    ESP_ERROR_CHECK(esp_netif_dhcps_start(ap));
}

void net_wifi_start_ap(void)
{
    wifi_common_init();
    esp_netif_t *ap = esp_netif_create_default_wifi_ap();
    ap_set_dhcp_pool(ap);
    wifi_driver_init();

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        ap_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED,
                                                        ap_event_handler, NULL, NULL));

    wifi_config_t cfg = { 0 };
    strlcpy((char *)cfg.ap.ssid, CONFIG_SM_WIFI_SSID, sizeof(cfg.ap.ssid));
    cfg.ap.ssid_len = strlen(CONFIG_SM_WIFI_SSID);
    strlcpy((char *)cfg.ap.password, CONFIG_SM_WIFI_PASSWORD, sizeof(cfg.ap.password));
    cfg.ap.channel = WIFI_CHANNEL;
    cfg.ap.max_connection = AP_MAX_STATIONS;
    cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
}

static void sta_set_static_ip(esp_netif_t *sta)
{
    esp_err_t err = esp_netif_dhcpc_stop(sta);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        ESP_LOGE(TAG, "wifi state=static_ip_failed err=%s", esp_err_to_name(err));
        return;
    }
    esp_netif_ip_info_t ip = { 0 };
    ESP_ERROR_CHECK(esp_netif_str_to_ip4(CONFIG_SM_B_IP, &ip.ip));
    ESP_ERROR_CHECK(esp_netif_str_to_ip4(NET_AP_IP, &ip.gw));
    ESP_ERROR_CHECK(esp_netif_str_to_ip4("255.255.255.0", &ip.netmask));
    ESP_ERROR_CHECK(esp_netif_set_ip_info(sta, &ip));
}

static void sta_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    esp_netif_t *sta = arg;

    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "wifi state=connecting ssid=%s", CONFIG_SM_WIFI_SSID);
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) {
        sta_set_static_ip(sta);
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *e = data;
        bool was_ready = xEventGroupGetBits(s_wifi_events) & WIFI_READY_BIT;
        xEventGroupClearBits(s_wifi_events, WIFI_READY_BIT);
        if (was_ready) {
            ESP_LOGW(TAG, "wifi state=disconnected reason=%u", e->reason);
        }
        /* Keep retrying silently until A's access point is back (each
         * attempt includes a scan, so this does not spin). */
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        /* Setting the static IP can raise this event more than once per association. */
        if (xEventGroupGetBits(s_wifi_events) & WIFI_READY_BIT) {
            return;
        }
        wifi_ap_record_t ap_info = { 0 };
        esp_wifi_sta_get_ap_info(&ap_info);
        xEventGroupSetBits(s_wifi_events, WIFI_READY_BIT);
        ESP_LOGI(TAG, "wifi state=connected ip=%s rssi=%d", CONFIG_SM_B_IP, ap_info.rssi);
    }
}

void net_wifi_start_sta(void)
{
    wifi_common_init();
    esp_netif_t *sta = esp_netif_create_default_wifi_sta();
    wifi_driver_init();

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        sta_event_handler, sta, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        sta_event_handler, sta, NULL));

    wifi_config_t cfg = { 0 };
    strlcpy((char *)cfg.sta.ssid, CONFIG_SM_WIFI_SSID, sizeof(cfg.sta.ssid));
    strlcpy((char *)cfg.sta.password, CONFIG_SM_WIFI_PASSWORD, sizeof(cfg.sta.password));
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
}

bool net_wifi_wait_ready(TickType_t timeout)
{
    EventBits_t bits = xEventGroupWaitBits(s_wifi_events, WIFI_READY_BIT, pdFALSE, pdTRUE, timeout);
    return bits & WIFI_READY_BIT;
}

bool net_wifi_is_ready(void)
{
    return xEventGroupGetBits(s_wifi_events) & WIFI_READY_BIT;
}

/* ------------------------------------------------------------------------ */
/* TCP                                                                       */
/* ------------------------------------------------------------------------ */

static void configure_socket(int sock)
{
    int on = 1;
    int idle = KEEPALIVE_IDLE_SEC;
    int intvl = KEEPALIVE_INTVL_SEC;
    int count = KEEPALIVE_COUNT;
    struct timeval poll = { .tv_sec = RECV_POLL_SEC, .tv_usec = 0 };

    /* Short text messages: send immediately instead of batching (lower latency). */
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &poll, sizeof(poll));
}

int net_tcp_listen(uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(sock, 1) != 0) {
        close(sock);
        return -1;
    }
    return sock;
}

int net_tcp_accept(int listen_sock, char *peer_ip, size_t peer_ip_len)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int sock = accept(listen_sock, (struct sockaddr *)&addr, &addr_len);
    if (sock < 0) {
        return -1;
    }
    inet_ntoa_r(addr.sin_addr, peer_ip, peer_ip_len);
    configure_socket(sock);
    return sock;
}

int net_tcp_connect(const char *ip, uint16_t port)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        return -1;
    }
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }
    configure_socket(sock);
    return sock;
}

void net_tcp_close(int sock)
{
    if (sock >= 0) {
        shutdown(sock, SHUT_RDWR);
        close(sock);
    }
}

/* ------------------------------------------------------------------------ */
/* Framing                                                                   */
/* ------------------------------------------------------------------------ */

/* Reads exactly n bytes. With allow_idle, a timeout before the first byte
 * means "nothing to read yet" (NET_IDLE); a timeout after some bytes means
 * the sender stalled mid-frame (NET_ERR_TRUNCATED). */
static net_status_t recv_exact(int sock, uint8_t *buf, size_t n, bool allow_idle)
{
    size_t got = 0;
    while (got < n) {
        int r = recv(sock, buf + got, n - got, 0);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        if (r == 0) {
            return got ? NET_ERR_TRUNCATED : NET_CLOSED;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return (got == 0 && allow_idle) ? NET_IDLE : NET_ERR_TRUNCATED;
        }
        return NET_ERR_IO;
    }
    return NET_OK;
}

net_status_t net_send_frame(int sock, const uint8_t *payload, size_t len)
{
    if (len == 0 || len > NET_MAX_FRAME) {
        return NET_ERR_BAD_LENGTH;
    }

    /* Header and payload in one buffer so they leave in a single segment. */
    uint8_t frame[4 + NET_MAX_FRAME];
    frame[0] = (uint8_t)(len >> 24);
    frame[1] = (uint8_t)(len >> 16);
    frame[2] = (uint8_t)(len >> 8);
    frame[3] = (uint8_t)len;
    memcpy(frame + 4, payload, len);

    size_t total = 4 + len;
    size_t sent = 0;
    while (sent < total) {
        int r = send(sock, frame + sent, total - sent, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NET_ERR_IO;
        }
        sent += (size_t)r;
    }
    return NET_OK;
}

net_status_t net_recv_frame(int sock, uint8_t *buf, size_t cap, size_t *out_len)
{
    uint8_t hdr[4];
    *out_len = 0;

    net_status_t st = recv_exact(sock, hdr, sizeof(hdr), true);
    if (st != NET_OK) {
        return st;
    }

    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    if (len == 0 || len > NET_MAX_FRAME || len > cap) {
        *out_len = len; /* reported so the caller can log the claimed length */
        return NET_ERR_BAD_LENGTH;
    }

    st = recv_exact(sock, buf, len, false);
    if (st == NET_OK) {
        *out_len = len;
    }
    return st;
}
