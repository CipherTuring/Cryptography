/*
 * Network layer: Wi-Fi bring-up, TCP sockets and length-prefixed framing.
 *
 * Knows nothing about cryptography. Every frame on the wire is
 *   [length: 4 bytes, big-endian][payload: length bytes]
 * so payloads may contain any byte value (ciphertext included).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"

/* Largest accepted payload. Anything longer is treated as malformed. */
#define NET_MAX_FRAME 512

/* Fixed address of board A (default ESP32 access point address). */
#define NET_AP_IP "192.168.4.1"

typedef enum {
    NET_OK = 0,
    NET_IDLE,           /* no data arrived within the poll interval; not an error */
    NET_CLOSED,         /* peer closed the connection */
    NET_ERR_TRUNCATED,  /* stream stalled in the middle of a frame */
    NET_ERR_BAD_LENGTH, /* length prefix is 0 or larger than NET_MAX_FRAME */
    NET_ERR_IO,         /* socket error */
} net_status_t;

const char *net_status_str(net_status_t status);

/* Wi-Fi. Role A starts the access point; role B joins it with a static IP. */
void net_wifi_start_ap(void);
void net_wifi_start_sta(void);
bool net_wifi_wait_ready(TickType_t timeout);
bool net_wifi_is_ready(void);

/* TCP. All functions return a socket descriptor, or -1 on failure. */
int net_tcp_listen(uint16_t port);
int net_tcp_accept(int listen_sock, char *peer_ip, size_t peer_ip_len);
int net_tcp_connect(const char *ip, uint16_t port);
void net_tcp_close(int sock);

/* Framing. net_recv_frame returns NET_IDLE when nothing arrived for a while,
 * so the caller can keep polling; any other non-OK status ends the
 * connection, because the byte stream can no longer be trusted to be in sync. */
net_status_t net_send_frame(int sock, const uint8_t *payload, size_t len);
net_status_t net_recv_frame(int sock, uint8_t *buf, size_t cap, size_t *out_len);
