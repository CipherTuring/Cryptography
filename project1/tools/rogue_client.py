"""Unauthorized-device test harness for the two-ESP32 secure messaging project.

Course Project 1 requires showing that an unauthorized device is not
accepted. This script speaks this project's handshake to board A from the
laptop but deliberately fails one requirement, so A's rejection can be
observed. It proves the PSK + HMAC authentication and the state machine
reject anyone who cannot prove knowledge of the shared key, or who skips
the handshake.

    python rogue_client.py --bad-psk       wrong pre-shared key   -> A: bad_hmac
    python rogue_client.py --bad-id        unknown device id      -> A: unknown_id
    python rogue_client.py --data-first    data before handshake  -> A: bad_state

Run it with the laptop on the boards' Wi-Fi network, pointing at A
(192.168.4.1). Stdlib only; it never learns the real PSK and never
completes a session.
"""
import argparse
import hashlib
import hmac
import secrets
import socket

HOST_DEFAULT = "192.168.4.1"
PORT = 5000
VERSION = 1
ID_A, ID_B = 0x0A, 0x0B
MSG_HS1, MSG_HS2, MSG_DATA = 0x01, 0x02, 0x10
DH_LEN, NONCE_LEN, HMAC_LEN = 256, 16, 32
HS1_LEN = 3 + DH_LEN + NONCE_LEN       # 275
DATA_HEADER = 19


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_frame(sock):
    hdr = recv_exact(sock, 4)
    if hdr is None:
        return None
    return recv_exact(sock, int.from_bytes(hdr, "big"))


def write_frame(sock, payload):
    sock.sendall(len(payload).to_bytes(4, "big") + payload)


def in_range_public():
    """A 256-byte value accepted by A's 1 < y < p-1 check (p starts 0xFFFF...),
    without being a real key pair -- enough to reach the HMAC step."""
    return bytes([0x7F]) + secrets.token_bytes(DH_LEN - 1)


def send_hs2(sock, dh_a, n_a, sender_id, psk):
    """Builds and sends HS2. With a wrong psk the HMAC will not verify at A."""
    dh_b = in_range_public()
    n_b = secrets.token_bytes(NONCE_LEN)
    transcript = (bytes([VERSION, ID_A]) + dh_a + n_a +
                  bytes([ID_B]) + dh_b + n_b)
    hmac_b = hmac.new(psk, b"hs-B" + transcript, hashlib.sha256).digest()
    write_frame(sock, bytes([MSG_HS2, VERSION, sender_id]) + dh_b + n_b + hmac_b)


def main():
    ap = argparse.ArgumentParser(description="unauthorized-device test for the two-ESP32 project")
    ap.add_argument("--target", default=HOST_DEFAULT)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--bad-psk", action="store_true", help="wrong pre-shared key")
    g.add_argument("--bad-id", action="store_true", help="unknown device id")
    g.add_argument("--data-first", action="store_true", help="send data before the handshake")
    args = ap.parse_args()

    sock = socket.create_connection((args.target, PORT), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print(f"connected to A at {args.target}:{PORT}")

    if args.data_first:
        # Jump straight to a data frame; A is still in the handshake.
        junk = bytes([MSG_DATA, VERSION, ID_B]) + secrets.token_bytes(DATA_HEADER - 3 + 8 + 16)
        write_frame(sock, junk)
        print("sent a DATA frame before completing the handshake")
        print("expected on A: RX ... -> REJECT reason=bad_state")
    else:
        hs1 = read_frame(sock)
        if not hs1 or hs1[0] != MSG_HS1 or len(hs1) != HS1_LEN:
            print(f"did not receive a valid HS1 (got {len(hs1) if hs1 else 0} bytes)")
            sock.close()
            return
        dh_a = hs1[3:3 + DH_LEN]
        n_a = hs1[3 + DH_LEN:HS1_LEN]
        print("received HS1 from A")

        if args.bad_id:
            # Correct-looking HMAC input, but an id A does not recognize:
            # A rejects at the header before even checking the HMAC.
            send_hs2(sock, dh_a, n_a, sender_id=0xBB, psk=secrets.token_bytes(32))
            print("sent HS2 with an unknown device id (0xBB)")
            print("expected on A: AUTH reject reason=unknown_id")
        else:  # bad-psk
            wrong_psk = bytes(32)  # all zeros: not the real key
            send_hs2(sock, dh_a, n_a, sender_id=ID_B, psk=wrong_psk)
            print("sent HS2 with a valid structure but the wrong PSK")
            print("expected on A: AUTH hmac_verify ok=0, reject reason=bad_hmac")

    # A rejects and drops the connection; show that nothing useful came back.
    # A greets every new connection with HS1, so with --data-first that greeting
    # is the only reply: the data frame itself was refused.
    sock.settimeout(5)
    try:
        resp = read_frame(sock)
        if resp is None:
            print("A closed the connection (rejected)")
        elif resp[0] == MSG_HS1:
            print("A only sent its handshake greeting (HS1); the data frame was not accepted")
        else:
            print(f"A unexpectedly replied with {len(resp)} bytes")
    except socket.timeout:
        print("no reply within 5 s (A did not accept this device)")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
