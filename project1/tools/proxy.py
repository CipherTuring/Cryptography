"""Man-in-the-middle test harness for the two-ESP32 secure messaging project.

Course Project 1 requires testing the prototype under controlled attack
scenarios (modification, forgery, replay). This script sits on the laptop,
on the boards' own Wi-Fi network, and relays the length-prefixed frames
between board B and board A so a tampered or replayed frame on the wire can
be observed being rejected by the receiver.

Topology for the tests:
    B  --TCP-->  laptop (this script)  --TCP-->  A
Point B at the laptop with `connect <laptop-ip>` in B's console; the proxy
forwards to A at 192.168.4.1. It is protocol-aware only to label frames and
alter one chosen field; it never needs the PSK or any key.

    python proxy.py --mode flip-tag
    python proxy.py --mode replay
    python proxy.py --mode passthrough      (baseline: relay unchanged)

Modes operate on the first matching frame, then the proxy relays everything
unchanged so you can watch the session recover. Stdlib only.
"""
import argparse
import socket
import threading

# This protocol's wire constants (see firmware/main/protocol.h).
MSG_HS1, MSG_HS2, MSG_HS3, MSG_DATA, MSG_PLAIN = 0x01, 0x02, 0x03, 0x10, 0x20
NAMES = {MSG_HS1: "HS1", MSG_HS2: "HS2", MSG_HS3: "HS3", MSG_DATA: "DATA", MSG_PLAIN: "PLAIN"}
DATA_HEADER = 19          # type|ver|sender|session_id(8)|counter(8)
DATA_COUNTER_OFF = 11     # counter within a DATA frame
DH_OFF = 3                # DH public value within HS1/HS2
MAX_FRAME = 512


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_frame(sock):
    """Reads one 4-byte-length-prefixed frame. Returns the payload or None."""
    hdr = recv_exact(sock, 4)
    if hdr is None:
        return None
    length = int.from_bytes(hdr, "big")
    if length == 0 or length > MAX_FRAME:
        # Pass the oddity straight through so A's own length check sees it.
        return ("raw", hdr)
    payload = recv_exact(sock, length)
    return None if payload is None else payload


def write_frame(sock, payload):
    sock.sendall(len(payload).to_bytes(4, "big") + payload)


def describe(payload):
    t = payload[0]
    name = NAMES.get(t, f"0x{t:02x}")
    if t == MSG_DATA and len(payload) >= DATA_HEADER:
        ctr = int.from_bytes(payload[DATA_COUNTER_OFF:DATA_COUNTER_OFF + 8], "big")
        return f"{name} ctr={ctr} len={len(payload)}"
    return f"{name} len={len(payload)}"


def tamper(payload, mode):
    """Returns (new_payload, label) or (payload, None) if this frame is not the target."""
    t = payload[0]
    b = bytearray(payload)

    if mode == "flip-ct" and t == MSG_DATA and len(b) > DATA_HEADER:
        b[DATA_HEADER] ^= 0x01
        return bytes(b), "flipped first ciphertext byte"
    if mode == "flip-tag" and t == MSG_DATA and len(b) >= DATA_HEADER:
        b[-1] ^= 0x01
        return bytes(b), "flipped last tag byte"
    if mode == "set-counter" and t == MSG_DATA and len(b) >= DATA_HEADER:
        ctr = int.from_bytes(b[DATA_COUNTER_OFF:DATA_COUNTER_OFF + 8], "big")
        b[DATA_COUNTER_OFF:DATA_COUNTER_OFF + 8] = (ctr + 100).to_bytes(8, "big")
        return bytes(b), f"counter {ctr} -> {ctr + 100}"
    if mode == "flip-sender" and t == MSG_DATA:
        b[2] ^= 0x01
        return bytes(b), "altered sender id"
    if mode == "flip-dh" and t in (MSG_HS1, MSG_HS2) and len(b) > DH_OFF:
        b[DH_OFF] ^= 0x01
        return bytes(b), "flipped a DH public-value byte (tests HMAC binding)"
    return payload, None


def is_target(payload, mode):
    """True if this frame is the one the mode attacks. Replay and the malformed
    modes act on a whole DATA frame instead of altering a field."""
    if mode in ("replay", "truncate", "oversize"):
        return payload[0] == MSG_DATA
    return tamper(payload, mode)[1] is not None


def dump(payload):
    """What an eavesdropper sees of a message body: hex and printable text."""
    body = payload[DATA_HEADER:] if payload[0] == MSG_DATA else payload[1:]
    shown = body[:48]
    text = "".join(chr(c) if 32 <= c < 127 else "." for c in shown)
    more = ".." if len(body) > len(shown) else ""
    return f"    body hex : {shown.hex()}{more}\n    body text: \"{text}\"{more}"


def relay(src, dst, src_name, dst_name, mode, state):
    """Forwards frames src->dst. `state` holds the one-shot 'armed' flag and lock."""
    while True:
        frame = read_frame(src)
        if frame is None:
            break

        # Odd length prefix: forward the raw bytes untouched.
        if isinstance(frame, tuple):
            dst.sendall(frame[1])
            print(f"[{src_name}->{dst_name}] raw length prefix forwarded")
            continue

        label = None
        with state["lock"]:
            armed = state["armed"] and src_name == "B"
            if armed and is_target(frame, mode):
                if mode in ("truncate", "oversize"):
                    _craft_malformed(dst, frame, mode)
                    state["armed"] = False
                    print(f"[{src_name}->{dst_name}] {describe(frame)} -> sent {mode} frame")
                    continue
                if mode == "replay":
                    write_frame(dst, frame)      # the genuine copy
                    write_frame(dst, frame)      # the duplicate A must reject
                    state["armed"] = False
                    print(f"[{src_name}->{dst_name}] {describe(frame)} -> forwarded twice (replay)")
                    continue
                frame, label = tamper(frame, mode)
                state["armed"] = False

        write_frame(dst, frame)
        note = f"  <-- {label}" if label else ""
        print(f"[{src_name}->{dst_name}] {describe(frame)}{note}")
        if state["hex"] and frame[0] in (MSG_DATA, MSG_PLAIN):
            print(dump(frame))

    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _craft_malformed(dst, frame, mode):
    if mode == "oversize":
        # Claim a huge length so A's framing layer rejects it (bad_length).
        dst.sendall((0xFFFFFFFF).to_bytes(4, "big") + frame[:16])
    else:  # truncate: promise more bytes than we send, then stop.
        dst.sendall(len(frame).to_bytes(4, "big") + frame[: len(frame) // 2])


def wait_for_client(listen_sock):
    """accept() that Ctrl+C can interrupt: on Windows a blocking accept() ignores
    Ctrl+C, so the listening socket polls with a short timeout instead."""
    while True:
        try:
            client, addr = listen_sock.accept()
        except socket.timeout:
            continue
        client.settimeout(None)
        return client, addr


def serve_one(listen_sock, target, mode, show_hex):
    client, addr = wait_for_client(listen_sock)
    print(f"\n=== B connected from {addr[0]}; opening link to A at {target[0]} ===")
    try:
        upstream = socket.create_connection(target, timeout=5)
    except OSError as e:
        print(f"cannot reach A at {target[0]}:{target[1]} ({e}); dropping B")
        client.close()
        return
    upstream.settimeout(None)
    sockets = (client, upstream)
    for s in sockets:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    state = {"armed": True, "lock": threading.Lock(), "hex": show_hex}
    threads = [
        threading.Thread(target=relay, args=(client, upstream, "B", "A", mode, state), daemon=True),
        threading.Thread(target=relay, args=(upstream, client, "A", "B", mode, state), daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        # Short joins for the same reason: a join without timeout blocks Ctrl+C on Windows.
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(0.2)
    finally:
        for s in sockets:
            s.close()
    print("=== link closed ===")


def main():
    modes = ["passthrough", "flip-ct", "flip-tag", "set-counter", "flip-sender",
             "flip-dh", "replay", "truncate", "oversize"]
    ap = argparse.ArgumentParser(description="MITM test harness for the two-ESP32 project")
    ap.add_argument("--listen", default="0.0.0.0:5000", help="where B connects")
    ap.add_argument("--target", default="192.168.4.1:5000", help="board A")
    ap.add_argument("--mode", default="passthrough", choices=modes)
    ap.add_argument("--hex", action="store_true",
                    help="show each message body as an eavesdropper sees it")
    args = ap.parse_args()

    lhost, lport = args.listen.rsplit(":", 1)
    thost, tport = args.target.rsplit(":", 1)
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((lhost, int(lport)))
    listen_sock.listen(1)
    listen_sock.settimeout(0.5)
    print(f"proxy mode={args.mode}  listen={args.listen}  target={args.target}")
    print("waiting for B...  (Ctrl+C to stop)")
    try:
        while True:
            serve_one(listen_sock, (thost, int(tport)), args.mode, args.hex)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        listen_sock.close()


if __name__ == "__main__":
    main()
