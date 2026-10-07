# Test tools (laptop)

These scripts verify the protocol under the controlled attack scenarios the
project requires, using the two boards you own. They speak only this
project's message format and only talk to your boards. Stdlib only; run them
from the `tools` venv.

The laptop must be on the boards' Wi-Fi network (`esp32-secure-msg`) for
these. That network has no internet, so run them, then switch back.

## proxy.py — man in the middle (modification, forgery, replay)

B talks to A through the laptop so a frame can be altered or replayed on the
wire and seen rejected by A.

1. Start the proxy on the laptop (find the laptop's address with `ipconfig`;
   it is in 192.168.4.100-120):
   `python proxy.py --mode flip-tag`
2. In B's console: `connect <laptop-ip>` then `handshake`, then `send hola`.
3. Watch A's log; return B to direct mode with `connect 192.168.4.1`.

| `--mode` | What A should log |
|---|---|
| passthrough | normal ACCEPT (baseline through the proxy) |
| flip-ct / flip-tag | REJECT reason=tag_fail |
| set-counter | REJECT reason=tag_fail (counter is in the AAD) |
| flip-sender | REJECT reason=bad_sender |
| flip-dh | handshake fails: AUTH reject reason=bad_hmac (the HMAC binds DH) |
| replay | first message ACCEPT, duplicate REJECT reason=replay |
| truncate / oversize | NET frame_error, connection dropped, no crash |

Add `--hex` to any mode to print each message body as an eavesdropper sees it:
unreadable in secure mode, the plain text after `mode plain` on both boards.
Each attack fires once per connection; `handshake` on B re-arms it. Stop the
proxy with `Ctrl+C` before starting another mode.

## rogue_client.py — unauthorized device

Speaks the handshake to A but fails one requirement, so A rejects it. Point
B away first (or leave it; A serves the newest connection).

    python rogue_client.py --bad-psk      -> A: AUTH reject reason=bad_hmac
    python rogue_client.py --bad-id       -> A: AUTH reject reason=unknown_id
    python rogue_client.py --data-first   -> A: RX reject reason=bad_state

No script ever learns the PSK or completes a session.

## measure.py — processing time, latency and overhead

Turns a captured monitor log into the report's measurement tables and the
overhead chart. The firmware already stamps each step with a `us=` field, so
running the demo is the measurement campaign — there is no separate benchmark
command.

1. During the demo, save each board's monitor output: in `idf.py monitor`,
   press `Ctrl+T` then `Ctrl+L` to start (and again to stop) writing to a file.
   Put them under `results/raw/` (gitignored).
2. From `tools/` with the venv active:

       python measure.py --log ..\results\raw\demo_a.log ..\results\raw\demo_b.log

   Writes `results/timing.csv`, `results/timing_by_size.csv`,
   `results/overhead.csv` and `results/overhead.png`.

Run it with no `--log` to (re)generate just the overhead table and chart, which
are computed from the framing constants and need no hardware. Needs matplotlib
for the chart (the CSVs are written either way).
