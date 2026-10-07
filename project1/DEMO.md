# Demo guide: Secure Wireless Messaging (2 × ESP32)

Runbook for the live presentation: every command in order, and the log line
that proves each requirement.

- `A>` / `B>`: type it in that board's `idf.py monitor` pane.
- `PS>`: laptop PowerShell in `project1\tools` with the venv active.
- Red `E` lines are rejections, yellow `W` lines are warnings.

## What each part proves

| Requirement | Part | Proof on screen |
|---|---|---|
| Session-key establishment | 1 | Same `fp_kdh`, `fp_kab`, `fp_kba` and `sid` on A and B; new values on every `handshake` |
| Device authentication | 1, 6 | `AUTH: hmac_verify ok=1`; intruders get `bad_hmac`, `unknown_id` or `bad_state` |
| Confidentiality | 2 | Proxy shows unreadable `body text`; readable only in `mode plain` |
| Integrity (modification) | 3 | `REJECT reason=tag_fail` |
| Forgery | 4, 6 | `bad_sender`, `bad_hmac` (key substitution), `bad_state` (injected frame) |
| Replay | 5 | First copy `ACCEPT`, second copy `REJECT reason=replay` |
| Measurements | 7 | `us=` fields, `frame=` / proxy `len=`, `measure.py` |

## 0. Setup (before the audience arrives)

1. Flash both boards, A first, from `project1\firmware` in *ESP-IDF PowerShell*
   (replace the COM ports with yours):

   ```powershell
   idf.py -B build_a -DSDKCONFIG=build_a/sdkconfig -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.a" -p COM5 build flash monitor
   idf.py -B build_b -DSDKCONFIG=build_b/sdkconfig -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.b" -p COM6 build flash monitor
   ```

   If both boards are already flashed, run the same commands with `monitor` in
   place of `build flash monitor`.
2. Split the terminal into three panes (Windows Terminal, `Alt+Shift+D`):
   A monitor, B monitor, and the laptop PowerShell.
3. Start saving logs for Part 7: in **each** monitor press `Ctrl+T`, then `Ctrl+L`.
   This writes a `log.*.txt` file in `firmware\`.
4. Connect the laptop to Wi-Fi `esp32-secure-msg` (password `sm-demo-2026`).
   Find its address with `PS> ipconfig` (Wi-Fi IPv4, 192.168.4.100–120); A also
   logs it as `NET: wifi state=dhcp_assigned ip=…`. This guide calls it `<LAPTOP_IP>`.
5. Activate the tools venv:
   `PS> cd project1\tools; .\.venv\Scripts\Activate.ps1`
6. The first time `proxy.py` runs, Windows Firewall asks for permission: allow
   **Private networks**, or B cannot reach the laptop.

Check before you start: `A> status` and `B> status` both show `hs=READY`, and B
shows `target=192.168.4.1`.

## 1. Normal communication, session key, authentication

1. (Optional) Reset A with `Ctrl+T` then `Ctrl+R`. Both boards print
   `SELFTEST: result=PASS`: the cryptographic known-answer tests run on every
   boot, and a board that fails them never joins Wi-Fi. B reconnects on its own.
2. `B> handshake`. Point at these lines in **both** panes:

   ```text
   HS: pub_recv … valid=1                    DH public value checked (1 < y < p-1)
   AUTH: hmac_verify peer=… ok=1             peer proved it holds the PSK
   HS: shared fp_kdh=…                       DH shared secret (fingerprint only)
   HS: kdf fp_kab=… fp_kba=… sid=…           derived keys A->B, B->A, session id
   HS: state from=… to=READY
   HS: complete total_us=…                   handshake time
   ```

   - `fp_kdh`, `fp_kab`, `fp_kba` and `sid` are **identical on A and B**: both
     boards derived the same keys, and the keys themselves are never printed.
   - Run `B> handshake` again: every value changes, because each session uses a
     new ephemeral DH key (forward secrecy).
3. `B> send hello from B`
   - B: `TX: send ctr=1 len=12 frame=47 pt="hello from B" ct=… tag=…`
   - A: `RX: recv ctr=1 … tag=ok -> ACCEPT pt="hello from B"`
4. `A> send hello from A`: B accepts it. `A> status` shows that each direction
   keeps its own counter (`tx_ctr` / `rx_ctr`).

## 2. Confidentiality: the laptop eavesdrops

1. `PS> python proxy.py --mode passthrough --hex`
2. `B> connect <LAPTOP_IP>`. B reconnects through the laptop: A shows
   `tcp state=connected peer=<LAPTOP_IP>`, and both boards reach `READY` again.
3. `B> send secret-1234`
   - Proxy: `[B->A] DATA ctr=1 len=46` and `body text: "……"` (unreadable).
   - A: `ACCEPT pt="secret-1234"`.
   - Overhead: `len=46` is 11 bytes of text plus 35 bytes of protocol.
4. Baseline for contrast: `A> mode plain`, `B> mode plain`, then
   `B> send secret-1234`. The proxy now shows `body text: "secret-1234"`.
   Restore with `A> mode secure` and `B> mode secure`.
5. (Optional) Put only `B> mode plain`, then `B> send hi`. A refuses the
   unprotected message with `REJECT reason=plain_disabled`. Restore with
   `B> mode secure`.

## 3. Modification (integrity)

The proxy alters the **first** data message from B on each connection. To
change the attack, press `Ctrl+C` in the proxy pane and start the next mode;
B reconnects by itself (about 2 s; wait for `HS: complete`). For every mode:

1. `B> send test`: A rejects it.
2. `B> send test` again: A accepts it. The session survives the attack.

| Laptop command | Proxy prints | A shows |
|---|---|---|
| `PS> python proxy.py --mode flip-ct` | `<-- flipped first ciphertext byte` | `tag=FAIL -> REJECT reason=tag_fail` |
| `PS> python proxy.py --mode flip-tag` | `<-- flipped last tag byte` | `tag=FAIL -> REJECT reason=tag_fail` |
| `PS> python proxy.py --mode set-counter` | `<-- counter N -> N+100` | `tag_fail` (the counter is authenticated as AAD) |

To repeat the same attack without restarting the proxy, run `B> handshake`:
the new connection re-arms the attack.

## 4. Forgery

| Laptop command | Proxy prints | A shows |
|---|---|---|
| `PS> python proxy.py --mode flip-sender` | `<-- altered sender id` | `sender=FAIL -> REJECT reason=bad_sender` |
| `PS> python proxy.py --mode flip-dh` | `<-- flipped a DH public-value byte` | `AUTH: hmac_verify peer=B ok=0`, `reject type=HS2 reason=bad_hmac`; no `READY` |

`flip-dh` is a man in the middle trying to substitute its own key. The
handshake fails on every retry (every 2 s) until you stop the proxy. A forged
frame from an outside device is in Part 6 (`--data-first`).

## 5. Replay

1. `PS> python proxy.py --mode replay`, then wait for `READY`.
2. `B> send pay 10 USD`
   - Proxy: `forwarded twice (replay)`.
   - A: first `ACCEPT pt="pay 10 USD"`, then
     `counter=FAIL -> REJECT reason=replay last=N`.

Without the laptop: `B> send pay 10 USD`, then `B> debug replay`. A shows the
same `REJECT reason=replay`.

## 6. Unauthorized devices

1. Stop the proxy (`Ctrl+C`). B keeps retrying the laptop (`connect_failed`),
   so it stays away from A while the intruder connects.
2. `PS> python rogue_client.py --bad-psk` (wrong key)
   - A: `AUTH: hmac_verify peer=B ok=0`, `AUTH: reject type=HS2 reason=bad_hmac`,
     `tcp state=closed … reason=handshake_failed`
   - Script: `A closed the connection (rejected)`
3. `PS> python rogue_client.py --bad-id` (unknown device)
   - A: `AUTH: identity id=0xBB expected=0x0B`, `reject … reason=unknown_id`
4. `PS> python rogue_client.py --data-first` (forged data, no handshake)
   - A: `RX: recv … state=FAIL … -> REJECT reason=bad_state`, then
     `tcp state=closed … reason=peer_closed` when the script exits
   - Script: `A only sent its handshake greeting (HS1); the data frame was not accepted`
5. Real board as intruder:
   1. `B> connect 192.168.4.1` and wait for `READY`.
   2. `B> debug psk wrong`, then `B> handshake`.
   3. A shows `bad_hmac`, and neither board reaches `READY` (B retries every 2 s).
   4. Restore with `B> debug psk ok`: the next retry reaches `READY`.

## 7. Measurements

1. Collect samples while logs are being saved (step 0.3):
   - `B> handshake` five times.
   - Messages of 16, 64, 128 and 200 characters, a few of each, in both
     directions. A console line holds at most 256 characters, so 200 is the
     largest practical size.
   - To build a message: `PS> Set-Clipboard ('x' * 64)`, then type `send ` in
     the monitor and paste.
2. Stop saving: `Ctrl+T`, then `Ctrl+L` in each monitor.
3. Process the logs:
   `PS> python measure.py --log ..\firmware\log.<A>.txt ..\firmware\log.<B>.txt --out ..\results`
   - **Processing time:** `results\timing.csv` (DH keygen, DH shared, HKDF,
     handshake, encrypt, decrypt + verify) and `results\timing_by_size.csv`.
   - **Latency:** session setup is `HS: complete total_us`. The crypto latency
     per message is `TX … us=` on the sender plus `RX … us=` on the receiver;
     `mode plain` skips both, and the radio transit is the same in both modes.
   - **Overhead:** `TX: send … len=L frame=L+35` (the proxy's `len=` matches),
     plus `results\overhead.png` and `overhead.csv`.

## Plan B: attacks without the laptop

If the laptop network fails, B can stage the attacks itself. With B connected
directly to A and in `READY`, send one normal message first:

| Command on B | A shows |
|---|---|
| `B> debug tamper ct` | `REJECT reason=tag_fail` |
| `B> debug tamper tag` | `REJECT reason=tag_fail` |
| `B> debug tamper ctr` | `REJECT reason=tag_fail` |
| `B> debug tamper sid` | `REJECT reason=bad_session` |
| `B> debug tamper sender` | `REJECT reason=bad_sender` |
| `B> debug replay` | `REJECT reason=replay` |

## Restore and troubleshooting

Restore after the demo: `B> connect 192.168.4.1`, `B> debug psk ok`,
`A> mode secure`, `B> mode secure`.

| Symptom | Fix |
|---|---|
| B never reaches the proxy | Check the firewall prompt, that the laptop is on `esp32-secure-msg`, and `<LAPTOP_IP>` |
| Laptop drops the ESP Wi-Fi ("no internet") | Reconnect; tick *Connect automatically* |
| `could not open port` | That COM port is open in another monitor or program |
| Flashing hangs on `Connecting....` | Hold **BOOT**, tap **EN/RST**, release **BOOT** |
| Strange handshake failures after a reflash | Flash **both** boards, A first |
