# Secure Wireless Messaging for IoT Devices

Two ESP32 boards exchange short text messages over Wi-Fi/TCP with confidentiality,
integrity, device authentication, session-key establishment and replay protection.

| Board | Role |
|---|---|
| **A** | Wi-Fi access point (192.168.4.1) + TCP server |
| **B** | Wi-Fi station (192.168.4.2) + TCP client |

The laptop plays the attacker on the untrusted channel and runs the test tools. It joins
A's network (`esp32-secure-msg`, password set in `menuconfig` → *Secure Messaging*) and
gets an address from A's DHCP pool, 192.168.4.100–120; A logs the one it hands out.

## Serial console

Type commands in `idf.py monitor`; `help` lists them all.

| Command | Board | Effect |
|---|---|---|
| `send <text>` | A, B | Send a message to the peer |
| `handshake` | A, B | New session: drops the connection, B reconnects and A runs a fresh handshake |
| `connect <ip>` | B | Reconnect to another server (A directly, or the laptop proxy) |
| `status` | A, B | Show Wi-Fi, TCP and handshake state |
| `selftest` | A, B | Re-run the cryptographic self-tests (they also run at every boot) |

Test builds only (`SM_TEST_COMMANDS`, on by default):

| Command | Effect |
|---|---|
| `debug psk wrong\|ok` | Use a corrupted PSK: this board becomes an unauthorized device |
| `debug replay` | Resend the last encrypted message unchanged (peer must reject: `replay`) |
| `debug tamper ct\|tag\|ctr\|sid\|sender` | Send a new message with that field altered in transit (peer must reject) |
| `mode plain\|secure` | `plain` sends text unprotected, for the latency baseline only; a board in `secure` mode rejects it |

Messages are refused in both directions until the handshake reaches `READY`. Each
encrypted message adds 35 bytes to the text (39 with the length prefix); text is limited
to 477 bytes.

If any self-test fails at boot, the board logs `network disabled reason=selftest_failed`
and never joins the network.

## Layout

```text
project1/
├── firmware/           # one ESP-IDF project, built once per role
│   ├── sdkconfig.defaults   # settings shared by A and B
│   ├── sdkconfig.a          # role A
│   ├── sdkconfig.b          # role B
│   └── main/                # application sources; secrets.h holds the PSK (gitignored)
└── tools/              # Python tools for the laptop (attacks, tests, measurements)
```

## Setup

1. **USB-serial driver.** Plug in one board at a time and note its COM port
   (Device Manager → *Ports (COM & LPT)*). If none appears, install the driver for the
   chip next to the USB connector: CP210x (Silicon Labs) or CH340 (WCH).
2. **ESP-IDF.** Install the latest stable v5.x with the *ESP-IDF Tools Installer for
   Windows* and run every `idf.py` command from the **ESP-IDF PowerShell** shortcut.
   Check with `idf.py --version`.
3. **Pre-shared key.** Copy `firmware/main/secrets.example.h` to `secrets.h` and fill it
   with 32 random bytes (the command is in the file). Never commit `secrets.h`.
4. **Laptop tools.**
   ```powershell
   cd tools
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

## Build and flash

From `firmware/`, one terminal pane per board (replace the COM ports with yours):

```powershell
# Board A
idf.py -B build_a -DSDKCONFIG=build_a/sdkconfig -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.a" -p COM5 build flash monitor
# Board B
idf.py -B build_b -DSDKCONFIG=build_b/sdkconfig -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.b" -p COM6 build flash monitor
```

- `-DSDKCONFIG` keeps a separate configuration per role; without it both builds
  overwrite the same `sdkconfig`.
- After adding a new option to `Kconfig.projbuild`, run the command once with
  `reconfigure build` in place of `build`: an incremental build keeps the old
  `build_x/sdkconfig` and silently ignores the new option.
- Values already stored in `build_x/sdkconfig` win over `sdkconfig.defaults`. To apply a
  changed default, delete `build_a/sdkconfig` and `build_b/sdkconfig` and build again.
- The default target is the classic ESP32. For an ESP32-S3 or C3, run the same command
  once with `set-target esp32s3` (or `esp32c3`) in place of `build flash monitor`.
- Always flash **both** boards after a change, A first.
- The first log line on boot identifies the board: `I (...) MAIN: role=A id=0x0A`.
- Exit the monitor with `Ctrl+]`; reset the board with `Ctrl+T` then `Ctrl+R`.
- If flashing hangs on `Connecting....`, hold **BOOT**, tap **EN/RST**, release **BOOT**.
