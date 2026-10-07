"""Turns a captured demo log into the measurement tables and plots the report needs.

Course Project 1 asks for processing time, latency and message overhead. The
firmware already stamps every cryptographic step with a `us=` field in its
`idf.py monitor` output, so no extra on-device benchmark command is needed:
run the demo, save the monitor output (in the monitor, Ctrl+T then Ctrl+L
writes it to a file), and feed that file here.

    # Timing from one or more saved monitor logs, plus the overhead chart:
    python measure.py --log results/raw/demo_a.log results/raw/demo_b.log

    # Just the (hardware-independent) overhead table and chart:
    python measure.py

Outputs, under --out (default: results/):
    timing.csv          mean/median/p95 of each operation, in microseconds
    timing_by_size.csv  AES-GCM encrypt/decrypt time grouped by payload size
    overhead.csv        bytes added per field, and the on-wire overhead curve
    overhead.png        overhead (%) versus plaintext length

Stdlib only, except matplotlib for the chart (skipped with a note if absent).
"""
import argparse
import csv
import os
import re
import statistics
from collections import defaultdict

# --- Protocol framing (see firmware/main/protocol.h) ----------------------
# Encrypted DATA frame on the wire:
#   [length prefix 4] [type 1 | version 1 | sender 1 | session_id 8 | counter 8]
#   [ciphertext = plaintext length] [tag 16]
LENGTH_PREFIX = 4
DATA_HEADER = 1 + 1 + 1 + 8 + 8   # 19 bytes, also the GCM AAD
AEAD_TAG = 16
FRAME_OVERHEAD = DATA_HEADER + AEAD_TAG            # 35, what the proxy's len shows
WIRE_OVERHEAD = FRAME_OVERHEAD + LENGTH_PREFIX     # 39, bytes added on the wire
MAX_TEXT = 512 - FRAME_OVERHEAD                    # 477

# --- Log line patterns -----------------------------------------------------
# Each monitor line looks like:  I (3466) HS: shared fp_kdh=3f9a1c22 us=4120
# These capture the `us=` timing field of each instrumented operation.
SCALAR_METRICS = {
    "dh_keygen":       re.compile(r"\bHS: keygen\b.*\bus=(\d+)"),
    "dh_shared":       re.compile(r"\bHS: shared\b.*\bus=(\d+)"),
    "key_derivation":  re.compile(r"\bHS: kdf\b.*\bus=(\d+)"),
    "handshake_total": re.compile(r"\bHS: complete\b.*\btotal_us=(\d+)"),
}
# Encrypt/decrypt also report the payload length, so time can be read per size.
SIZED_METRICS = {
    "aead_encrypt": re.compile(r"\bTX: send\b.*\blen=(\d+).*\bus=(\d+)"),
    "aead_decrypt": re.compile(r"\bRX: recv\b.*\blen=(\d+).*-> ACCEPT.*\bus=(\d+)"),
}


def parse_logs(paths):
    """Returns (scalars, sized): metric -> [us], and metric -> {len -> [us]}."""
    scalars = defaultdict(list)
    sized = defaultdict(lambda: defaultdict(list))
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                for name, pat in SCALAR_METRICS.items():
                    m = pat.search(line)
                    if m:
                        scalars[name].append(int(m.group(1)))
                for name, pat in SIZED_METRICS.items():
                    m = pat.search(line)
                    if m:
                        sized[name][int(m.group(1))].append(int(m.group(2)))
    return scalars, sized


def summary(values):
    """n, mean, median, p95, min, max for a list of microsecond samples."""
    s = sorted(values)
    n = len(s)
    # Nearest-rank p95; for tiny samples this is just the largest value.
    p95 = s[min(n - 1, max(0, round(0.95 * n) - 1))]
    return {
        "n": n,
        "mean_us": round(statistics.mean(s), 1),
        "median_us": statistics.median(s),
        "p95_us": p95,
        "min_us": s[0],
        "max_us": s[-1],
    }


def write_timing(scalars, sized, out_dir):
    rows = []
    for name in list(SCALAR_METRICS) + list(SIZED_METRICS):
        samples = scalars.get(name) or [v for d in sized.get(name, {}).values() for v in d]
        if samples:
            rows.append({"operation": name, **summary(samples)})
    _write_csv(os.path.join(out_dir, "timing.csv"),
               ["operation", "n", "mean_us", "median_us", "p95_us", "min_us", "max_us"], rows)

    size_rows = []
    for name, by_len in sized.items():
        for length in sorted(by_len):
            size_rows.append({"operation": name, "payload_len": length, **summary(by_len[length])})
    _write_csv(os.path.join(out_dir, "timing_by_size.csv"),
               ["operation", "payload_len", "n", "mean_us", "median_us", "p95_us", "min_us", "max_us"],
               size_rows)
    return rows, size_rows


def overhead_table():
    """Per-field byte cost of an encrypted DATA frame (independent of payload)."""
    return [
        ("type", 1), ("version", 1), ("sender_id", 1),
        ("session_id", 8), ("counter", 8),
        ("header subtotal (= GCM AAD)", DATA_HEADER),
        ("ciphertext", "= plaintext length"),
        ("tag", AEAD_TAG),
        ("frame payload (what the proxy logs)", f"plaintext + {FRAME_OVERHEAD}"),
        ("length prefix (framing)", LENGTH_PREFIX),
        ("on-wire total", f"plaintext + {WIRE_OVERHEAD}"),
    ]


def write_overhead(out_dir):
    path = os.path.join(out_dir, "overhead.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["field", "bytes"])
        for field, value in overhead_table():
            w.writerow([field, value])
        w.writerow([])
        w.writerow(["plaintext_len", "on_wire_bytes", "overhead_pct"])
        for length in (16, 64, 128, 256, MAX_TEXT):
            wire = length + WIRE_OVERHEAD
            w.writerow([length, wire, round(WIRE_OVERHEAD / length * 100, 2)])
    return path


def plot_overhead(out_dir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping overhead.png "
              "(overhead.csv still written)")
        return None

    lengths = list(range(1, MAX_TEXT + 1))
    pct = [WIRE_OVERHEAD / n * 100 for n in lengths]

    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(lengths, pct, color="#2563eb", linewidth=2)
    ax.set_xlabel("Plaintext length (bytes)")
    ax.set_ylabel("Protocol overhead (%)")
    ax.set_title(f"Fixed {WIRE_OVERHEAD}-byte overhead as a share of message size")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 300)
    for n in (16, 64, 128, 256, MAX_TEXT):
        y = WIRE_OVERHEAD / n * 100
        ax.annotate(f"{n} B\n{y:.0f}%", xy=(n, y), xytext=(6, 6),
                    textcoords="offset points", fontsize=8, color="#1e3a8a")
        ax.plot(n, y, "o", color="#1e3a8a", markersize=4)
    fig.tight_layout()
    path = os.path.join(out_dir, "overhead.png")
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def _write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def _print_table(title, rows):
    print(f"\n{title}")
    if not rows:
        print("  (no samples found)")
        return
    cols = list(rows[0].keys())
    widths = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in cols}
    print("  " + "  ".join(c.ljust(widths[c]) for c in cols))
    for r in rows:
        print("  " + "  ".join(str(r[c]).ljust(widths[c]) for c in cols))


def main():
    ap = argparse.ArgumentParser(description="Measurement tables and overhead chart")
    ap.add_argument("--log", nargs="+", default=[],
                    help="saved idf.py monitor log(s); omit for overhead only")
    ap.add_argument("--out", default="results", help="output directory")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    if args.log:
        scalars, sized = parse_logs(args.log)
        timing_rows, size_rows = write_timing(scalars, sized, args.out)
        _print_table("Processing time (us)", timing_rows)
        _print_table("AES-GCM time by payload size (us)", size_rows)
        if not timing_rows:
            print("\nNo `us=` lines matched. Is this a monitor log from this firmware?")

    csv_path = write_overhead(args.out)
    png_path = plot_overhead(args.out)
    print(f"\nWrote {csv_path}")
    if png_path:
        print(f"Wrote {png_path}")


if __name__ == "__main__":
    main()
