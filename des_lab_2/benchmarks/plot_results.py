"""
Exercise 10 plots, built from `results/benchmark_parallel.json`.

    python -m benchmarks.plot_results

Generates:
  results/plot_workers_vs_throughput.png   Workers vs Keys/s
  results/plot_workers_vs_speedup.png      Workers vs S_p, with the ideal line
"""

import argparse
import json
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
SOURCE = RESULTS_DIR / "benchmark_parallel.json"


def _load(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(
            f"No se encontró {path}.\n"
            "Ejecuta primero: python -m benchmarks.benchmark_bruteforce parallel"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def make_plots(source: Path = SOURCE, results_dir: Path = RESULTS_DIR) -> list[Path]:
    import matplotlib

    matplotlib.use("Agg")  # windowless backend: the scripts are not interactive
    import matplotlib.pyplot as plt

    data = _load(source)
    rows = sorted(data["results"], key=lambda r: r["workers"])
    workers = [r["workers"] for r in rows]
    throughput = [r["throughput_keys_per_s"] for r in rows]
    # The speedup only exists if the sweep included p = 1 (the T_1 baseline).
    has_speedup = all(r.get("speedup") is not None for r in rows)
    speedup = [r["speedup"] for r in rows] if has_speedup else []
    efficiency = [r["efficiency"] for r in rows] if has_speedup else []

    cpu = data["system"]["cpu_model"]
    logical = data["system"]["logical_cores"]
    physical = data["system"]["physical_cores"]
    cores_note = f"{physical} físicos / {logical} lógicos" if physical else f"{logical} lógicos"
    subtitle = f"{cpu} — {cores_note} — n = {data['unknown_bits']} bits"

    results_dir.mkdir(parents=True, exist_ok=True)
    written = []

    # --- Workers vs Keys/s ---------------------------------------------------
    figure, axes = plt.subplots(figsize=(7.5, 4.6))
    axes.plot(workers, throughput, marker="o", color="#1f77b4", label="medido")
    ideal = [throughput[0] * w / workers[0] for w in workers]
    axes.plot(workers, ideal, linestyle="--", color="#999999", label="escalado ideal")
    for w, value in zip(workers, throughput):
        axes.annotate(f"{value:,.0f}", (w, value),
                      textcoords="offset points", xytext=(0, 8), ha="center", fontsize=8)
    axes.set_xlabel("Trabajadores (procesos)")
    axes.set_ylabel("Throughput [llaves/s]")
    axes.set_title(f"Workers vs Keys/s\n{subtitle}", fontsize=10)
    axes.set_xticks(workers)
    axes.grid(alpha=0.3)
    axes.legend()
    figure.tight_layout()
    path = results_dir / "plot_workers_vs_throughput.png"
    figure.savefig(path, dpi=150)
    plt.close(figure)
    written.append(path)

    # --- Workers vs Speedup --------------------------------------------------
    if not has_speedup:
        print("Sin p = 1 en el barrido no hay T_1: se omite la gráfica de speedup.")
        return written

    figure, axes = plt.subplots(figsize=(7.5, 4.6))
    axes.plot(workers, speedup, marker="o", color="#d62728", label="speedup medido $S_p$")
    axes.plot(workers, workers, linestyle="--", color="#999999", label="ideal $S_p = p$")
    if physical:
        axes.axvline(physical, color="#2ca02c", linestyle=":", linewidth=1.4,
                     label=f"{physical} núcleos físicos")
    for w, s, e in zip(workers, speedup, efficiency):
        axes.annotate(f"{s:.2f}\n$E_p$={e:.2f}", (w, s),
                      textcoords="offset points", xytext=(0, 9), ha="center", fontsize=8)
    axes.set_xlabel("Trabajadores (procesos)")
    axes.set_ylabel("Speedup $S_p = T_1 / T_p$")
    axes.set_title(f"Workers vs Speedup\n{subtitle}", fontsize=10)
    axes.set_xticks(workers)
    axes.grid(alpha=0.3)
    axes.legend()
    figure.tight_layout()
    path = results_dir / "plot_workers_vs_speedup.png"
    figure.savefig(path, dpi=150)
    plt.close(figure)
    written.append(path)

    return written


def main() -> None:
    from console import use_utf8_stdout

    use_utf8_stdout()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    args = parser.parse_args()
    for path in make_plots(args.source):
        print(f"-> {path}")


if __name__ == "__main__":
    main()
