"""
Exercise 4: the figures, drawn from the benchmark results.

    python -m benchmarks.plot_results

Reads `results/benchmark_aes.json` and writes four PNG files next to it.
Nothing is measured here: re-running this never changes a number, only
how the numbers already recorded are drawn. That separation is why the
fifty-minute benchmark has to be run only once.

Each figure answers one of the five questions of Exercise 4:

    time_vs_size.png          size -> execution time, on log-log axes,
                              so that a straight line of slope 1 means
                              the cost is linear in the amount of data
    throughput_by_version.png AES-128 vs AES-192 vs AES-256
    throughput_vs_rounds.png  the number of rounds against throughput,
                              with the 10 / Nr curve the round counts
                              predict
    encrypt_vs_decrypt.png    decryption throughput relative to
                              encryption

Colour always means the AES variant, in the same order in every figure,
and never means anything else; the direction of the operation is carried
by the panel or the axis instead. Grey is reserved for reference curves,
which are never data.
"""

import argparse
import json
from pathlib import Path

from console import use_utf8_stdout

from .report import RESULTS_DIR

__all__ = ["load_results", "draw_all", "main"]

# Categorical slots 1-3 of the reference palette, in fixed order. These
# three validate on all pairs: worst CVD difference 9.2, worst
# normal-vision difference 24.0 on a light surface.
VARIANT_COLOURS = {
    "AES-128": "#2a78d6",
    "AES-192": "#eb6834",
    "AES-256": "#1baf7a",
}
VARIANT_ORDER = ("AES-128", "AES-192", "AES-256")

SURFACE = "#fcfcfb"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
REFERENCE = "#8a8983"
GRID = "#d8d7d2"

FIGURE_SIZE = (7.5, 4.6)
DPI = 150


def load_results(path: Path) -> dict:
    """Read the JSON written by the benchmark."""
    if not path.exists():
        raise SystemExit(
            f"{path} not found. Run 'python -m benchmarks.benchmark_aes' first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _series(data: dict) -> dict[str, list[dict]]:
    """Measurements grouped by variant, each sorted by data size."""
    grouped: dict[str, list[dict]] = {}
    for item in data["measurements"]:
        grouped.setdefault(item["variant"], []).append(item)
    for rows in grouped.values():
        rows.sort(key=lambda row: row["size_mb"])
    return grouped


def _subtitle(data: dict) -> str:
    """One line identifying the machine the numbers come from."""
    system = data["system"]
    parameters = data["parameters"]
    return (
        f"{system['cpu_model']} - {system['python_implementation']} "
        f"{system['python_version']} - {parameters['backend']} backend, "
        f"average of {parameters['repeats']} runs"
    )


def _style(axes) -> None:
    """Recessive chrome: hairline solid grid, no box, muted labels."""
    axes.set_facecolor(SURFACE)
    axes.grid(True, color=GRID, linewidth=0.8, alpha=0.6, linestyle="-")
    axes.set_axisbelow(True)
    for side in ("top", "right"):
        axes.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        axes.spines[side].set_color(GRID)
    axes.tick_params(colors=TEXT_SECONDARY, labelsize=9)
    axes.xaxis.label.set_color(TEXT_SECONDARY)
    axes.yaxis.label.set_color(TEXT_SECONDARY)


def _title(figure, title: str, subtitle: str) -> None:
    figure.suptitle(title, color=TEXT_PRIMARY, fontsize=13, x=0.01, ha="left", y=0.98)
    figure.text(0.01, 0.91, subtitle, color=TEXT_SECONDARY, fontsize=8.5, ha="left")


def _save(figure, path: Path) -> Path:
    figure.savefig(path, dpi=DPI, facecolor=SURFACE)
    print(f"-> {path}")
    return path


def plot_time_vs_size(data: dict, output_dir: Path):
    """
    Execution time against data size, on log-log axes.

    A straight line of slope 1 means doubling the data doubles the time.
    The fitted slope is printed for each variant, so the claim is read
    off the numbers and not off the shape of the line.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy

    grouped = _series(data)
    figure, panels = plt.subplots(
        1, 2, figsize=(9.0, 4.6), sharey=True, facecolor=SURFACE
    )

    for panel, direction in zip(panels, ("encrypt", "decrypt")):
        _style(panel)
        for variant in VARIANT_ORDER:
            rows = grouped[variant]
            sizes = [row["size_mb"] for row in rows]
            times = [row[direction]["mean_s"] for row in rows]
            slope = numpy.polyfit(numpy.log10(sizes), numpy.log10(times), 1)[0]
            panel.plot(
                sizes,
                times,
                color=VARIANT_COLOURS[variant],
                linewidth=2,
                marker="o",
                markersize=6,
                markeredgecolor=SURFACE,
                markeredgewidth=2,
                solid_capstyle="round",
                solid_joinstyle="round",
                label=f"{variant}  (slope {slope:.3f})",
            )
        panel.set_xscale("log")
        panel.set_yscale("log")
        panel.set_xlabel("Data size (MB)")
        panel.set_title(
            direction.capitalize(), color=TEXT_PRIMARY, fontsize=10, loc="left"
        )
        panel.legend(
            frameon=False, fontsize=8.5, labelcolor=TEXT_SECONDARY, loc="upper left"
        )

    panels[0].set_ylabel("Execution time (s)")
    _title(
        figure,
        "Execution time grows linearly with the amount of data",
        _subtitle(data),
    )
    figure.tight_layout(rect=(0, 0, 1, 0.88))
    path = output_dir / "time_vs_size.png"
    _save(figure, path)
    plt.close(figure)
    return path


def plot_throughput_by_version(data: dict, output_dir: Path):
    """
    Encryption throughput for the three variants at each data size.

    Only the largest size carries value labels: the exact figures are in
    the text report, and what this chart is for is the shape, which is
    that the ordering never changes and the level barely moves.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy

    grouped = _series(data)
    sizes = sorted({row["size_mb"] for row in data["measurements"]})
    positions = numpy.arange(len(sizes))
    width = 0.20

    figure, axes = plt.subplots(figsize=FIGURE_SIZE, facecolor=SURFACE)
    _style(axes)

    for index, variant in enumerate(VARIANT_ORDER):
        values = [row["encrypt"]["throughput_mb_s"] for row in grouped[variant]]
        offset = (index - 1) * (width + 0.03)
        bars = axes.bar(
            positions + offset,
            values,
            width,
            color=VARIANT_COLOURS[variant],
            label=variant,
            edgecolor=SURFACE,
            linewidth=2,
        )
        # Selective labels: the largest size only.
        axes.annotate(
            f"{values[-1]:.2f}",
            xy=(positions[-1] + offset, values[-1]),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center",
            fontsize=8.5,
            color=TEXT_SECONDARY,
        )
        del bars

    axes.set_xticks(positions)
    axes.set_xticklabels([f"{size:g} MB" for size in sizes])
    axes.set_xlabel("Data size")
    axes.set_ylabel("Encryption throughput (MB/s)")
    axes.set_ylim(0, max(
        row["encrypt"]["throughput_mb_s"] for row in data["measurements"]
    ) * 1.25)
    axes.legend(
        frameon=False, fontsize=9, labelcolor=TEXT_SECONDARY, ncol=3, loc="upper center"
    )
    _title(
        figure,
        "Throughput is set by the variant, not by the amount of data",
        _subtitle(data),
    )
    figure.tight_layout(rect=(0, 0, 1, 0.88))
    path = output_dir / "throughput_by_version.png"
    _save(figure, path)
    plt.close(figure)
    return path


def plot_throughput_vs_rounds(data: dict, output_dir: Path):
    """
    The central result of Exercise 4: cost follows the number of rounds.

    If the only thing that changes between the variants is how many
    rounds they run, throughput should fall as 10 / Nr relative to
    AES-128. That prediction is drawn as a grey reference curve and the
    measurements are placed on top of it.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy

    grouped = _series(data)
    largest = max(row["size_mb"] for row in data["measurements"])

    rounds, measured = [], []
    for variant in VARIANT_ORDER:
        row = next(item for item in grouped[variant] if item["size_mb"] == largest)
        rounds.append(row["rounds"])
        measured.append(row["encrypt"]["throughput_mb_s"])

    baseline_rounds, baseline_throughput = rounds[0], measured[0]

    figure, axes = plt.subplots(figsize=FIGURE_SIZE, facecolor=SURFACE)
    _style(axes)

    smooth = numpy.linspace(min(rounds) - 0.4, max(rounds) + 0.4, 100)
    axes.plot(
        smooth,
        baseline_throughput * baseline_rounds / smooth,
        color=REFERENCE,
        linewidth=1.5,
        linestyle="--",
        label=f"Predicted: {baseline_rounds} / Nr",
        zorder=1,
    )

    for variant, round_count, value in zip(VARIANT_ORDER, rounds, measured):
        predicted = baseline_throughput * baseline_rounds / round_count
        axes.scatter(
            round_count,
            value,
            s=90,
            color=VARIANT_COLOURS[variant],
            edgecolor=SURFACE,
            linewidth=2,
            zorder=3,
            label=variant,
        )
        axes.annotate(
            f"{value:.3f} MB/s\n({value / predicted:+.1%} vs predicted)".replace(
                "(+", "("
            ),
            xy=(round_count, value),
            xytext=(8, 6),
            textcoords="offset points",
            fontsize=8.5,
            color=TEXT_SECONDARY,
        )

    axes.set_xticks(rounds)
    axes.set_xlabel("Number of rounds (Nr)")
    axes.set_ylabel("Encryption throughput (MB/s)")
    axes.set_xlim(min(rounds) - 1, max(rounds) + 1.6)
    axes.legend(frameon=False, fontsize=9, labelcolor=TEXT_SECONDARY)
    _title(
        figure,
        "Cost scales with the number of rounds, not with the key size",
        f"{_subtitle(data)} - measured at {largest:g} MB",
    )
    figure.tight_layout(rect=(0, 0, 1, 0.88))
    path = output_dir / "throughput_vs_rounds.png"
    _save(figure, path)
    plt.close(figure)
    return path


def plot_encrypt_vs_decrypt(data: dict, output_dir: Path):
    """
    Decryption throughput as a fraction of encryption throughput.

    Plotted as a ratio rather than as two sets of bars so that colour can
    keep meaning the variant. The reference line at 1.0 is where the two
    directions cost the same; points below it mean decryption is slower.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    grouped = _series(data)

    figure, axes = plt.subplots(figsize=FIGURE_SIZE, facecolor=SURFACE)
    _style(axes)

    axes.axhline(
        1.0,
        color=REFERENCE,
        linewidth=1.5,
        linestyle="--",
        zorder=1,
        label="Equal cost",
    )

    for variant in VARIANT_ORDER:
        rows = grouped[variant]
        sizes = [row["size_mb"] for row in rows]
        ratios = [
            row["decrypt"]["throughput_mb_s"] / row["encrypt"]["throughput_mb_s"]
            for row in rows
        ]
        axes.plot(
            sizes,
            ratios,
            color=VARIANT_COLOURS[variant],
            linewidth=2,
            marker="o",
            markersize=6,
            markeredgecolor=SURFACE,
            markeredgewidth=2,
            solid_capstyle="round",
            label=variant,
            zorder=3,
        )

    # The ratios sit within a couple of percent of 1.0. Letting the axis
    # auto-scale would spread that sliver over the whole panel and turn
    # measurement noise into an apparent trend, so the range is fixed
    # wide enough for the reader to see that the lines are flat.
    axes.set_ylim(0.90, 1.10)
    axes.set_yticks([0.90, 0.95, 1.00, 1.05, 1.10])

    worst = max(
        abs(
            row["decrypt"]["throughput_mb_s"] / row["encrypt"]["throughput_mb_s"] - 1
        )
        for rows in grouped.values()
        for row in rows
    )
    axes.annotate(
        f"Largest difference: {worst:.1%}",
        xy=(0.5, 0.06),
        xycoords="axes fraction",
        ha="center",
        fontsize=9,
        color=TEXT_SECONDARY,
    )

    axes.set_xscale("log")
    axes.set_xlabel("Data size (MB)")
    axes.set_ylabel("Decryption throughput / encryption throughput")
    axes.legend(frameon=False, fontsize=9, labelcolor=TEXT_SECONDARY)
    _title(
        figure,
        "Decryption costs almost exactly what encryption costs",
        _subtitle(data),
    )
    figure.tight_layout(rect=(0, 0, 1, 0.88))
    path = output_dir / "encrypt_vs_decrypt.png"
    _save(figure, path)
    plt.close(figure)
    return path


def draw_all(data: dict, output_dir: Path) -> list[Path]:
    """Draw every figure of Exercise 4."""
    output_dir.mkdir(parents=True, exist_ok=True)
    return [
        plot_time_vs_size(data, output_dir),
        plot_throughput_by_version(data, output_dir),
        plot_throughput_vs_rounds(data, output_dir),
        plot_encrypt_vs_decrypt(data, output_dir),
    ]


def main(argv: list[str] | None = None) -> int:
    use_utf8_stdout()
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.plot_results",
        description="Draw the figures of Exercise 4 from the benchmark results.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=RESULTS_DIR / "benchmark_aes.json",
        help="benchmark results to read (default: results/benchmark_aes.json)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=RESULTS_DIR,
        help="where to write the figures (default: results/)",
    )
    arguments = parser.parse_args(argv)

    data = load_results(arguments.input)
    draw_all(data, arguments.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
