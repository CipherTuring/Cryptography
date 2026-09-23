"""
The figures, drawn from the committed results.

    python -m benchmarks.plot_results

Reads `results/benchmark_factorization.json` and
`results/fermat_distance.json` and writes three PNG files next to them.
Nothing is measured here: re-running this never changes a number, only
how the numbers already recorded are drawn. That separation is why the
benchmark has to be run only once.

    cost_vs_bits.png        size of n -> time and iterations, with the
                            fitted exponents next to the predicted ones
    fermat_vs_distance.png  |p - q| -> Fermat's iterations, against the
                            closed form, with Pollard's Rho as a control
    speedup.png             how many times slower than Pollard's Rho

Colour always means the algorithm, in the same order in every figure,
and never means anything else. Grey is reserved for reference curves
and for the budget line, which are never data.

The three colours were checked against the dataviz validator's six
tests on the light surface: lightness band, chroma floor, adjacent-pair
CVD separation (worst 9.2, target 8), normal-vision separation (worst
24.0, floor 15) and contrast. The green lands at 2.74:1 against the
surface, just under the 3:1 relief threshold, which obliges the figures
to carry visible labels rather than rely on colour alone - every series
is named in a legend and every number is also in the committed tables.

Timeouts are drawn, never dropped. A cell that exhausted its budget
appears as a hollow marker on the grey budget line with an arrow
pointing up: omitting it would make Trial Division look as if it
improved at 80 bits, and plotting it at the budget value would state a
measurement that was never taken.
"""

import argparse
import json
import math
from pathlib import Path
from typing import NamedTuple

from console import use_utf8_stdout
from factorlib.api import ALGORITHM_ORDER, display_name

from .report import RESULTS_DIR

__all__ = ["load", "draw_all", "main"]

COLOURS = {
    "trial-division": "#2a78d6",
    "fermat": "#eb6834",
    "pollard-rho": "#1baf7a",
}

SURFACE = "#fcfcfb"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
REFERENCE = "#8a8983"
GRID = "#d8d7d2"

FIGURE_SIZE = (7.5, 4.6)
DPI = 150

# The cost of Trial Division is about n^(1/2) and that of Pollard's Rho
# about n^(1/4). On a log2 scale against the bit size those are straight
# lines of slope 0.5 and 0.25. Fermat has no prediction in terms of the
# size alone - its cost is set by |p - q| - which is the point of the
# second figure.
PREDICTED_SLOPE = {"trial-division": 0.5, "pollard-rho": 0.25}


def load(path: Path) -> dict:
    """Read one of the JSON files the experiments wrote."""
    if not path.exists():
        raise SystemExit(
            f"{path} not found. Run the experiment that produces it first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _style(axes) -> None:
    """Recessive chrome: hairline grid, no box, muted labels."""
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


def _subtitle(data: dict) -> str:
    system = data["system"]
    parameters = data["parameters"]
    return (
        f"{system['cpu_model']} - {system['python_implementation']} "
        f"{system['python_version']} - average of {parameters['repeats']} runs"
    )


def _save(figure, path: Path):
    figure.savefig(path, dpi=DPI, facecolor=SURFACE)
    print(f"-> {path}")
    return path


def _slope(xs: list[float], ys: list[float]) -> float | None:
    """Least squares slope of log2(y) against x, in bits per bit."""
    points = [(x, math.log2(y)) for x, y in zip(xs, ys) if y and y > 0]
    if len(points) < 2:
        return None
    mean_x = sum(x for x, _ in points) / len(points)
    mean_y = sum(y for _, y in points) / len(points)
    denominator = sum((x - mean_x) ** 2 for x, _ in points)
    if denominator == 0:
        return None
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator


class Series(NamedTuple):
    """One algorithm's row of the benchmark, split into what it answered."""

    bits: list[int]
    seconds: list[float]
    stdevs: list[float]
    iterations: list[int]
    timed_out: list[int]


def _series(data: dict, algorithm: str) -> Series:
    """The solved points of one algorithm, plus the sizes that timed out."""
    series = Series([], [], [], [], [])
    for measurement in data["measurements"]:
        if measurement["algorithm"] != algorithm:
            continue
        if measurement["status"] == "ok":
            series.bits.append(measurement["bits"])
            series.seconds.append(measurement["mean_s"])
            series.stdevs.append(measurement["stdev_s"] or 0.0)
            series.iterations.append(measurement["iterations"])
        else:
            series.timed_out.append(measurement["bits"])
    return series


def plot_cost_vs_bits(data: dict, output_dir: Path):
    """
    Time and iterations against the size of the modulus.

    Two panels because the two say different things: a time belongs to
    this machine on this day, an iteration count belongs to the
    algorithm. They agree here, which is what makes the conclusion
    safe to state.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    budget = data["parameters"]["budget_seconds"]
    figure, panels = plt.subplots(1, 2, figsize=(10.0, 4.8), facecolor=SURFACE)
    time_panel, iteration_panel = panels
    for panel in panels:
        _style(panel)

    worst_spread = 0.0
    for algorithm in ALGORITHM_ORDER:
        bits, seconds, stdevs, iterations, timed_out = _series(data, algorithm)
        colour = COLOURS[algorithm]
        slope = _slope(bits, seconds)
        worst_spread = max(
            [worst_spread]
            + [100 * s / m for s, m in zip(stdevs, seconds) if m]
        )
        predicted = PREDICTED_SLOPE.get(algorithm)
        label = display_name(algorithm)
        if slope is not None:
            label += f"  (slope {slope:.2f}/bit"
            label += f", predicted {predicted:.2f})" if predicted else ")"

        # The average of three runs is not a number on its own: the bars
        # are one standard deviation, and where two series overlap the
        # measurement is not saying which of them is faster.
        time_panel.errorbar(
            bits,
            seconds,
            yerr=stdevs,
            color=colour,
            linewidth=2,
            marker="o",
            markersize=7,
            markeredgecolor=SURFACE,
            markeredgewidth=2,
            elinewidth=1.5,
            capsize=4,
            capthick=1.5,
            label=label,
            zorder=3,
        )
        iteration_panel.plot(
            bits,
            iterations,
            color=colour,
            linewidth=2,
            marker="o",
            markersize=7,
            markeredgecolor=SURFACE,
            markeredgewidth=2,
            solid_capstyle="round",
            label=display_name(algorithm),
            zorder=3,
        )

        # Censored points: known only to be at or above the budget.
        for size in timed_out:
            time_panel.plot(
                [size],
                [budget],
                marker="^",
                markersize=9,
                markerfacecolor=SURFACE,
                markeredgecolor=colour,
                markeredgewidth=2,
                linestyle="none",
                zorder=4,
            )

    time_panel.axhline(
        budget,
        color=REFERENCE,
        linewidth=1.5,
        linestyle="--",
        zorder=1,
        label=f"budget: {budget:g} s (hollow = gave up)",
    )

    # Reference slopes, each anchored on the first point of the series it
    # predicts, so the grey line lies along the measurements it explains
    # instead of floating somewhere above them.
    for algorithm, name in (
        ("trial-division", "n^(1/2)"),
        ("pollard-rho", "n^(1/4)"),
    ):
        bits, _, _, iterations, _ = _series(data, algorithm)
        exponent = PREDICTED_SLOPE[algorithm]
        span = [min(bits), max(bits)]
        iteration_panel.plot(
            span,
            [iterations[0] * 2 ** (exponent * (size - span[0])) for size in span],
            color=REFERENCE,
            linewidth=1.5,
            linestyle="--",
            zorder=1,
            label=name,
        )

    time_panel.set_yscale("log")
    time_panel.set_xlabel("Size of n (bits)")
    time_panel.set_ylabel("Average factorization time (s)")
    time_panel.set_title("Time", color=TEXT_PRIMARY, fontsize=10, loc="left")
    time_panel.legend(
        frameon=False, fontsize=8, labelcolor=TEXT_SECONDARY, loc="lower right"
    )

    iteration_panel.set_yscale("log")
    iteration_panel.set_xlabel("Size of n (bits)")
    iteration_panel.set_ylabel("Iterations")
    iteration_panel.set_title(
        "Iterations, independent of the machine",
        color=TEXT_PRIMARY,
        fontsize=10,
        loc="left",
    )
    iteration_panel.legend(
        frameon=False, fontsize=8, labelcolor=TEXT_SECONDARY, loc="upper left"
    )

    _title(
        figure,
        "Every extra bit of n costs Trial Division twice what it costs Rho",
        f"{_subtitle(data)} - bars are one standard deviation, "
        f"worst spread {worst_spread:.0f}%",
    )
    figure.tight_layout(rect=(0, 0, 1, 0.88))
    path = _save(figure, output_dir / "cost_vs_bits.png")
    plt.close(figure)
    return path


def plot_fermat_vs_distance(data: dict, output_dir: Path):
    """
    Fermat's cost against |p - q|, on log-log axes.

    A straight line of slope 2 means the work grows with the square of
    the distance. The closed form is drawn behind the measurements, and
    Pollard's Rho is drawn flat across the same moduli: colour means the
    algorithm here exactly as it does in the other figures.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = data["measurements"]
    gaps = [row["gap"] for row in rows]
    fermat_iterations = [row["fermat_iterations"] for row in rows]
    predicted = [max(row["predicted_iterations"], 0.5) for row in rows]
    rho_iterations = [row["rho_iterations"] for row in rows]
    exponent = data["fitted_exponent"]

    figure, axes = plt.subplots(figsize=FIGURE_SIZE, facecolor=SURFACE)
    _style(axes)

    axes.plot(
        gaps,
        predicted,
        color=REFERENCE,
        linewidth=1.5,
        linestyle="--",
        zorder=1,
        label="predicted: |p-q|^2 / (8 sqrt(n))",
    )
    axes.plot(
        gaps,
        rho_iterations,
        color=COLOURS["pollard-rho"],
        linewidth=2,
        marker="o",
        markersize=6,
        markeredgecolor=SURFACE,
        markeredgewidth=2,
        label="Pollard's Rho (control)",
        zorder=2,
    )
    axes.plot(
        gaps,
        fermat_iterations,
        color=COLOURS["fermat"],
        linewidth=2,
        marker="o",
        markersize=7,
        markeredgecolor=SURFACE,
        markeredgewidth=2,
        label=f"Fermat  (fitted exponent {exponent:.2f}, predicted 2.00)",
        zorder=3,
    )

    # The two cases the assignment asks for by name.
    close = rows[0]
    far = rows[-1]
    for row, text, offset in (
        (close, "p and q close", (12, 10)),
        (far, "p and q far apart", (-14, -24)),
    ):
        axes.annotate(
            f"{text}\n|p-q| = {row['gap']:,}\n{row['fermat_iterations']:,} iterations",
            xy=(row["gap"], row["fermat_iterations"]),
            xytext=offset,
            textcoords="offset points",
            fontsize=8.5,
            color=TEXT_SECONDARY,
            ha="left" if offset[0] > 0 else "right",
        )

    axes.set_xscale("log")
    axes.set_yscale("log")
    axes.set_xlabel("Distance between the factors, |p - q|")
    axes.set_ylabel("Iterations")
    axes.legend(frameon=False, fontsize=8.5, labelcolor=TEXT_SECONDARY, loc="upper left")
    _title(
        figure,
        "Ten times the distance, a hundred times the work",
        f"{_subtitle(data)} - moduli of {data['parameters']['bits']} bits, same p",
    )
    figure.tight_layout(rect=(0, 0, 1, 0.88))
    path = _save(figure, output_dir / "fermat_vs_distance.png")
    plt.close(figure)
    return path


def plot_speedup(data: dict, output_dir: Path):
    """
    How many times slower than Pollard's Rho, size by size.

    Plotted as a ratio so the answer can be read as a number rather
    than inferred from the distance between two curves. The reference
    line at 1.0 is Rho itself.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    baseline = {
        measurement["bits"]: measurement["mean_s"]
        for measurement in data["measurements"]
        if measurement["algorithm"] == "pollard-rho" and measurement["status"] == "ok"
    }

    figure, axes = plt.subplots(figsize=FIGURE_SIZE, facecolor=SURFACE)
    _style(axes)

    axes.axhline(
        1.0,
        color=REFERENCE,
        linewidth=1.5,
        linestyle="--",
        zorder=1,
        label="Pollard's Rho itself",
    )

    worst = 1.0
    rightmost = 0
    for algorithm in ("trial-division", "fermat"):
        bits, seconds, _, _, _ = _series(data, algorithm)
        pairs = [
            (size, value / baseline[size])
            for size, value in zip(bits, seconds)
            if size in baseline
        ]
        if not pairs:
            continue
        sizes = [size for size, _ in pairs]
        ratios = [ratio for _, ratio in pairs]
        worst = max(worst, max(ratios))
        rightmost = max(rightmost, max(sizes))
        axes.plot(
            sizes,
            ratios,
            color=COLOURS[algorithm],
            linewidth=2,
            marker="o",
            markersize=7,
            markeredgecolor=SURFACE,
            markeredgewidth=2,
            label=display_name(algorithm),
            zorder=3,
        )
        axes.annotate(
            f"{ratios[-1]:,.0f}x",
            xy=(sizes[-1], ratios[-1]),
            xytext=(6, 0),
            textcoords="offset points",
            fontsize=9,
            color=TEXT_SECONDARY,
            va="center",
        )

    axes.set_yscale("log")
    axes.set_xlabel("Size of n (bits)")
    axes.set_ylabel("Times slower than Pollard's Rho")
    # Only as far as there is data: the sizes where these two ran out of
    # time have no ratio to show, and empty axis would suggest otherwise.
    axes.set_xlim(right=rightmost + 6)
    axes.legend(frameon=False, fontsize=9, labelcolor=TEXT_SECONDARY, loc="upper left")
    _title(
        figure,
        f"At their last workable size the others are {worst:,.0f} times slower",
        _subtitle(data),
    )
    figure.tight_layout(rect=(0, 0, 1, 0.88))
    path = _save(figure, output_dir / "speedup.png")
    plt.close(figure)
    return path


def draw_all(results_dir: Path = RESULTS_DIR, output_dir: Path | None = None):
    """Draw every figure of Parts IV and V."""
    output_dir = output_dir or results_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    benchmark = load(results_dir / "benchmark_factorization.json")
    distance = load(results_dir / "fermat_distance.json")
    return [
        plot_cost_vs_bits(benchmark, output_dir),
        plot_fermat_vs_distance(distance, output_dir),
        plot_speedup(benchmark, output_dir),
    ]


def main(argv: list[str] | None = None) -> int:
    use_utf8_stdout()
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.plot_results",
        description="Draw the figures of Parts IV and V from the committed results.",
    )
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--output-dir", type=Path, default=None)
    arguments = parser.parse_args(argv)

    draw_all(arguments.results_dir, arguments.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
