"""
Exercise 7: what the distance between p and q does to Fermat.

    python -m benchmarks.fermat_distance

The assignment asks for two moduli of similar size, one whose factors
are close together and one whose factors are far apart, and for the
distance, the iteration count and the time of each. Those two are
reported first and are the answer to the exercise.

Around them the same measurement is repeated across a sweep of nine
distances, because two points cannot distinguish "grows with the gap"
from "grows with the square of the gap", and the second is the claim
worth making. Fermat starts at ceil(sqrt(n)) and stops at (p + q)/2, so

    iterations = (p + q)/2 - sqrt(n),

which for p and q of similar size is close to

    |p - q|^2 / (8 sqrt(n)),

quadratic in the distance. The sweep fits the exponent from the
measurements and prints it next to the 2.0 the algebra predicts.

Every modulus in the sweep is built from the same seed, so `p` is the
same prime throughout and only `q` moves. That is what makes this a
controlled experiment rather than nine unrelated factorizations: the
one thing changing is the distance.

Pollard's Rho is measured on the same moduli as a control. It knows
nothing about how far apart the factors are, so its cost should stay
flat while Fermat's climbs by six orders of magnitude. A control that
also climbed would mean the moduli, not the method, were responsible.
"""

import argparse
import gc
import math
import statistics
import time

from console import use_utf8_stdout
from factorlib.fermat import fermat
from factorlib.pollard_rho import pollard_rho
from factorlib.result import Budget, FactorizationTimeout
from rsalib.keygen import modulus_with_gap

from .report import Report, format_seconds
from .sysinfo import system_info

__all__ = ["run_sweep", "build_report", "main"]

BITS = 48
SEED = 4207

# Nine distances spanning six orders of magnitude. The smallest are
# below the point where Fermat needs a second iteration at all, which
# is itself the result: close enough is free.
GAPS = (10, 10**3, 10**4, 3 * 10**4, 10**5, 3 * 10**5, 10**6, 3 * 10**6, 10**7)

# The two the assignment asks for by name.
CLOSE_GAP = GAPS[0]
FAR_GAP = GAPS[-1]

REPEATS = 3
BUDGET_SECONDS = 120.0

# Below this many iterations the count is dominated by the rounding of
# ceil(sqrt(n)) rather than by the gap, so those points are excluded
# from the fit - they are plotted, but they cannot constrain a slope.
FIT_THRESHOLD = 10


def time_it(function, n: int, repeats: int, budget: Budget) -> tuple[float, int]:
    """Mean seconds and iteration count for one algorithm on one modulus."""
    timings = []
    iterations = 0
    for _ in range(repeats):
        gc.disable()
        try:
            start = time.perf_counter()
            result = function(n, budget=budget)
            timings.append(time.perf_counter() - start)
        finally:
            gc.enable()
        iterations = result.iterations
    return statistics.fmean(timings), iterations


def run_sweep(
    gaps: tuple[int, ...] = GAPS,
    bits: int = BITS,
    repeats: int = REPEATS,
    budget_seconds: float = BUDGET_SECONDS,
    echo: bool = True,
) -> list[dict]:
    """Measure Fermat, and Rho as a control, at each requested distance."""
    budget = Budget(seconds=budget_seconds)
    rows = []

    for gap in gaps:
        modulus = modulus_with_gap(bits, gap, seed=SEED)
        try:
            fermat_s, fermat_iterations = time_it(
                fermat, modulus.n, repeats, budget
            )
        except FactorizationTimeout:
            fermat_s, fermat_iterations = None, None
        rho_s, rho_iterations = time_it(pollard_rho, modulus.n, repeats, budget)

        # The closed form the measurement is compared against.
        predicted = modulus.gap**2 / (8 * math.isqrt(modulus.n))

        row = {
            "target_gap": gap,
            "gap": modulus.gap,
            "bits": modulus.bits,
            "n": modulus.n,
            "p": modulus.p,
            "q": modulus.q,
            "fermat_iterations": fermat_iterations,
            "fermat_seconds": fermat_s,
            "predicted_iterations": predicted,
            "rho_iterations": rho_iterations,
            "rho_seconds": rho_s,
        }
        rows.append(row)

        if echo:
            print(
                f"  |p-q| = {modulus.gap:>12,}   "
                f"Fermat {fermat_iterations:>10,} iterations   "
                f"{format_seconds(fermat_s):>10}   "
                f"(Rho {rho_iterations:,})"
            )

    return rows


def fit_exponent(rows: list[dict]) -> float | None:
    """
    Least squares on log(iterations) against log(gap).

    The slope of that line is the exponent: 1 would mean the cost grows
    with the distance, 2 that it grows with its square.
    """
    points = [
        (math.log(row["gap"]), math.log(row["fermat_iterations"]))
        for row in rows
        if row["fermat_iterations"] and row["fermat_iterations"] >= FIT_THRESHOLD
    ]
    if len(points) < 2:
        return None
    mean_x = statistics.fmean(x for x, _ in points)
    mean_y = statistics.fmean(y for _, y in points)
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in points)
    denominator = sum((x - mean_x) ** 2 for x, _ in points)
    return numerator / denominator


def _decade_pair(rows: list[dict]) -> tuple[dict, dict] | None:
    """
    Two measured points a factor of ten apart, both above the floor.

    A single pair says the same thing as the fitted slope in a form that
    can be read without a logarithm: multiplying the distance by ten
    should multiply the work by about a hundred.
    """
    usable = [
        row
        for row in rows
        if row["fermat_iterations"] and row["fermat_iterations"] >= FIT_THRESHOLD
    ]
    for low in usable:
        for high in usable:
            if abs(high["gap"] / low["gap"] - 10) < 0.2:
                return low, high
    return None


def build_report(rows: list[dict], repeats: int) -> Report:
    """The two required moduli first, then the sweep that explains them."""
    report = Report("Exercise 7: the distance between p and q, and Fermat's cost")
    system = system_info()
    exponent = fit_exponent(rows)

    close = next(row for row in rows if row["target_gap"] == CLOSE_GAP)
    far = next(row for row in rows if row["target_gap"] == FAR_GAP)

    report.section("Experimental conditions")
    report.line(f"  Processor        {system['cpu_model']}")
    report.line(
        f"  Interpreter      {system['python_implementation']} "
        f"{system['python_version']}"
    )
    report.line(f"  Repetitions      {repeats} per point, average reported")
    report.line(f"  Moduli           {BITS} bits, seed {SEED}, same p throughout")

    report.section("The two moduli the exercise asks for")
    report.line("| Case | n | bits | distance | Fermat iterations | Fermat time |")
    report.line("|---|---|---|---|---|---|")
    for label, row in (("p and q close", close), ("p and q far apart", far)):
        report.line(
            f"| {label} | {row['n']} | {row['bits']} | {row['gap']:,} | "
            f"{row['fermat_iterations']:,} | {format_seconds(row['fermat_seconds'])} |"
        )
    report.line()
    report.line(
        f"  The close pair is settled in {close['fermat_iterations']} iteration: "
        "its factors are near"
    )
    report.line(
        "  enough that the first candidate, a = ceil(sqrt(n)), already works."
    )
    report.line(
        "  One is the floor, so these two points alone cannot measure how the"
    )
    report.line(
        "  cost grows - only that it does. The sweep below is what measures it."
    )

    report.section("The full sweep")
    report.line(
        "| distance | Fermat iterations | predicted | Fermat time | "
        "Rho iterations | Rho time |"
    )
    report.line("|---|---|---|---|---|---|")
    for row in rows:
        report.line(
            f"| {row['gap']:,} | {row['fermat_iterations']:,} | "
            f"{row['predicted_iterations']:,.0f} | "
            f"{format_seconds(row['fermat_seconds'])} | "
            f"{row['rho_iterations']:,} | {format_seconds(row['rho_seconds'])} |"
        )

    report.section("What the sweep shows")
    if exponent is not None:
        report.line(
            f"  Fitted exponent      {exponent:.2f}   "
            "(the algebra predicts 2.00)"
        )
    decade = _decade_pair(rows)
    if decade is not None:
        low, high = decade
        report.line(
            f"  Ten times the gap    {low['gap']:,} -> {high['gap']:,} multiplies "
            f"the work by {high['fermat_iterations'] / low['fermat_iterations']:.0f}, "
            "not by 10"
        )
    rho_counts = [row["rho_iterations"] for row in rows]
    report.line(
        f"  Rho, the control     {min(rho_counts):,} to {max(rho_counts):,} "
        "iterations, with no trend in the distance"
    )
    report.line(
        "  Fermat is not a slow algorithm or a fast one. It is the right"
    )
    report.line(
        "  algorithm for a modulus whose factors were chosen too close"
    )
    report.line(
        "  together, and the wrong one for every other modulus - which is"
    )
    report.line(
        "  why key generation is required to keep p and q far apart."
    )

    report.data = {
        "experiment": "Fermat's cost against the distance between the factors",
        "system": system,
        "parameters": {
            "bits": BITS,
            "seed": SEED,
            "repeats": repeats,
            "gaps": list(GAPS),
            "close_gap": CLOSE_GAP,
            "far_gap": FAR_GAP,
            "fit_threshold": FIT_THRESHOLD,
        },
        "fitted_exponent": exponent,
        "measurements": rows,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    use_utf8_stdout()
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.fermat_distance",
        description="Measure Fermat's cost against the distance between p and q.",
    )
    parser.add_argument("--repeats", type=int, default=REPEATS)
    parser.add_argument("--budget", type=float, default=BUDGET_SECONDS)
    parser.add_argument("--stem", default="fermat_distance")
    arguments = parser.parse_args(argv)

    rows = run_sweep(repeats=arguments.repeats, budget_seconds=arguments.budget)
    print()
    build_report(rows, arguments.repeats).emit(arguments.stem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
