"""
Exercise 6: how the three algorithms scale with the size of n.

    python -m benchmarks.benchmark_factorization           # the full matrix
    python -m benchmarks.benchmark_factorization --quick   # a smoke test

Six RSA moduli are generated, each of an exact bit size, and every
algorithm is run against every one of them three times; the average is
reported. The moduli come from a fixed seed, so a second run measures
the same numbers rather than different ones.

Four of the sizes are chosen so that all three algorithms can finish:
those rows are the comparison the assignment asks for. The two largest
are there for the opposite reason - to show where each method stops
being usable - and the cells that do not finish are reported as
timeouts rather than left blank.

What is measured, and what is deliberately left out:

- generating the modulus happens before the clock starts. The subject
  is the cost of factoring n, not the cost of producing it;
- the budget check inside each algorithm costs one comparison every few
  thousand iterations, far below the measurement noise;
- every run verifies its own result against the known factors. A
  benchmark of a wrong implementation would be meaningless, so
  correctness is confirmed while the numbers are taken;
- once an algorithm exhausts its budget at one size, the larger sizes
  are not attempted. Its cost grows with n, so the outcome is already
  known, and the row says so instead of spending minutes confirming it.
"""

import argparse
import gc
import statistics
import time
from dataclasses import asdict, dataclass, field

from console import use_utf8_stdout
from factorlib.api import ALGORITHM_ORDER, display_name, factor
from factorlib.result import Budget, FactorizationTimeout, NotFactorable
from rsalib.keygen import RsaModulus, generate_modulus

from .report import Report, format_seconds
from .sysinfo import system_info

__all__ = ["Measurement", "measure", "run_benchmark", "build_report", "main"]

# Four sizes where every algorithm finishes, then two where they do not.
SIZES = (24, 32, 40, 48, 64, 80)
QUICK_SIZES = (16, 20, 24)

REPEATS = 3
BUDGET_SECONDS = 60.0
QUICK_BUDGET_SECONDS = 2.0

# Each modulus is drawn from `MODULUS_SEED + bits`, so the experiment is
# reproducible and each size gets a different pair of primes.
MODULUS_SEED = 1000

OK = "ok"
TIMEOUT = "timeout"
SKIPPED = "timeout (not attempted)"


@dataclass
class Measurement:
    """One cell of the table: one algorithm against one modulus."""

    bits: int
    n: int
    algorithm: str
    status: str
    seconds: list[float] = field(default_factory=list)
    iterations: int | None = None

    @property
    def mean_s(self) -> float | None:
        return statistics.fmean(self.seconds) if self.seconds else None

    @property
    def stdev_s(self) -> float | None:
        return statistics.stdev(self.seconds) if len(self.seconds) > 1 else None

    @property
    def relative_spread(self) -> float | None:
        """Standard deviation as a percentage of the mean."""
        if not self.stdev_s or not self.mean_s:
            return None
        return 100 * self.stdev_s / self.mean_s

    def cell(self) -> str:
        """
        How this measurement appears in the assignment's table.

        The dispersion is printed next to the average rather than left
        in the JSON. Two cells whose averages differ by less than their
        spread are not telling us which algorithm is faster, and a
        table that shows only the average invites exactly that reading.
        """
        if self.status != OK:
            return self.status
        if self.relative_spread is None:
            return format_seconds(self.mean_s)
        return f"{format_seconds(self.mean_s)} ± {self.relative_spread:.1f}%"

    def as_dict(self) -> dict:
        data = asdict(self)
        data["mean_s"] = self.mean_s
        data["stdev_s"] = self.stdev_s
        return data


def measure(
    modulus: RsaModulus, algorithm: str, repeats: int, budget_seconds: float
) -> Measurement:
    """
    Time one algorithm against one modulus, `repeats` times.

    The first run decides the outcome: if it exhausts the budget the
    others would too, so the repetitions are abandoned and the cell is
    a timeout. A timing is only kept when the factorization came back
    correct.
    """
    measurement = Measurement(
        bits=modulus.bits, n=modulus.n, algorithm=algorithm, status=OK
    )
    budget = Budget(seconds=budget_seconds)

    for _ in range(repeats):
        # The garbage collector is disabled for the timed region so a
        # collection triggered by unrelated allocations cannot land
        # inside one measurement and not another.
        gc.disable()
        try:
            start = time.perf_counter()
            result = factor(modulus.n, algorithm, budget=budget)
            elapsed = time.perf_counter() - start
        except FactorizationTimeout:
            measurement.status = TIMEOUT
            return measurement
        except NotFactorable as error:  # pragma: no cover - a generator bug
            raise AssertionError(
                f"{algorithm} called {modulus.n} unfactorable: {error}"
            ) from error
        finally:
            gc.enable()

        if (result.p, result.q) != (modulus.p, modulus.q):
            raise AssertionError(
                f"{algorithm} returned {result.p} * {result.q} for {modulus.n}, "
                f"but the modulus was built from {modulus.p} * {modulus.q}"
            )

        measurement.seconds.append(elapsed)
        measurement.iterations = result.iterations

    return measurement


def run_benchmark(
    sizes: tuple[int, ...] = SIZES,
    repeats: int = REPEATS,
    budget_seconds: float = BUDGET_SECONDS,
    echo: bool = True,
) -> tuple[list[RsaModulus], list[Measurement]]:
    """Run the whole matrix and return the moduli and the measurements."""
    moduli = [generate_modulus(bits, seed=MODULUS_SEED + bits) for bits in sizes]
    measurements: list[Measurement] = []
    exhausted: set[str] = set()

    for modulus in moduli:
        if echo:
            print(f"{modulus.bits} bits: n = {modulus.n}")
        for algorithm in ALGORITHM_ORDER:
            if algorithm in exhausted:
                measurements.append(
                    Measurement(
                        bits=modulus.bits,
                        n=modulus.n,
                        algorithm=algorithm,
                        status=SKIPPED,
                    )
                )
                if echo:
                    print(f"  {display_name(algorithm):<16}{SKIPPED}")
                continue

            measurement = measure(modulus, algorithm, repeats, budget_seconds)
            measurements.append(measurement)
            if measurement.status == TIMEOUT:
                exhausted.add(algorithm)
            if echo:
                detail = (
                    f"{measurement.iterations:,} iterations"
                    if measurement.iterations
                    else f"gave up after {format_seconds(budget_seconds)}"
                )
                print(f"  {display_name(algorithm):<16}{measurement.cell():<12}{detail}")

    return moduli, measurements


def build_report(
    moduli: list[RsaModulus],
    measurements: list[Measurement],
    repeats: int,
    budget_seconds: float,
) -> Report:
    """Turn the measurements into the table Exercise 6 asks for."""
    report = Report("Exercise 6: factorization time against the size of n")
    system = system_info()
    labels = [display_name(algorithm) for algorithm in ALGORITHM_ORDER]

    report.section("Experimental conditions")
    report.line(f"  Processor        {system['cpu_model']}")
    report.line(f"  Platform         {system['platform']}")
    report.line(
        f"  Interpreter      {system['python_implementation']} "
        f"{system['python_version']}"
    )
    report.line(f"  Repetitions      {repeats} per cell, average reported")
    report.line(f"  Budget           {format_seconds(budget_seconds)} per algorithm")
    report.line(f"  Modulus seed     {MODULUS_SEED} + bits, so the run repeats")

    by_cell = {(m.bits, m.algorithm): m for m in measurements}

    report.section("Average factorization time, ± the spread of the repetitions")
    report.line("| Bits | n | " + " | ".join(labels) + " |")
    report.line("|---" * (2 + len(labels)) + "|")
    for modulus in moduli:
        cells = [
            by_cell[(modulus.bits, algorithm)].cell() for algorithm in ALGORITHM_ORDER
        ]
        report.line(f"| {modulus.bits} | {modulus.n} | " + " | ".join(cells) + " |")

    report.section("Iterations, which do not depend on this machine")
    report.line("| Bits | " + " | ".join(labels) + " |")
    report.line("|---" * (1 + len(labels)) + "|")
    for modulus in moduli:
        cells = []
        for algorithm in ALGORITHM_ORDER:
            measurement = by_cell[(modulus.bits, algorithm)]
            cells.append(
                f"{measurement.iterations:,}"
                if measurement.iterations is not None
                else measurement.status
            )
        report.line(f"| {modulus.bits} | " + " | ".join(cells) + " |")

    report.section("The moduli, and how far apart their factors are")
    report.line("| Bits | n | p | q | distance |")
    report.line("|---|---|---|---|---|")
    for modulus in moduli:
        report.line(
            f"| {modulus.bits} | {modulus.n} | {modulus.p} | "
            f"{modulus.q} | {modulus.gap:,} |"
        )

    report.data = {
        "experiment": "factorization time against the size of n",
        "system": system,
        "parameters": {
            "repeats": repeats,
            "budget_seconds": budget_seconds,
            "modulus_seed": MODULUS_SEED,
            "sizes": [modulus.bits for modulus in moduli],
            "algorithms": list(ALGORITHM_ORDER),
        },
        "moduli": [
            {
                "bits": modulus.bits,
                "n": modulus.n,
                "p": modulus.p,
                "q": modulus.q,
                "gap": modulus.gap,
            }
            for modulus in moduli
        ],
        "measurements": [measurement.as_dict() for measurement in measurements],
    }
    return report


def main(argv: list[str] | None = None) -> int:
    use_utf8_stdout()
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.benchmark_factorization",
        description="Measure the three algorithms against moduli of several sizes.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="three small sizes and a short budget, to check the harness",
    )
    parser.add_argument("--repeats", type=int, default=None, help="runs per cell")
    parser.add_argument(
        "--budget", type=float, default=None, help="seconds allowed per algorithm"
    )
    parser.add_argument(
        "--stem",
        default=None,
        help="name of the files written in results/",
    )
    arguments = parser.parse_args(argv)

    sizes = QUICK_SIZES if arguments.quick else SIZES
    repeats = arguments.repeats or (1 if arguments.quick else REPEATS)
    budget = arguments.budget or (
        QUICK_BUDGET_SECONDS if arguments.quick else BUDGET_SECONDS
    )
    stem = arguments.stem or (
        "benchmark_factorization_quick"
        if arguments.quick
        else "benchmark_factorization"
    )

    moduli, measurements = run_benchmark(sizes, repeats, budget)
    print()
    build_report(moduli, measurements, repeats, budget).emit(stem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
