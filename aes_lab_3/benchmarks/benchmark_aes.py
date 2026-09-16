"""
Exercise 3: performance of the AES core.

Measures encryption time, decryption time and the corresponding
throughput for AES-128, AES-192 and AES-256 over 1, 10 and 100 MB,
repeating every experiment and reporting the average.

    python -m benchmarks.benchmark_aes             # the full matrix
    python -m benchmarks.benchmark_aes --quick     # a smoke test

Throughput is R = D / T with D in megabytes and T in seconds.

What is being measured, and what is deliberately left out:

- The key schedule runs once, in the `AES` constructor, outside the
  timed region. The subject of Exercise 3 is the cost of the core, not
  the cost of setting up a key, and a key is set up once per session
  while blocks are processed by the million.
- The data buffer is generated before the clock starts, so the cost of
  `os.urandom` never enters a measurement.
- The fast backend is used by default. It is validated against the
  reference core byte for byte in `tests/test_backends.py`; the
  reference core would need about an hour and a half per 100 MB pass,
  which makes the full matrix impractical.
- Every repetition decrypts what it just encrypted and checks that the
  plaintext comes back. A benchmark of a wrong implementation would be
  meaningless, so correctness is confirmed while the numbers are taken.

The blocks are processed independently, which is raw ECB. As the
assignment states, this measures the cryptographic core and is not a
secure mode of operation for real applications.
"""

import argparse
import gc
import os
import statistics
import sys
import time
from dataclasses import dataclass, field

from aeslib.api import AES, BACKENDS
from aeslib.state import BLOCK_SIZE
from console import use_utf8_stdout

from .report import Report
from .sysinfo import system_info

__all__ = ["Measurement", "run_benchmark", "main"]

MEGABYTE = 1024 * 1024

DEFAULT_SIZES_MB = (1.0, 10.0, 100.0)
DEFAULT_REPEATS = 3
DEFAULT_BACKEND = "fast"
DEFAULT_STEM = "benchmark_aes"

# The quick mode exists to check that the harness works end to end, not
# to produce a measurement worth reporting.
QUICK_SIZES_MB = (1.0,)
QUICK_REPEATS = 2

KEY_SIZES_IN_BYTES = (16, 24, 32)

# A measurement is rejected when a timed interval spent more than this
# share of its wall-clock time off the processor. The failure this
# guards against is a machine that suspends or is busy with something
# else, which showed up in practice as 99% of an interval lost; ordinary
# scheduling noise stays well under 10%, so the threshold sits between
# the two rather than as close to zero as possible.
IDLE_TOLERANCE = 0.20

# On top of the relative tolerance, a fixed allowance. The CPU clock is
# quantised to about 15 ms on Windows, and a few scheduler quanta are
# unavoidable, so on a short interval a purely relative rule is far too
# strict: 5% of 1.3 s is only four clock ticks.
IDLE_ABSOLUTE_SLACK_S = 0.25

# Below this duration the check abstains entirely rather than reporting
# noise. Every size the assignment asks for runs far longer than a
# second.
IDLE_MIN_INTERVAL_S = 1.0


@dataclass
class Measurement:
    """Timings of one variant over one data size."""

    variant: str
    key_bits: int
    rounds: int
    size_mb: float
    encrypt_times: list[float] = field(default_factory=list)
    decrypt_times: list[float] = field(default_factory=list)
    encrypt_cpu_times: list[float] = field(default_factory=list)
    decrypt_cpu_times: list[float] = field(default_factory=list)
    round_trip_verified: bool = False

    @property
    def idle_fraction(self) -> float:
        """
        Largest share of a timed interval during which this process was
        not actually running on a processor.

        Wall-clock time is what the throughput of Exercise 3 is defined
        on, but it also counts time the machine spent suspended or
        running something else. Comparing it against CPU time turns that
        contamination into a number: a clean measurement sits near zero,
        while a long gap means the reading is about the machine, not
        about AES.

        Intervals shorter than `IDLE_MIN_INTERVAL_S` are ignored, because
        the resolution of the CPU clock would dominate the comparison.
        With no interval long enough to judge, the result is zero: the
        check abstains instead of inventing a verdict.
        """
        return max(
            ((wall - cpu) / wall for wall, cpu in self._judgeable_intervals()),
            default=0.0,
        )

    def _judgeable_intervals(self):
        """The timed intervals long enough for the CPU clock to resolve."""
        for wall, cpu in zip(
            self.encrypt_times + self.decrypt_times,
            self.encrypt_cpu_times + self.decrypt_cpu_times,
        ):
            if wall >= IDLE_MIN_INTERVAL_S:
                yield wall, cpu

    @property
    def reliable(self) -> bool:
        """
        True when no repetition lost a meaningful amount of time.

        The allowance is whichever is larger, the relative tolerance or
        the fixed slack, so that a short interval is not condemned by a
        few clock ticks while a long one is still held to a percentage.
        """
        return all(
            (wall - cpu) <= max(IDLE_TOLERANCE * wall, IDLE_ABSOLUTE_SLACK_S)
            for wall, cpu in self._judgeable_intervals()
        )

    @staticmethod
    def _stdev(values: list[float]) -> float:
        return statistics.stdev(values) if len(values) > 1 else 0.0

    @property
    def encrypt_mean(self) -> float:
        return statistics.fmean(self.encrypt_times)

    @property
    def decrypt_mean(self) -> float:
        return statistics.fmean(self.decrypt_times)

    @property
    def encrypt_stdev(self) -> float:
        return self._stdev(self.encrypt_times)

    @property
    def decrypt_stdev(self) -> float:
        return self._stdev(self.decrypt_times)

    @property
    def encrypt_throughput(self) -> float:
        """R = D / T, in MB/s."""
        return self.size_mb / self.encrypt_mean

    @property
    def decrypt_throughput(self) -> float:
        return self.size_mb / self.decrypt_mean

    def as_dict(self) -> dict:
        return {
            "variant": self.variant,
            "key_bits": self.key_bits,
            "rounds": self.rounds,
            "size_mb": self.size_mb,
            "round_trip_verified": self.round_trip_verified,
            "idle_fraction": self.idle_fraction,
            "reliable": self.reliable,
            "encrypt": {
                "times_s": self.encrypt_times,
                "cpu_times_s": self.encrypt_cpu_times,
                "mean_s": self.encrypt_mean,
                "stdev_s": self.encrypt_stdev,
                "throughput_mb_s": self.encrypt_throughput,
            },
            "decrypt": {
                "times_s": self.decrypt_times,
                "cpu_times_s": self.decrypt_cpu_times,
                "mean_s": self.decrypt_mean,
                "stdev_s": self.decrypt_stdev,
                "throughput_mb_s": self.decrypt_throughput,
            },
        }


def _aligned_length(size_mb: float) -> int:
    """Bytes for `size_mb`, rounded down to a whole number of blocks."""
    return int(size_mb * MEGABYTE) // BLOCK_SIZE * BLOCK_SIZE


def measure(
    size_mb: float, key_bytes: int, repeats: int, backend: str, data: bytes
) -> Measurement:
    """Time one variant over one buffer, `repeats` times."""
    # Outside the clock: building the instance runs the key schedule.
    aes = AES(os.urandom(key_bytes), backend=backend)
    result = Measurement(
        variant=aes.name,
        key_bits=aes.key_size,
        rounds=aes.rounds,
        size_mb=len(data) / MEGABYTE,
    )

    verified = True
    for _ in range(repeats):
        # A collection in the middle of a measurement would be charged to
        # the cipher, so one is forced beforehand.
        gc.collect()

        start, cpu_start = time.perf_counter(), time.process_time()
        ciphertext = aes.encrypt(data)
        result.encrypt_times.append(time.perf_counter() - start)
        result.encrypt_cpu_times.append(time.process_time() - cpu_start)

        start, cpu_start = time.perf_counter(), time.process_time()
        recovered = aes.decrypt(ciphertext)
        result.decrypt_times.append(time.perf_counter() - start)
        result.decrypt_cpu_times.append(time.process_time() - cpu_start)

        verified = verified and recovered == data
        del ciphertext, recovered

    result.round_trip_verified = verified
    return result


def run_benchmark(
    sizes_mb: tuple[float, ...],
    repeats: int,
    backend: str,
    echo: bool = True,
) -> list[Measurement]:
    """Run the whole matrix: every size against every key length."""
    measurements: list[Measurement] = []
    for size_mb in sizes_mb:
        length = _aligned_length(size_mb)
        if length == 0:
            raise ValueError(f"{size_mb} MB is smaller than one AES block")
        data = os.urandom(length)
        for key_bytes in KEY_SIZES_IN_BYTES:
            result = measure(size_mb, key_bytes, repeats, backend, data)
            measurements.append(result)
            if echo:
                print(
                    f"  {result.variant}  {result.size_mb:7.2f} MB  "
                    f"encrypt {result.encrypt_mean:8.3f} s "
                    f"({result.encrypt_throughput:5.2f} MB/s)  "
                    f"decrypt {result.decrypt_mean:8.3f} s "
                    f"({result.decrypt_throughput:5.2f} MB/s)"
                    f"{'' if result.round_trip_verified else '  ROUND TRIP FAILED'}"
                    f"{'' if result.reliable else f'  UNRELIABLE: {result.idle_fraction:.0%} off-CPU'}",
                    flush=True,
                )
        del data
    return measurements


def _table_for_size(report: Report, size_mb: float, rows: list[Measurement]) -> None:
    """One block of the text report: all three variants at one data size."""
    report.section(f"Data size: {size_mb:g} MB")
    report.line(
        f"{'Variant':<10}{'Rounds':>7}{'Encrypt (s)':>16}{'Enc (MB/s)':>12}"
        f"{'Decrypt (s)':>16}{'Dec (MB/s)':>12}"
    )
    report.rule("-", 73)
    for row in rows:
        # Each time field is 9 + 3 + 4 = 16 characters, matching its header.
        report.line(
            f"{row.variant:<10}{row.rounds:>7}"
            f"{row.encrypt_mean:>9.3f} +-{row.encrypt_stdev:>4.2f}"
            f"{row.encrypt_throughput:>12.3f}"
            f"{row.decrypt_mean:>9.3f} +-{row.decrypt_stdev:>4.2f}"
            f"{row.decrypt_throughput:>12.3f}"
        )


def _relative_table(report: Report, measurements: list[Measurement]) -> None:
    """
    Throughput of each variant relative to AES-128, against the ratio the
    round counts predict. This is the evidence for Exercise 4.
    """
    report.section("Throughput relative to AES-128, and the ratio 10 : Nr")
    report.line(
        f"{'Size (MB)':<12}{'Variant':<10}{'Rounds':>7}"
        f"{'Measured':>11}{'10 / Nr':>10}{'Difference':>12}"
    )
    report.rule("-", 62)
    by_size: dict[float, list[Measurement]] = {}
    for item in measurements:
        by_size.setdefault(item.size_mb, []).append(item)
    for size_mb, rows in by_size.items():
        baseline = next(row for row in rows if row.key_bits == 128)
        for row in rows:
            measured = row.encrypt_throughput / baseline.encrypt_throughput
            predicted = baseline.rounds / row.rounds
            report.line(
                f"{size_mb:<12.2f}{row.variant:<10}{row.rounds:>7}"
                f"{measured:>11.3f}{predicted:>10.3f}"
                f"{measured - predicted:>+12.3f}"
            )


def build_report(
    measurements: list[Measurement], backend: str, repeats: int
) -> Report:
    """Assemble the text and JSON forms of the results."""
    report = Report("Exercise 3 - AES core performance")
    information = system_info()

    report.section("Experimental setup")
    report.line(f"CPU               : {information['cpu_model']}")
    report.line(f"Logical cores     : {information['logical_cores']}")
    report.line(f"Platform          : {information['platform']}")
    report.line(
        f"Python            : {information['python_implementation']} "
        f"{information['python_version']}"
    )
    report.line(f"Backend           : {backend}")
    report.line(f"Repetitions       : {repeats} (times below are the average)")
    report.line("Mode              : raw ECB over the core, not a secure mode")
    report.line(
        "Key schedule      : computed once per variant, outside the timed region"
    )

    verified = all(item.round_trip_verified for item in measurements)
    report.line(
        f"Round trip        : {'verified on every repetition' if verified else 'FAILED'}"
    )
    worst_idle = max((item.idle_fraction for item in measurements), default=0.0)
    reliable = all(item.reliable for item in measurements)
    report.line(
        f"Off-CPU time      : at most {worst_idle:.1%} of any timed interval"
        f"{'' if reliable else '  -- ABOVE TOLERANCE, RESULTS NOT USABLE'}"
    )

    by_size: dict[float, list[Measurement]] = {}
    for item in measurements:
        by_size.setdefault(item.size_mb, []).append(item)
    for size_mb, rows in by_size.items():
        _table_for_size(report, size_mb, rows)

    _relative_table(report, measurements)

    report.data = {
        "system": information,
        "parameters": {
            "backend": backend,
            "repeats": repeats,
            "sizes_mb": sorted(by_size),
            "block_size_bytes": BLOCK_SIZE,
        },
        "round_trip_verified": verified,
        "reliable": reliable,
        "worst_idle_fraction": worst_idle,
        "measurements": [item.as_dict() for item in measurements],
    }
    return report


def _parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.benchmark_aes",
        description=(
            "Measure encryption and decryption time and throughput for "
            "AES-128, AES-192 and AES-256."
        ),
    )
    parser.add_argument(
        "--sizes",
        type=float,
        nargs="+",
        metavar="MB",
        default=list(DEFAULT_SIZES_MB),
        help="data sizes in megabytes (default: 1 10 100)",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=DEFAULT_REPEATS,
        metavar="N",
        help="repetitions per experiment, averaged (default: 3)",
    )
    parser.add_argument(
        "--backend",
        choices=BACKENDS,
        default=DEFAULT_BACKEND,
        help=(
            "core implementation to measure (default: fast; the reference "
            "core is around forty-five times slower)"
        ),
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="smoke test of the harness: 1 MB, 2 repetitions",
    )
    parser.add_argument(
        "--stem",
        default=DEFAULT_STEM,
        help="base name of the files written to results/ (default: benchmark_aes)",
    )
    arguments = parser.parse_args(argv)

    if arguments.quick:
        arguments.sizes = list(QUICK_SIZES_MB)
        arguments.repeats = QUICK_REPEATS
    if arguments.repeats < 1:
        parser.error("--repeats must be at least 1")
    if any(size <= 0 for size in arguments.sizes):
        parser.error("every size must be greater than zero")
    return arguments


def main(argv: list[str] | None = None) -> int:
    use_utf8_stdout()
    arguments = _parse_arguments(argv)
    sizes = tuple(sorted(arguments.sizes))

    # Three variants, two directions, at roughly 0.68 MB/s on the fast
    # backend. Only an order of magnitude, but the full run takes long
    # enough that it is worth saying so before starting.
    seconds = sum(sizes) * arguments.repeats * 2 * 3 / 0.68
    estimate = (
        f"{seconds:.0f} s" if seconds < 90 else f"{seconds / 60:.0f} min"
    )
    print(f"Backend: {arguments.backend}   repetitions: {arguments.repeats}")
    print(f"Sizes  : {', '.join(f'{size:g} MB' for size in sizes)}")
    print(f"Rough estimate: {estimate}\n")

    measurements = run_benchmark(sizes, arguments.repeats, arguments.backend)

    if not all(item.round_trip_verified for item in measurements):
        print("\nERROR: decryption did not recover the plaintext", file=sys.stderr)
        return 1

    print()
    report = build_report(measurements, arguments.backend, arguments.repeats)
    report.emit(arguments.stem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
