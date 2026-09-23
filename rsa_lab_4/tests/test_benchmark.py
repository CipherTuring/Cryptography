"""
Tests for the Exercise 6 harness.

Nothing here measures performance: a timing assertion would be a test
that fails on a busy machine, and the numbers are the benchmark's job,
not the suite's. What is tested is that the harness reports honestly -
that it verifies each factorization while timing it, that a cell which
ran out of time says so instead of going blank, and that the table and
the JSON describe the same run.

Everything runs at the quick sizes, so the whole file takes well under
a second.
"""

import json

import pytest

from benchmarks import benchmark_factorization as bench
from benchmarks import report as report_module
from factorlib.api import ALGORITHM_ORDER
from rsalib.keygen import generate_modulus

SIZES = (16, 20)


@pytest.fixture
def run():
    """One quick run of the matrix, shared by the tests that read it."""
    return bench.run_benchmark(SIZES, repeats=2, budget_seconds=5.0, echo=False)


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------


def test_every_algorithm_is_measured_against_every_modulus(run):
    moduli, measurements = run
    assert len(measurements) == len(SIZES) * len(ALGORITHM_ORDER)
    covered = {(m.bits, m.algorithm) for m in measurements}
    assert covered == {
        (modulus.bits, algorithm)
        for modulus in moduli
        for algorithm in ALGORITHM_ORDER
    }


def test_the_repetitions_are_actually_repeated(run):
    """Three runs per cell is what the assignment asks for; here it is two."""
    _, measurements = run
    for measurement in measurements:
        assert len(measurement.seconds) == 2
        assert measurement.mean_s > 0
        assert measurement.stdev_s is not None


def test_small_moduli_are_solved_by_all_three(run):
    _, measurements = run
    assert all(measurement.status == bench.OK for measurement in measurements)
    assert all(measurement.iterations >= 1 for measurement in measurements)


def test_the_moduli_are_the_reproducible_ones(run):
    """The rows must come from the documented seed, not from chance."""
    moduli, _ = run
    for modulus in moduli:
        expected = generate_modulus(modulus.bits, seed=bench.MODULUS_SEED + modulus.bits)
        assert modulus.n == expected.n


def test_a_wrong_factorization_would_stop_the_benchmark(monkeypatch):
    """
    Each timed run is verified against the known factors. A silently
    wrong algorithm must abort the experiment rather than have its
    speed reported as a result.
    """
    modulus = generate_modulus(16, seed=bench.MODULUS_SEED + 16)

    class Wrong:
        p, q, iterations = 1, modulus.n, 1

    monkeypatch.setattr(bench, "factor", lambda *args, **kwargs: Wrong())
    with pytest.raises(AssertionError, match="but the modulus was built from"):
        bench.measure(modulus, "trial-division", repeats=1, budget_seconds=5.0)


# ---------------------------------------------------------------------------
# Giving up
# ---------------------------------------------------------------------------


def test_an_exhausted_budget_is_reported_as_a_timeout():
    modulus = generate_modulus(48, seed=bench.MODULUS_SEED + 48)
    measurement = bench.measure(
        modulus, "trial-division", repeats=3, budget_seconds=0.001
    )
    assert measurement.status == bench.TIMEOUT
    assert measurement.cell() == "timeout"
    assert measurement.seconds == []
    assert measurement.mean_s is None


def test_larger_sizes_are_not_attempted_after_a_timeout():
    """
    Cost grows with n, so once an algorithm has run out of time the
    larger rows are already decided. They are labelled, not blank: an
    empty cell would read as missing data rather than as a result.
    """
    _, measurements = bench.run_benchmark(
        (32, 40), repeats=1, budget_seconds=0.001, echo=False
    )
    status = {(m.bits, m.algorithm): m.status for m in measurements}

    # A millisecond is not enough for Trial Division at 32 bits...
    assert status[(32, "trial-division")] == bench.TIMEOUT
    # ...so 40 bits is settled without being run.
    assert status[(40, "trial-division")] == bench.SKIPPED

    # The other two are unaffected: each algorithm gives up on its own.
    assert status[(40, "pollard-rho")] == bench.OK


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


def test_the_table_has_one_row_per_modulus(run):
    moduli, measurements = run
    text = bench.build_report(moduli, measurements, 2, 5.0).render()
    assert "| Bits | n | Trial Division | Fermat | Pollard's Rho |" in text
    for modulus in moduli:
        assert f"| {modulus.bits} | {modulus.n} |" in text


def test_the_report_records_the_experimental_conditions(run):
    """
    The assignment requires the same machine and conditions for every
    measurement, so they are printed next to the numbers.
    """
    moduli, measurements = run
    text = bench.build_report(moduli, measurements, 2, 5.0).render()
    assert "Processor" in text
    assert "Repetitions      2 per cell" in text


def test_the_json_mirrors_the_table(run):
    moduli, measurements = run
    data = bench.build_report(moduli, measurements, 2, 5.0).data
    assert data["parameters"]["algorithms"] == list(ALGORITHM_ORDER)
    assert data["parameters"]["repeats"] == 2
    assert len(data["measurements"]) == len(measurements)
    assert len(data["moduli"]) == len(moduli)
    assert {entry["bits"] for entry in data["moduli"]} == set(SIZES)
    for entry in data["measurements"]:
        assert entry["mean_s"] > 0


def test_both_files_are_written(tmp_path, monkeypatch, run):
    """The figures read the JSON, so it has to be valid and complete."""
    monkeypatch.setattr(report_module, "RESULTS_DIR", tmp_path)
    moduli, measurements = run
    text_path, json_path = bench.build_report(moduli, measurements, 2, 5.0).emit(
        "unit_test", echo=False
    )
    assert text_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["experiment"].startswith("factorization time")


def test_the_quick_mode_runs_end_to_end(tmp_path, monkeypatch, capsys):
    """
    The command the README tells a reader to try first. It has to work
    without waiting for the full matrix.
    """
    monkeypatch.setattr(report_module, "RESULTS_DIR", tmp_path)
    assert bench.main(["--quick", "--stem", "unit_test"]) == 0
    assert "Exercise 6" in capsys.readouterr().out
    assert (tmp_path / "unit_test.json").exists()
