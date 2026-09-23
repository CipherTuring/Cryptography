"""
Tests for the figures.

A test cannot judge whether a chart reads well, and these do not try.
What they check is the part that can be got wrong silently: that the
figures are drawn from the committed results rather than from anything
measured here, that a cell which timed out still appears, and that the
files are actually written.

The censored-point check is the one that matters. Dropping a timeout
would leave Trial Division's curve ending at 48 bits with no sign that
it was ever asked about 64, which reads as "not tested" instead of
"could not finish".
"""

import json

import pytest

from benchmarks import plot_results as plots
from benchmarks.report import RESULTS_DIR

matplotlib = pytest.importorskip("matplotlib")


@pytest.fixture(scope="module")
def benchmark():
    path = RESULTS_DIR / "benchmark_factorization.json"
    if not path.exists():
        pytest.skip("run 'python -m benchmarks.benchmark_factorization' first")
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def distance():
    path = RESULTS_DIR / "fermat_distance.json"
    if not path.exists():
        pytest.skip("run 'python -m benchmarks.fermat_distance' first")
    return json.loads(path.read_text(encoding="utf-8"))


def test_a_missing_results_file_says_what_to_run(tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        plots.load(tmp_path / "nothing.json")


def test_solved_and_timed_out_points_are_kept_apart(benchmark):
    """
    Trial Division finishes at the four small sizes and runs out of
    time at the two large ones. Both sets have to come back: one is
    plotted as a measurement, the other as a censored marker.
    """
    series = plots._series(benchmark, "trial-division")
    assert len(series.bits) == len(series.seconds) == len(series.iterations)
    assert len(series.stdevs) == len(series.seconds)
    assert series.timed_out, "the benchmark recorded no timeout to draw"
    assert set(series.bits).isdisjoint(series.timed_out)
    assert min(series.timed_out) > max(series.bits)


def test_no_measured_point_is_silently_dropped(benchmark):
    """Every cell of the table is either plotted or marked as censored."""
    for algorithm in plots.COLOURS:
        series = plots._series(benchmark, algorithm)
        recorded = [
            measurement
            for measurement in benchmark["measurements"]
            if measurement["algorithm"] == algorithm
        ]
        assert len(series.bits) + len(series.timed_out) == len(recorded)


def test_the_fitted_slope_recovers_the_known_exponents(benchmark):
    """
    The claim the left panel prints in its legend: Trial Division costs
    about n^(1/2) and Pollard's Rho about n^(1/4), which against the
    bit size are slopes of 0.50 and 0.25.
    """
    for algorithm, predicted in plots.PREDICTED_SLOPE.items():
        series = plots._series(benchmark, algorithm)
        slope = plots._slope(series.bits, series.seconds)
        assert abs(slope - predicted) < 0.1, (algorithm, slope)


def test_a_slope_needs_at_least_two_points():
    assert plots._slope([24], [0.1]) is None
    assert plots._slope([], []) is None


def test_every_algorithm_has_its_own_colour():
    assert len(set(plots.COLOURS.values())) == len(plots.COLOURS)


def test_the_three_figures_are_written(tmp_path, benchmark, distance):
    """
    Drawn into a temporary directory: the committed PNGs are a
    deliverable and a test must not overwrite them with a variant.
    """
    paths = plots.draw_all(RESULTS_DIR, tmp_path)
    assert {path.name for path in paths} == {
        "cost_vs_bits.png",
        "fermat_vs_distance.png",
        "speedup.png",
    }
    for path in paths:
        assert path.exists()
        assert path.stat().st_size > 10_000  # a real chart, not a blank canvas


def test_the_command_line_entry_point(tmp_path, benchmark, distance, capsys):
    assert plots.main(["--output-dir", str(tmp_path)]) == 0
    assert "cost_vs_bits.png" in capsys.readouterr().out


def test_every_timing_carries_its_dispersion(benchmark):
    """
    The figure labels its points as the average of three runs, so each
    one has to arrive with the spread of those runs. Where two series
    overlap within their bars, the measurement is not claiming that one
    is faster than the other - Fermat and Trial Division at 48 bits are
    exactly that case.
    """
    for algorithm in plots.COLOURS:
        series = plots._series(benchmark, algorithm)
        assert all(stdev >= 0 for stdev in series.stdevs)
        assert len(series.stdevs) == len(series.seconds)
