"""
Tests for the Exercise 7 experiment.

The sweep is a controlled experiment, and what the tests check is that
the control really holds: that only the distance changes from point to
point, that Fermat's cost follows it quadratically, and that Pollard's
Rho - which cannot see the distance at all - stays flat across the same
moduli.

A short sweep at a small size is used so the file runs in about a
second; the committed results come from the real one.
"""

import pytest

from benchmarks import fermat_distance as sweep
from benchmarks import report as report_module

GAPS = (10, 10**4, 10**5)
BITS = 40


@pytest.fixture(scope="module")
def rows():
    return sweep.run_sweep(GAPS, bits=BITS, repeats=1, echo=False)


def test_every_distance_is_measured(rows):
    assert len(rows) == len(GAPS)
    assert [row["target_gap"] for row in rows] == list(GAPS)


def test_the_real_distance_is_at_least_the_target(rows):
    """
    q is the first prime at or above p + gap, so the achieved distance
    overshoots slightly and the report quotes the real one.
    """
    for row in rows:
        assert row["gap"] >= row["target_gap"]


def test_only_the_distance_changes(rows):
    """
    The heart of the experiment. All the moduli share one seed, so p is
    the same prime throughout and q is the only thing moving. If p
    varied too, a change in cost could not be attributed to the gap.
    """
    assert len({row["p"] for row in rows}) == 1
    assert len({row["q"] for row in rows}) == len(rows)


def test_the_moduli_stay_about_the_same_size(rows):
    """The exercise compares moduli of similar size, not of any size."""
    sizes = [row["bits"] for row in rows]
    assert max(sizes) - min(sizes) <= 1


def test_fermat_gets_more_expensive_as_the_factors_separate(rows):
    counts = [row["fermat_iterations"] for row in rows]
    assert counts == sorted(counts)
    assert counts[-1] > counts[0]


def test_the_measurements_match_the_closed_form(rows):
    """
    |p - q|^2 / (8 sqrt(n)) is not a rough guide here, it is the count.
    Checked only where the count is large enough that the rounding of
    ceil(sqrt(n)) does not dominate it.
    """
    for row in rows:
        if row["fermat_iterations"] < sweep.FIT_THRESHOLD:
            continue
        ratio = row["fermat_iterations"] / row["predicted_iterations"]
        assert 0.8 < ratio < 1.25, row


def test_the_control_does_not_move(rows):
    """
    Pollard's Rho cannot see the distance. Its cost across the same
    moduli must stay within the same order of magnitude while Fermat's
    climbs; otherwise the moduli, not the method, would be the cause.
    """
    counts = [row["rho_iterations"] for row in rows]
    assert max(counts) < 10 * min(counts)

    fermat_counts = [row["fermat_iterations"] for row in rows]
    assert max(fermat_counts) / min(fermat_counts) > 100


def test_the_fitted_exponent_is_quadratic():
    """
    The claim of Part V, measured rather than asserted. A wider sweep
    than the fixture's, because a slope needs points above the floor.
    """
    rows = sweep.run_sweep(
        (10**4, 10**5, 3 * 10**5, 10**6), bits=44, repeats=1, echo=False
    )
    exponent = sweep.fit_exponent(rows)
    assert 1.8 <= exponent <= 2.2


def test_the_fit_ignores_the_points_on_the_floor():
    """
    One iteration is the floor: a modulus whose factors are close is
    solved by the first candidate and cannot report less. Those points
    are real, but they cannot constrain a slope, so they are excluded.
    """
    rows = [
        {"gap": 10, "fermat_iterations": 1},
        {"gap": 100, "fermat_iterations": 1},
    ]
    assert sweep.fit_exponent(rows) is None


def test_the_report_leads_with_the_two_required_moduli(rows, tmp_path, monkeypatch):
    monkeypatch.setattr(report_module, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(sweep, "CLOSE_GAP", GAPS[0])
    monkeypatch.setattr(sweep, "FAR_GAP", GAPS[-1])

    report = sweep.build_report(rows, repeats=1)
    text = report.render()
    assert "The two moduli the exercise asks for" in text
    assert "p and q close" in text
    assert "p and q far apart" in text

    data = report.data
    assert data["fitted_exponent"] is None or data["fitted_exponent"] > 1
    assert len(data["measurements"]) == len(GAPS)
    assert data["parameters"]["bits"] == sweep.BITS
