"""
Tests for the benchmark harness.

The harness is not part of the cryptographic core, but it is what the
conclusions of Exercise 4 rest on: if the throughput formula or the
aggregation were wrong, the analysis would be wrong with them. What is
checked here is the arithmetic and the argument handling, not the
timings themselves, which are not reproducible by nature.
"""

import pytest

from aeslib.state import BLOCK_SIZE
from benchmarks.benchmark_aes import (
    DEFAULT_REPEATS,
    DEFAULT_SIZES_MB,
    MEGABYTE,
    Measurement,
    _aligned_length,
    _parse_arguments,
    build_report,
    run_benchmark,
)


def make_measurement(**overrides) -> Measurement:
    defaults = {
        "variant": "AES-128",
        "key_bits": 128,
        "rounds": 10,
        "size_mb": 10.0,
        "encrypt_times": [2.0, 2.0, 2.0],
        "decrypt_times": [4.0, 4.0, 4.0],
        "round_trip_verified": True,
    }
    defaults.update(overrides)
    return Measurement(**defaults)


# ---------------------------------------------------------------------------
# Throughput and aggregation
# ---------------------------------------------------------------------------


def test_throughput_is_data_over_time():
    """R = D / T: 10 MB in 2 s is 5 MB/s."""
    measurement = make_measurement()
    assert measurement.encrypt_throughput == pytest.approx(5.0)
    assert measurement.decrypt_throughput == pytest.approx(2.5)


def test_the_reported_time_is_the_average_of_the_repetitions():
    measurement = make_measurement(encrypt_times=[1.0, 2.0, 3.0])
    assert measurement.encrypt_mean == pytest.approx(2.0)


def test_the_standard_deviation_is_reported():
    measurement = make_measurement(encrypt_times=[1.0, 2.0, 3.0])
    assert measurement.encrypt_stdev == pytest.approx(1.0)


def test_a_single_repetition_has_no_spread():
    """statistics.stdev needs two points; one measurement reports zero."""
    measurement = make_measurement(encrypt_times=[1.5], decrypt_times=[1.5])
    assert measurement.encrypt_stdev == 0.0
    assert measurement.decrypt_stdev == 0.0


def test_the_dictionary_form_carries_every_reported_number():
    payload = make_measurement().as_dict()
    assert payload["variant"] == "AES-128"
    assert payload["rounds"] == 10
    assert payload["encrypt"]["throughput_mb_s"] == pytest.approx(5.0)
    assert payload["decrypt"]["mean_s"] == pytest.approx(4.0)
    assert payload["round_trip_verified"] is True


# ---------------------------------------------------------------------------
# Sizes are whole blocks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size_mb", [0.25, 1, 10, 100])
def test_the_buffer_length_is_a_whole_number_of_blocks(size_mb):
    length = _aligned_length(size_mb)
    assert length % BLOCK_SIZE == 0
    assert length > 0


def test_whole_megabytes_need_no_rounding():
    assert _aligned_length(1) == MEGABYTE
    assert _aligned_length(100) == 100 * MEGABYTE


def test_a_size_below_one_block_is_rejected():
    with pytest.raises(ValueError):
        run_benchmark((0.000001,), repeats=1, backend="fast", echo=False)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def test_the_defaults_match_the_assignment():
    arguments = _parse_arguments([])
    assert tuple(arguments.sizes) == DEFAULT_SIZES_MB == (1.0, 10.0, 100.0)
    assert arguments.repeats == DEFAULT_REPEATS >= 3
    assert arguments.backend == "fast"


def test_quick_mode_overrides_the_sizes_and_repetitions():
    arguments = _parse_arguments(["--quick", "--sizes", "50", "--repeats", "9"])
    assert arguments.sizes == [1.0]
    assert arguments.repeats == 2


@pytest.mark.parametrize("argv", [["--repeats", "0"], ["--sizes", "0"], ["--sizes", "-1"]])
def test_invalid_parameters_are_refused(argv):
    with pytest.raises(SystemExit):
        _parse_arguments(argv)


def test_an_unknown_backend_is_refused():
    with pytest.raises(SystemExit):
        _parse_arguments(["--backend", "gpu"])


# ---------------------------------------------------------------------------
# End to end, on a buffer small enough for a test suite
# ---------------------------------------------------------------------------


def test_a_tiny_run_produces_one_measurement_per_variant():
    measurements = run_benchmark((0.01,), repeats=1, backend="fast", echo=False)
    assert [item.variant for item in measurements] == [
        "AES-128",
        "AES-192",
        "AES-256",
    ]
    assert [item.rounds for item in measurements] == [10, 12, 14]


def test_a_tiny_run_verifies_the_round_trip():
    """The benchmark confirms correctness while it measures."""
    measurements = run_benchmark((0.01,), repeats=1, backend="fast", echo=False)
    assert all(item.round_trip_verified for item in measurements)


def test_the_report_records_the_setup_and_every_measurement():
    measurements = run_benchmark((0.01,), repeats=1, backend="fast", echo=False)
    report = build_report(measurements, backend="fast", repeats=1)
    assert report.data["parameters"]["backend"] == "fast"
    assert report.data["round_trip_verified"] is True
    assert len(report.data["measurements"]) == 3
    assert "cpu_model" in report.data["system"]

    text = report.render()
    assert "AES-128" in text and "AES-256" in text
    assert "not a secure mode" in text


def test_the_text_tables_are_aligned():
    """A header and its rows must have the same width to stay readable."""
    measurements = run_benchmark((0.01,), repeats=1, backend="fast", echo=False)
    lines = build_report(measurements, backend="fast", repeats=1).render().splitlines()
    header = next(line for line in lines if line.startswith("Variant"))
    rows = [line for line in lines if line.startswith("AES-")]
    assert rows, "no measurement rows in the report"
    for row in rows:
        assert len(row) == len(header), f"{row!r} does not match the header width"
