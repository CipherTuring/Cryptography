"""
Tests for the figures of Exercise 4.

What can be checked automatically about a chart is not whether it looks
good, but whether it is drawn from the right numbers and whether it can
be drawn at all. The figures are rendered here from a small synthetic
result set, so a broken plotting script is caught by the suite instead
of at the end of a fifty-minute benchmark run.

The colour rules are also pinned: one fixed colour per AES variant,
never reused for anything else, so that a reader who learns the legend
of one figure can read all four.
"""

import json

import pytest

from benchmarks.plot_results import (
    VARIANT_COLOURS,
    VARIANT_ORDER,
    _series,
    _subtitle,
    draw_all,
    load_results,
)

FIGURES = (
    "time_vs_size.png",
    "throughput_by_version.png",
    "throughput_vs_rounds.png",
    "encrypt_vs_decrypt.png",
)


def synthetic_results() -> dict:
    """A miniature stand-in for results/benchmark_aes.json."""
    measurements = []
    for variant, key_bits, rounds, rate in (
        ("AES-128", 128, 10, 0.80),
        ("AES-192", 192, 12, 0.67),
        ("AES-256", 256, 14, 0.57),
    ):
        for size_mb in (1.0, 10.0, 100.0):
            encrypt_time = size_mb / rate
            decrypt_time = encrypt_time * 1.01
            measurements.append(
                {
                    "variant": variant,
                    "key_bits": key_bits,
                    "rounds": rounds,
                    "size_mb": size_mb,
                    "round_trip_verified": True,
                    "encrypt": {
                        "times_s": [encrypt_time],
                        "mean_s": encrypt_time,
                        "stdev_s": 0.0,
                        "throughput_mb_s": rate,
                    },
                    "decrypt": {
                        "times_s": [decrypt_time],
                        "mean_s": decrypt_time,
                        "stdev_s": 0.0,
                        "throughput_mb_s": size_mb / decrypt_time,
                    },
                }
            )
    return {
        "system": {
            "cpu_model": "Test CPU",
            "logical_cores": 8,
            "platform": "test",
            "python_version": "3.12.0",
            "python_implementation": "CPython",
        },
        "parameters": {
            "backend": "fast",
            "repeats": 3,
            "sizes_mb": [1.0, 10.0, 100.0],
            "block_size_bytes": 16,
        },
        "round_trip_verified": True,
        "measurements": measurements,
    }


# ---------------------------------------------------------------------------
# Colour discipline
# ---------------------------------------------------------------------------


def test_every_variant_has_a_colour_and_a_place_in_the_order():
    assert set(VARIANT_ORDER) == set(VARIANT_COLOURS)
    assert VARIANT_ORDER == ("AES-128", "AES-192", "AES-256")


def test_no_two_variants_share_a_colour():
    assert len(set(VARIANT_COLOURS.values())) == len(VARIANT_COLOURS)


# ---------------------------------------------------------------------------
# Reading the results
# ---------------------------------------------------------------------------


def test_measurements_are_grouped_by_variant_and_sorted_by_size():
    grouped = _series(synthetic_results())
    assert set(grouped) == set(VARIANT_ORDER)
    for rows in grouped.values():
        sizes = [row["size_mb"] for row in rows]
        assert sizes == sorted(sizes)


def test_the_subtitle_identifies_the_machine_and_the_backend():
    subtitle = _subtitle(synthetic_results())
    assert "Test CPU" in subtitle
    assert "fast" in subtitle
    assert "3 runs" in subtitle


def test_a_missing_results_file_is_a_clear_error(tmp_path):
    with pytest.raises(SystemExit):
        load_results(tmp_path / "does_not_exist.json")


def test_results_are_read_back_from_disk(tmp_path):
    path = tmp_path / "results.json"
    path.write_text(json.dumps(synthetic_results()), encoding="utf-8")
    assert load_results(path)["parameters"]["backend"] == "fast"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_every_figure_is_produced(tmp_path):
    paths = draw_all(synthetic_results(), tmp_path)
    assert [path.name for path in paths] == list(FIGURES)
    for path in paths:
        assert path.exists()
        assert path.stat().st_size > 5_000, f"{path.name} looks empty"


def test_the_output_directory_is_created_if_missing(tmp_path):
    target = tmp_path / "figures"
    draw_all(synthetic_results(), target)
    assert target.is_dir()
    assert len(list(target.glob("*.png"))) == len(FIGURES)
