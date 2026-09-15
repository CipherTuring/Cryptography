"""
Tests for the AES substitution box.

Exercise 2. The implementation builds the S-box algebraically from the
field arithmetic, while `tests/vectors.py` holds the 16x16 table exactly
as printed in FIPS-197. The two are produced by completely different
routes, so agreeing on all 256 entries is strong evidence that both are
right.

The remaining tests check the structural properties the S-box was
designed to have, which the published table alone would not reveal.
"""

import pytest

from aeslib.gf import inverse, mul
from aeslib.sbox import (
    AFFINE_CONSTANT,
    INV_SBOX,
    SBOX,
    inv_sub_byte,
    sub_byte,
)

from .vectors import FIPS197_INV_SBOX, FIPS197_SBOX

ALL_BYTES = range(256)


# ---------------------------------------------------------------------------
# Agreement with the published tables
# ---------------------------------------------------------------------------


def test_sbox_matches_the_table_published_in_fips_197():
    assert len(SBOX) == 256
    for value in ALL_BYTES:
        assert SBOX[value] == FIPS197_SBOX[value], f"mismatch at 0x{value:02x}"


def test_inv_sbox_matches_the_table_published_in_fips_197():
    assert len(INV_SBOX) == 256
    for value in ALL_BYTES:
        assert INV_SBOX[value] == FIPS197_INV_SBOX[value], f"mismatch at 0x{value:02x}"


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_sbox_is_a_permutation_of_the_bytes():
    assert sorted(SBOX) == list(ALL_BYTES)


def test_inv_sbox_undoes_sbox():
    for value in ALL_BYTES:
        assert INV_SBOX[SBOX[value]] == value
        assert SBOX[INV_SBOX[value]] == value


def test_sbox_is_the_affine_image_of_the_multiplicative_inverse():
    """
    Ties the substitution back to `gf`: undoing the affine constant and
    the rotations must leave the inverse of the input. Checked here on
    the linear part by rebuilding the map from `inverse` directly.
    """
    for value in ALL_BYTES:
        candidate = inverse(value)
        rotations = 0
        for amount in range(5):
            rotations ^= ((candidate << amount) | (candidate >> (8 - amount))) & 0xFF
        assert SBOX[value] == rotations ^ AFFINE_CONSTANT


def test_sbox_of_zero_is_the_affine_constant():
    """The inverse of 0 is 0, so only the constant c = 0x63 survives."""
    assert SBOX[0x00] == AFFINE_CONSTANT == 0x63


def test_sbox_has_no_fixed_points():
    """A design requirement of AES: no byte is left unchanged."""
    for value in ALL_BYTES:
        assert SBOX[value] != value


def test_sbox_has_no_opposite_fixed_points():
    """A second design requirement: no byte maps to its own complement."""
    for value in ALL_BYTES:
        assert SBOX[value] != value ^ 0xFF


def test_sbox_is_not_affine_over_the_whole_byte():
    """
    The inversion step is what makes the S-box non-linear; if the map
    were additive, AES would be trivially breakable.
    """
    assert any(
        SBOX[a ^ b] != SBOX[a] ^ SBOX[b] ^ SBOX[0]
        for a in ALL_BYTES
        for b in ALL_BYTES
    )


def test_a_known_entry_agrees_with_the_field_computation():
    """0x53 inverts to 0xCA in the field, and the S-box sends it to 0xED."""
    assert inverse(0x53) == 0xCA
    assert mul(0x53, 0xCA) == 1
    assert SBOX[0x53] == 0xED


# ---------------------------------------------------------------------------
# The byte-level helpers
# ---------------------------------------------------------------------------


def test_sub_byte_and_inv_sub_byte_round_trip():
    for value in ALL_BYTES:
        assert inv_sub_byte(sub_byte(value)) == value


def test_helpers_agree_with_the_tables():
    for value in ALL_BYTES:
        assert sub_byte(value) == SBOX[value]
        assert inv_sub_byte(value) == INV_SBOX[value]


@pytest.mark.parametrize("bad", [-1, 256, 1000])
@pytest.mark.parametrize("function", [sub_byte, inv_sub_byte])
def test_helpers_reject_values_outside_a_byte(function, bad):
    with pytest.raises(ValueError):
        function(bad)
