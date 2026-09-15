"""
Tests for the arithmetic in GF(2^8).

Exercise 2, "finite-field operations". The field is small enough that
most of its laws can be checked exhaustively over all 256 elements
instead of being sampled, which turns these tests into proofs rather
than spot checks. The three-argument laws (associativity and
distributivity) would need 2^24 combinations, so they are checked on a
fixed pseudo-random sample.
"""

import random

import pytest

from aeslib.gf import (
    FIELD_SIZE,
    GENERATOR,
    IRREDUCIBLE,
    MULTIPLICATIVE_ORDER,
    add,
    inverse,
    mul,
    xtime,
)

ALL_BYTES = range(FIELD_SIZE)
NON_ZERO_BYTES = range(1, FIELD_SIZE)

# Fixed seed: a failure must be reproducible.
_RANDOM = random.Random(20260915)
TRIPLES = [
    (
        _RANDOM.randrange(FIELD_SIZE),
        _RANDOM.randrange(FIELD_SIZE),
        _RANDOM.randrange(FIELD_SIZE),
    )
    for _ in range(500)
]


# ---------------------------------------------------------------------------
# Addition
# ---------------------------------------------------------------------------


def test_addition_is_the_xor_of_the_coefficients():
    for a in ALL_BYTES:
        for b in ALL_BYTES:
            assert add(a, b) == a ^ b


def test_addition_is_its_own_inverse():
    """Characteristic 2: adding an element twice cancels it out."""
    for a in ALL_BYTES:
        for b in ALL_BYTES:
            assert add(add(a, b), b) == a


def test_zero_is_the_additive_identity():
    for a in ALL_BYTES:
        assert add(a, 0) == a


# ---------------------------------------------------------------------------
# Multiplication by x
# ---------------------------------------------------------------------------


def test_xtime_agrees_with_multiplying_by_two():
    for a in ALL_BYTES:
        assert xtime(a) == mul(a, 2)


def test_xtime_is_a_plain_shift_when_no_reduction_is_needed():
    for a in range(0x80):
        assert xtime(a) == a << 1


def test_xtime_reduces_with_the_aes_irreducible_polynomial():
    """
    0x80 is x^7; doubling it gives x^8, which must fold back into
    x^4 + x^3 + x + 1 = 0x1B.
    """
    assert xtime(0x80) == 0x1B
    assert IRREDUCIBLE == 0x11B


def test_xtime_never_leaves_the_field():
    for a in ALL_BYTES:
        assert 0 <= xtime(a) < FIELD_SIZE


# ---------------------------------------------------------------------------
# Multiplication
# ---------------------------------------------------------------------------


def test_one_is_the_multiplicative_identity():
    for a in ALL_BYTES:
        assert mul(a, 1) == a
        assert mul(1, a) == a


def test_zero_annihilates_every_element():
    for a in ALL_BYTES:
        assert mul(a, 0) == 0
        assert mul(0, a) == 0


def test_multiplication_is_commutative():
    for a in ALL_BYTES:
        for b in ALL_BYTES:
            assert mul(a, b) == mul(b, a)


@pytest.mark.parametrize("a, b, c", TRIPLES)
def test_multiplication_is_associative(a, b, c):
    assert mul(mul(a, b), c) == mul(a, mul(b, c))


@pytest.mark.parametrize("a, b, c", TRIPLES)
def test_multiplication_distributes_over_addition(a, b, c):
    assert mul(a, add(b, c)) == add(mul(a, b), mul(a, c))


def test_the_field_has_no_zero_divisors():
    """A product of non-zero elements is never zero in a field."""
    for a in NON_ZERO_BYTES:
        for b in NON_ZERO_BYTES:
            assert mul(a, b) != 0


@pytest.mark.parametrize(
    "a, b, expected",
    [
        # FIPS-197, section 4.2: the worked example of the standard.
        (0x57, 0x83, 0xC1),
        # FIPS-197, section 4.2.1: the chain of repeated xtime calls.
        (0x57, 0x02, 0xAE),
        (0x57, 0x04, 0x47),
        (0x57, 0x08, 0x8E),
        (0x57, 0x10, 0x07),
        (0x57, 0x13, 0xFE),
    ],
)
def test_known_products_from_the_specification(a, b, expected):
    assert mul(a, b) == expected


# ---------------------------------------------------------------------------
# Inverses and the structure of the multiplicative group
# ---------------------------------------------------------------------------


def test_every_non_zero_element_has_an_inverse():
    for a in NON_ZERO_BYTES:
        assert mul(a, inverse(a)) == 1


def test_inverse_of_zero_is_zero_by_convention():
    """Zero has no inverse; AES maps it to itself when building the S-box."""
    assert inverse(0) == 0


def test_inverse_is_an_involution():
    for a in ALL_BYTES:
        assert inverse(inverse(a)) == a


def test_inverses_are_unique():
    """Distinct elements cannot share an inverse."""
    inverses = [inverse(a) for a in NON_ZERO_BYTES]
    assert len(set(inverses)) == len(inverses)


def test_one_is_its_own_inverse():
    assert inverse(1) == 1


def test_the_generator_spans_the_whole_multiplicative_group():
    """
    The 255 powers of 0x03 must be 255 distinct non-zero bytes; this is
    what makes the log tables used by `inverse` well defined.
    """
    powers = set()
    value = 1
    for _ in range(MULTIPLICATIVE_ORDER):
        powers.add(value)
        value = mul(value, GENERATOR)
    assert powers == set(NON_ZERO_BYTES)
    assert value == 1  # the cycle closes after exactly 255 steps


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [-1, 256, 1000])
@pytest.mark.parametrize("function", [xtime, inverse])
def test_single_argument_operations_reject_values_outside_a_byte(function, bad):
    with pytest.raises(ValueError):
        function(bad)


@pytest.mark.parametrize("bad", [-1, 256])
@pytest.mark.parametrize("function", [add, mul])
def test_two_argument_operations_reject_values_outside_a_byte(function, bad):
    with pytest.raises(ValueError):
        function(bad, 1)
    with pytest.raises(ValueError):
        function(1, bad)


@pytest.mark.parametrize("bad", ["01", 1.0, None, b"\x01"])
def test_operations_reject_non_integers(bad):
    with pytest.raises(TypeError):
        mul(bad, 1)
