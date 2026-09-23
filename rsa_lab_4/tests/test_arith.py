"""
Exercise 5: tests for the greatest common divisor, the modular inverse
and the integer square root.

Two kinds of check, on purpose. Small hand-written cases pin down the
corners, where an off-by-one lives. Randomised cases compare against the
standard library, which is the independent oracle: `math.gcd` and
`math.isqrt` are written in C and are not the code under test, so
agreement over thousands of inputs is evidence that our versions are
right and not just self-consistent.

The inverse has no standard-library oracle worth using, so it is checked
against its definition instead: `a * modinv(a, m) % m == 1`. That is a
stronger statement than matching another implementation.
"""

import math
import random

import pytest

from factorlib.arith import egcd, gcd, is_perfect_square, isqrt, modinv

# Fixed seed: a failing run has to be reproducible, otherwise a rare
# counterexample disappears the moment it is found.
RANDOM = random.Random(20260922)


# ---------------------------------------------------------------------------
# Greatest common divisor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (0, 0, 0),
        (0, 7, 7),
        (7, 0, 7),
        (1, 1, 1),
        (12, 18, 6),
        (18, 12, 6),
        (17, 5, 1),  # coprime
        (13, 13, 13),  # equal
        (2 * 3 * 5, 3 * 5 * 7, 15),
        (61 * 53, 61, 61),  # the factors of the assignment's modulus
    ],
)
def test_gcd_known_values(a, b, expected):
    assert gcd(a, b) == expected


def test_gcd_is_never_negative():
    """Sign is not part of the answer: gcd(-12, 18) is 6, not -6."""
    assert gcd(-12, 18) == 6
    assert gcd(12, -18) == 6
    assert gcd(-12, -18) == 6


def test_gcd_matches_the_standard_library():
    for _ in range(2000):
        a = RANDOM.randrange(0, 10**12)
        b = RANDOM.randrange(0, 10**12)
        assert gcd(a, b) == math.gcd(a, b)


def test_gcd_divides_both_arguments():
    """The defining property, checked directly rather than by comparison."""
    for _ in range(500):
        a = RANDOM.randrange(1, 10**9)
        b = RANDOM.randrange(1, 10**9)
        divisor = gcd(a, b)
        assert a % divisor == 0
        assert b % divisor == 0


def test_gcd_handles_big_integers():
    """No float anywhere, so size is not a problem."""
    a = 2**256 * 3**50
    b = 2**128 * 5**20
    assert gcd(a, b) == 2**128


# ---------------------------------------------------------------------------
# Extended Euclid
# ---------------------------------------------------------------------------


def test_egcd_satisfies_bezout():
    for _ in range(500):
        a = RANDOM.randrange(0, 10**9)
        b = RANDOM.randrange(0, 10**9)
        divisor, x, y = egcd(a, b)
        assert divisor == math.gcd(a, b)
        assert a * x + b * y == divisor


# ---------------------------------------------------------------------------
# Modular inverse
# ---------------------------------------------------------------------------


def test_modinv_of_the_assignment_key():
    """
    The key of Exercise 4: e = 17, phi(3233) = 60 * 52 = 3120.

    This is the step that turns the public exponent into the private
    one, so the expected value is the private exponent itself.
    """
    assert modinv(17, 3120) == 2753
    assert 17 * 2753 % 3120 == 1


@pytest.mark.parametrize(
    ("a", "m", "expected"),
    [
        (1, 7, 1),
        (3, 7, 5),  # 3 * 5 = 15 = 2*7 + 1
        (5, 12, 5),  # self-inverse
        (7, 12, 7),
        (2, 3, 2),
    ],
)
def test_modinv_known_values(a, m, expected):
    assert modinv(a, m) == expected


def test_modinv_satisfies_its_definition():
    for _ in range(1000):
        m = RANDOM.randrange(2, 10**9)
        a = RANDOM.randrange(1, m)
        if math.gcd(a, m) != 1:
            continue
        inverse = modinv(a, m)
        assert 0 <= inverse < m
        assert a * inverse % m == 1


def test_modinv_accepts_values_outside_the_modulus():
    """`a` is reduced first, so a + m has the same inverse as a."""
    assert modinv(17 + 3120, 3120) == modinv(17, 3120)
    assert modinv(-3, 7) == modinv(4, 7)


def test_modinv_rejects_non_coprime_arguments():
    """
    No inverse exists when the arguments share a factor.

    In RSA this is the case where the chosen public exponent divides
    phi(n), which makes the key pair invalid; it has to raise, not
    return a wrong number.
    """
    with pytest.raises(ValueError, match="no inverse"):
        modinv(6, 9)
    with pytest.raises(ValueError, match="no inverse"):
        modinv(4, 8)


def test_modinv_rejects_a_non_positive_modulus():
    with pytest.raises(ValueError, match="modulus must be positive"):
        modinv(3, 0)
    with pytest.raises(ValueError, match="modulus must be positive"):
        modinv(3, -7)


# ---------------------------------------------------------------------------
# Integer square root
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (0, 0),
        (1, 1),
        (2, 1),
        (3, 1),
        (4, 2),
        (8, 2),
        (9, 3),
        (15, 3),
        (16, 4),
        (3233, 56),  # 56^2 = 3136 <= 3233 < 3249 = 57^2
    ],
)
def test_isqrt_known_values(n, expected):
    assert isqrt(n) == expected


def test_isqrt_matches_the_standard_library():
    for _ in range(2000):
        n = RANDOM.randrange(0, 10**18)
        assert isqrt(n) == math.isqrt(n)


def test_isqrt_satisfies_its_definition():
    """r^2 <= n < (r+1)^2 — the property, not a comparison."""
    for _ in range(1000):
        n = RANDOM.randrange(0, 10**15)
        root = isqrt(n)
        assert root * root <= n < (root + 1) * (root + 1)


def test_isqrt_is_exact_where_floats_are_not():
    """
    Past 2^53 a float cannot hold consecutive integers apart, so
    `int(math.sqrt(n))` starts answering with rounded values. These are
    squares of large primes: the exact root has to come back, because
    Fermat's stopping test compares it for equality.
    """
    for root in (10**9 + 7, 2**40 + 15, 2**60 - 93):
        assert isqrt(root * root) == root
        assert isqrt(root * root - 1) == root - 1
        assert isqrt(root * root + 1) == root


def test_isqrt_rejects_negative_input():
    with pytest.raises(ValueError, match="negative"):
        isqrt(-1)


# ---------------------------------------------------------------------------
# Perfect squares — Fermat's stopping condition
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [0, 1, 4, 9, 16, 144, 10**12, (2**61 - 1) ** 2])
def test_is_perfect_square_accepts_squares(n):
    assert is_perfect_square(n)


@pytest.mark.parametrize("n", [-4, -1, 2, 3, 5, 8, 15, 3233, 10**12 + 1])
def test_is_perfect_square_rejects_non_squares(n):
    assert not is_perfect_square(n)


def test_is_perfect_square_agrees_with_isqrt():
    for _ in range(1000):
        n = RANDOM.randrange(0, 10**14)
        assert is_perfect_square(n) == (isqrt(n) ** 2 == n)


def test_is_perfect_square_on_fermats_first_step():
    """
    The first iteration of Fermat on the assignment's modulus.

    a = ceil(sqrt(3233)) = 57, and a^2 - n = 3249 - 3233 = 16 = 4^2, so
    Fermat succeeds immediately here. This is the exact computation the
    algorithm will perform in the next stage.
    """
    n = 3233
    a = 57
    assert is_perfect_square(a * a - n)
    assert isqrt(a * a - n) == 4
    assert (a - 4) * (a + 4) == n
