"""
Exercise 5: the contract the three algorithms share.

The per-algorithm files test what is particular to each method. This one
tests what must be true of all of them, by looping over the registry, so
that the table of cases lives in a single place and no algorithm can
quietly drift away from the others.

The central check is the one the assignment names: that the returned
factors multiply back to n. Next to it sits something stronger - that
the three agree with each other. Three independent methods landing on
the same pair is evidence no single method can give about itself.
"""

import math

import pytest

from factorlib.api import (
    ALGORITHM_ORDER,
    ALGORITHMS,
    DISPLAY_NAMES,
    display_name,
    factor,
)
from factorlib.result import FactorResult, NotFactorable

# (n, p, q) with p <= q, both prime. Kept small enough that Trial
# Division finishes instantly: this suite runs on every change, and the
# cost of the algorithms is the benchmark's subject, not the tests'.
SEMIPRIMES = [
    (15, 3, 5),
    (33, 3, 11),
    (3233, 53, 61),  # the modulus of Exercise 4
    (9409, 97, 97),  # a perfect square
    (15838, 2, 7919),  # even
    (1005973, 997, 1009),  # close factors
    (1006667, 101, 9967),  # distant factors, same size of n
]

PRIMES = [5, 97, 1009, 7919]


def is_prime(n: int) -> bool:
    """
    An oracle independent of the code under test.

    Deliberately the most naive check there is, written against
    `math.isqrt` rather than our own: a test that reused `factorlib` to
    validate `factorlib` would prove only that it is self-consistent.
    """
    if n < 2:
        return False
    return all(n % divisor for divisor in range(2, math.isqrt(n) + 1))


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm", ALGORITHM_ORDER)
@pytest.mark.parametrize(("n", "p", "q"), SEMIPRIMES)
def test_the_factors_multiply_back_to_n(algorithm, n, p, q):
    """p * q = n, the verification Exercise 5 asks for by name."""
    result = factor(n, algorithm)
    assert result.p * result.q == n


@pytest.mark.parametrize("algorithm", ALGORITHM_ORDER)
@pytest.mark.parametrize(("n", "p", "q"), SEMIPRIMES)
def test_the_expected_factors_are_recovered(algorithm, n, p, q):
    result = factor(n, algorithm)
    assert (result.p, result.q) == (p, q)


@pytest.mark.parametrize("algorithm", ALGORITHM_ORDER)
@pytest.mark.parametrize(("n", "p", "q"), SEMIPRIMES)
def test_the_factors_are_prime_and_non_trivial(algorithm, n, p, q):
    """
    Checked against the independent oracle. A semiprime has exactly one
    non-trivial factorization, so anything else would be wrong even if
    the product happened to come out right.
    """
    result = factor(n, algorithm)
    assert 1 < result.p <= result.q < n or result.p == result.q
    assert is_prime(result.p)
    assert is_prime(result.q)


@pytest.mark.parametrize(("n", "p", "q"), SEMIPRIMES)
def test_the_three_algorithms_agree(n, p, q):
    """
    Three unrelated methods, one answer. This is what catches a bug that
    a single algorithm's own tests would call correct.
    """
    pairs = {(factor(n, name).p, factor(n, name).q) for name in ALGORITHM_ORDER}
    assert pairs == {(p, q)}


@pytest.mark.parametrize("algorithm", ALGORITHM_ORDER)
def test_the_result_is_labelled_and_counted(algorithm):
    result = factor(3233, algorithm)
    assert isinstance(result, FactorResult)
    assert result.algorithm == algorithm
    assert result.n == 3233
    assert result.iterations >= 1


@pytest.mark.parametrize("algorithm", ALGORITHM_ORDER)
@pytest.mark.parametrize("n", [0, 1, 2, 3])
def test_every_algorithm_rejects_inputs_below_four(algorithm, n):
    with pytest.raises(NotFactorable):
        factor(n, algorithm)


@pytest.mark.parametrize("algorithm", ALGORITHM_ORDER)
@pytest.mark.parametrize("n", PRIMES)
def test_every_algorithm_rejects_primes(algorithm, n):
    """
    A prime has no non-trivial factorization, so the failure has to be
    the same exception everywhere - the benchmark distinguishes "no
    answer exists" from "ran out of time", and must not confuse them.
    """
    with pytest.raises(NotFactorable):
        factor(n, algorithm)


# ---------------------------------------------------------------------------
# The registry itself
# ---------------------------------------------------------------------------


def test_the_order_covers_the_registry():
    """
    Fixed order, used by every table and every figure. A colour follows
    the algorithm, so this tuple must never disagree with the registry.
    """
    assert set(ALGORITHM_ORDER) == set(ALGORITHMS)
    assert len(ALGORITHM_ORDER) == len(ALGORITHMS) == 3
    assert ALGORITHM_ORDER[0] == "trial-division"


def test_every_algorithm_has_a_label():
    assert set(DISPLAY_NAMES) == set(ALGORITHMS)
    assert display_name("pollard-rho") == "Pollard's Rho"


def test_an_unknown_algorithm_is_reported_clearly():
    with pytest.raises(KeyError, match="unknown algorithm"):
        factor(3233, "quadratic-sieve")


def test_options_reach_the_algorithm_that_accepts_them():
    """
    `seed` belongs to the rho method alone; the registry passes it
    through without the other two having to know about it.
    """
    assert factor(3233, "pollard-rho", seed=7).p == 53


def test_the_default_algorithm_is_the_fast_one():
    assert factor(3233).algorithm == "pollard-rho"
