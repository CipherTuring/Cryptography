"""
Exercise 2 under test.

The characteristic behaviour of this method is that its cost depends on
the distance between the factors and on nothing else, so the tests are
built around that: the iteration count is checked against the closed
form it must obey, and the close-versus-distant contrast that Part V
will measure is asserted here as a property.
"""

import pytest

from factorlib.arith import isqrt
from factorlib.fermat import fermat
from factorlib.result import Budget, FactorizationTimeout, NotFactorable

# Two primes twelve apart, just above 2^40. Their product has 81 bits,
# far beyond what a float can hold exactly.
CLOSE_P = 1099511627791
CLOSE_Q = 1099511627803


def test_the_assignment_modulus_is_found_immediately():
    """
    53 and 61 are close, so a = ceil(sqrt(3233)) = 57 already works:
    57^2 - 3233 = 16 = 4^2, and 57 -+ 4 are the factors. One iteration.
    """
    result = fermat(3233)
    assert (result.p, result.q) == (53, 61)
    assert result.iterations == 1


def test_the_iteration_count_matches_its_closed_form():
    """
    The search starts at ceil(sqrt(n)) and stops at a = (p + q)/2, so
    the number of values tried is fixed by the factors alone. This is
    the formula Part V uses to explain the measurements.
    """
    for p, q in [(53, 61), (101, 103), (3, 11), (CLOSE_P, CLOSE_Q)]:
        n = p * q
        start = isqrt(n) + (0 if isqrt(n) ** 2 == n else 1)
        expected = (p + q) // 2 - start + 1
        assert fermat(n).iterations == expected


def test_close_factors_are_much_cheaper_than_distant_ones():
    """
    The result Exercise 7 asks to explain, stated as a property. Both
    moduli are about 1.006 million, so size is held fixed and the only
    difference is the gap: 12 in one case, 9866 in the other.
    """
    close = fermat(997 * 1009)
    distant = fermat(101 * 9967)
    assert close.iterations == 1
    assert distant.iterations > 1000 * close.iterations


def test_exactness_above_the_float_range():
    """
    n here is 81 bits. `int(math.sqrt(n))` would be off, the starting
    point would be wrong, and the perfect-square test would never fire.
    Exact integer arithmetic is what makes this return at all.
    """
    result = fermat(CLOSE_P * CLOSE_Q)
    assert (result.p, result.q) == (CLOSE_P, CLOSE_Q)
    assert result.iterations == 1


def test_perfect_squares_are_the_best_case():
    """n = p^2 means b = 0: the very first a is already the answer."""
    result = fermat(53 * 53)
    assert (result.p, result.q) == (53, 53)
    assert result.iterations == 1


def test_even_moduli_are_settled_in_one_step():
    """
    2m with m odd is not a difference of two squares, so the factor 2 is
    taken out before the method starts.
    """
    result = fermat(2 * 7919)
    assert result.p == 2
    assert result.iterations == 1


@pytest.mark.parametrize("n", [0, 1, 2, 3])
def test_inputs_below_four_are_rejected(n):
    with pytest.raises(NotFactorable, match="no non-trivial factorization"):
        fermat(n)


@pytest.mark.parametrize("n", [5, 97, 1009])
def test_primes_are_rejected(n):
    """
    a = (n+1)/2 always solves the equation, with b = (n-1)/2 and the
    useless factorization n = 1 * n. Reaching it proves primality.
    """
    with pytest.raises(NotFactorable, match="is prime"):
        fermat(n)


def test_the_budget_stops_a_hopeless_search():
    """
    101 times a prime just above 2^60: a 67-bit modulus whose factors
    are as unbalanced as they get. The search would have to walk from
    sqrt(n) up to (p + q)/2, which is about 5.7 * 10^17 iterations, so
    Part IV reports this kind of cell as a timeout instead of waiting.

    Size alone would not do it: the 81-bit modulus of the test above has
    factors twelve apart and Fermat settles it in one step. What makes a
    case hopeless for this method is the distance, not the magnitude.
    """
    budget = Budget(seconds=0.05, check_every=64)
    with pytest.raises(FactorizationTimeout, match="exhausted"):
        fermat(101 * 1152921504606847009, budget=budget)


def test_the_budget_does_not_disturb_a_search_that_fits():
    budget = Budget(seconds=30.0)
    assert fermat(3233, budget=budget).p == 53
