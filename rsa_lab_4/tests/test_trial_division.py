"""
Exercise 1 under test.

Beyond "it finds the factors", two things are specific to this method
and are checked here: that it walks only the odd candidates, and that it
stops at sqrt(n) rather than wandering past it. Both are claims about
the amount of work done, so they are tested through the iteration
counter, which is the only place that work is visible.
"""

import pytest

from factorlib.result import Budget, FactorizationTimeout, NotFactorable
from factorlib.trial_division import trial_division


def test_the_assignment_modulus():
    result = trial_division(3233)
    assert (result.p, result.q) == (53, 61)


def test_the_smallest_factor_is_found_first():
    """
    105 = 3 * 35, not 5 * 21 or 7 * 15. The search goes upwards, so the
    first divisor it meets is the smallest one, and the cofactor it
    reports is whatever is left - which need not be prime.
    """
    result = trial_division(105)
    assert (result.p, result.q) == (3, 35)


def test_even_moduli_are_settled_in_one_step():
    result = trial_division(2 * 7919)
    assert result.p == 2
    assert result.iterations == 1


def test_only_odd_candidates_are_tested():
    """
    After ruling out 2, the loop steps by two. Reaching an odd divisor p
    therefore costs 1 + (p - 1)/2 iterations rather than p - 1; if the
    even numbers were being tested as well this count would double.
    """
    for n, smallest in [(3233, 53), (1100591668217, 1048583), (9409, 97)]:
        result = trial_division(n)
        assert result.iterations == 1 + (smallest - 1) // 2


def test_the_search_stops_at_the_square_root():
    """
    A prime is recognised by exhausting the candidates, and the message
    names the bound that was reached. Testing beyond sqrt(n) could never
    find anything, since the smaller factor of any factorization is at
    or below it.
    """
    with pytest.raises(NotFactorable, match="is prime: no divisor at or below 31"):
        trial_division(1009)


def test_perfect_squares():
    """n = p^2 is found exactly at the bound, the last candidate tried."""
    result = trial_division(53 * 53)
    assert (result.p, result.q) == (53, 53)


@pytest.mark.parametrize("n", [0, 1, 2, 3])
def test_inputs_below_four_are_rejected(n):
    with pytest.raises(NotFactorable, match="no non-trivial factorization"):
        trial_division(n)


@pytest.mark.parametrize("n", [5, 97, 7919, 1000003])
def test_primes_are_rejected(n):
    with pytest.raises(NotFactorable, match="is prime"):
        trial_division(n)


def test_the_budget_stops_a_hopeless_search():
    """
    An 81-bit modulus needs about 2^39 candidates, which is why Part IV
    reports this cell as a timeout instead of waiting for it.
    """
    budget = Budget(seconds=0.05, check_every=64)
    with pytest.raises(FactorizationTimeout, match="exhausted"):
        trial_division(1208925819660808663073173, budget=budget)


def test_the_budget_does_not_disturb_a_search_that_fits():
    budget = Budget(seconds=30.0)
    result = trial_division(3233, budget=budget)
    assert (result.p, result.q) == (53, 61)
