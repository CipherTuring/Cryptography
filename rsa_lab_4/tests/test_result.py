"""
Tests for the shared result type and the time budget.

`FactorResult` is where "the factors really are the factors" is checked
for all three algorithms at once, so the check itself has to be tested:
a validator that never rejects anything would let a wrong algorithm pass
Exercise 5 unnoticed.
"""

import time

import pytest

from factorlib.result import Budget, FactorizationTimeout, FactorResult


def test_create_derives_the_cofactor():
    result = FactorResult.create(3233, 61, iterations=17, algorithm="demo")
    assert (result.p, result.q) == (53, 61)
    assert result.n == 3233
    assert result.iterations == 17
    assert result.algorithm == "demo"


def test_create_orders_the_pair_either_way_round():
    """
    Fermat finds 53 first and Trial Division finds 53 first, but a
    different algorithm could hand over 61; both must produce the same
    result, otherwise the three cannot be compared for equality.
    """
    from_small = FactorResult.create(3233, 53, iterations=1, algorithm="demo")
    from_large = FactorResult.create(3233, 61, iterations=1, algorithm="demo")
    assert (from_small.p, from_small.q) == (from_large.p, from_large.q)


def test_the_product_is_verified():
    """p * q == n, the verification Exercise 5 asks for by name."""
    with pytest.raises(ValueError, match="which is not"):
        FactorResult(n=3233, p=53, q=60, iterations=1, algorithm="demo")


def test_the_trivial_factorization_is_rejected():
    """
    n = 1 * n is true and useless: it breaks nothing and recovers no
    key. An algorithm that returns it has failed, not succeeded.
    """
    with pytest.raises(ValueError, match="trivial"):
        FactorResult(n=3233, p=1, q=3233, iterations=1, algorithm="demo")


def test_an_unordered_pair_is_rejected():
    with pytest.raises(ValueError, match="p = 61 > q = 53"):
        FactorResult(n=3233, p=61, q=53, iterations=1, algorithm="demo")


def test_a_result_is_immutable():
    """Nothing downstream may rewrite a measurement after the fact."""
    result = FactorResult.create(3233, 61, iterations=1, algorithm="demo")
    with pytest.raises(AttributeError):
        result.p = 1


def test_a_budget_with_time_left_does_not_fire():
    budget = Budget(seconds=30.0, check_every=1)
    budget.start()
    for iteration in range(1, 1000):
        budget.tick(iteration)


def test_an_exhausted_budget_raises():
    budget = Budget(seconds=0.01, check_every=1)
    budget.start()
    time.sleep(0.05)
    with pytest.raises(FactorizationTimeout, match="exhausted"):
        budget.tick(1)


def test_the_clock_is_only_read_every_check_every_iterations():
    """
    The guard is meant to be nearly free inside a hot loop: iterations
    that are not multiples of `check_every` must not be able to fire,
    even long after the deadline has passed.
    """
    budget = Budget(seconds=0.01, check_every=4096)
    budget.start()
    time.sleep(0.05)
    budget.tick(4095)  # not a multiple: silent, even though time is up
    with pytest.raises(FactorizationTimeout):
        budget.tick(4096)


def test_a_budget_can_be_restarted_between_repetitions():
    """
    The benchmark repeats every experiment three times with the same
    budget object; a restart has to give the next run a full allowance.
    """
    budget = Budget(seconds=0.01, check_every=1)
    budget.start()
    time.sleep(0.05)
    with pytest.raises(FactorizationTimeout):
        budget.tick(1)
    budget.start()
    budget.tick(1)
