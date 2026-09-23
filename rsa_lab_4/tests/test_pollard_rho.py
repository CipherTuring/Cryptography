"""
Exercise 3 under test.

This is the only randomised algorithm of the three, so two properties
matter that do not arise elsewhere: the run has to be reproducible, or
the benchmark would report a different iteration count every time, and
it has to stay correct when the randomness changes, or the fixed seed
would be hiding a bug rather than controlling variance.

The scaling claim of Part IV is also asserted here: the cost is about
n^(1/4) where Trial Division needs n^(1/2), so on a 41-bit modulus the
rho method must be dramatically cheaper. The test compares iteration
counts rather than seconds, which is a property of the algorithms and
not of the machine.
"""

import pytest

from factorlib.pollard_rho import pollard_rho
from factorlib.result import Budget, FactorizationTimeout, NotFactorable
from factorlib.trial_division import trial_division

# Two primes just above 2^20; their product has 41 bits.
MID_P = 1048583
MID_Q = 1049599


def test_the_assignment_modulus():
    result = pollard_rho(3233)
    assert (result.p, result.q) == (53, 61)


def test_the_run_is_reproducible():
    """Same modulus, same seed, same trajectory, same iteration count."""
    first = pollard_rho(MID_P * MID_Q)
    second = pollard_rho(MID_P * MID_Q)
    assert first.iterations == second.iterations
    assert (first.p, first.q) == (second.p, second.q)


@pytest.mark.parametrize("seed", [1, 2, 3, 99, 20260922])
def test_correct_under_any_seed(seed):
    """
    The seed decides how long it takes, never what comes out. If a seed
    could change the answer, the fixed default would be hiding a bug.
    """
    result = pollard_rho(MID_P * MID_Q, seed=seed)
    assert (result.p, result.q) == (MID_P, MID_Q)


def test_a_different_seed_takes_a_different_path():
    """
    Confirms the seed is really wired to the trajectory: at least one
    of several seeds must disagree with the default on the cost.
    """
    default = pollard_rho(MID_P * MID_Q).iterations
    others = {pollard_rho(MID_P * MID_Q, seed=seed).iterations for seed in range(1, 6)}
    assert others != {default}


def test_it_beats_trial_division_by_orders_of_magnitude():
    """
    n^(1/4) against n^(1/2), measured in iterations on a 41-bit
    modulus. This is the core claim of the experimental part, so it is
    pinned down here rather than left to the benchmark alone.
    """
    n = MID_P * MID_Q
    assert pollard_rho(n).iterations * 100 < trial_division(n).iterations


@pytest.mark.parametrize("n", [9, 25, 49, 121, 3233, 1005973])
def test_small_composites(n):
    result = pollard_rho(n)
    assert result.p * result.q == n
    assert result.p > 1


def test_even_moduli_are_settled_in_one_step():
    """
    x^2 + c modulo an even number is a poor generator, so the factor 2
    is taken out before the sequence starts.
    """
    result = pollard_rho(2 * 7919)
    assert result.p == 2
    assert result.iterations == 1


@pytest.mark.parametrize("n", [0, 1, 2, 3])
def test_inputs_below_four_are_rejected(n):
    with pytest.raises(NotFactorable, match="no non-trivial factorization"):
        pollard_rho(n)


@pytest.mark.parametrize("n", [5, 97, 1009])
def test_primes_exhaust_the_restarts(n):
    """
    No collision can reveal a factor that does not exist, so every
    trajectory ends with d = n and the restarts run out. Unlike the
    other two methods this is a bounded search rather than a proof of
    primality, and the message says so.
    """
    with pytest.raises(NotFactorable, match="restarts of the rho method"):
        pollard_rho(n)


def test_the_restart_budget_is_adjustable():
    with pytest.raises(NotFactorable, match="^3 restarts"):
        pollard_rho(97, max_restarts=3)


def test_the_time_budget_stops_a_long_run():
    budget = Budget(seconds=0.001, check_every=1)
    with pytest.raises(FactorizationTimeout, match="exhausted"):
        pollard_rho(1208925819660808663073173, budget=budget)


def test_the_budget_does_not_disturb_a_search_that_fits():
    budget = Budget(seconds=30.0)
    assert pollard_rho(3233, budget=budget).p == 53
