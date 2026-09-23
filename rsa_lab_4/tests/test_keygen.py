"""
Tests for the generator that produces the experiments' inputs.

If the moduli were wrong, every number in `results/` would be wrong
with them, so the generator is held to three things: the primes really
are prime, the sizes really are the sizes the table claims, and the
same seed really does give the same modulus twice.

The primality test is checked against a naive oracle over a full range
of small integers, and against the Carmichael numbers, which are the
composites that defeat the simpler Fermat test and are therefore the
reason Miller-Rabin is used here at all.
"""

import math

import pytest

from rsalib.keygen import (
    RsaModulus,
    generate_modulus,
    is_probable_prime,
    modulus_with_gap,
    next_prime,
    random_prime,
)

# Composites that pass the Fermat test for every base coprime with them.
CARMICHAEL = [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265]

LARGE_PRIMES = [1000003, 1099511627791, 1152921504606847009]


def naive_is_prime(n: int) -> bool:
    """The oracle: trial division by everything up to the square root."""
    if n < 2:
        return False
    return all(n % divisor for divisor in range(2, math.isqrt(n) + 1))


# ---------------------------------------------------------------------------
# Primality
# ---------------------------------------------------------------------------


def test_primality_agrees_with_the_oracle_on_every_small_integer():
    """Exhaustive below 5000: no room for a wrong corner."""
    for n in range(-5, 5000):
        assert is_probable_prime(n) == naive_is_prime(n), n


@pytest.mark.parametrize("n", LARGE_PRIMES)
def test_large_primes_are_recognised(n):
    assert is_probable_prime(n)


@pytest.mark.parametrize("n", CARMICHAEL)
def test_carmichael_numbers_are_rejected(n):
    """
    These are composite but pass Fermat's test for every coprime base,
    so a weaker primality test would hand the benchmark a modulus with
    three factors and the experiment would quietly measure something
    else. Miller-Rabin sees through them.
    """
    assert not is_probable_prime(n)
    assert not naive_is_prime(n)


def test_products_of_large_primes_are_rejected():
    assert not is_probable_prime(1099511627791 * 1099511627803)


def test_next_prime():
    assert next_prime(0) == 2
    assert next_prime(2) == 2
    assert next_prime(3) == 3
    assert next_prime(4) == 5
    assert next_prime(1000) == 1009
    for start in (10, 100, 1000, 10**6):
        prime = next_prime(start)
        assert naive_is_prime(prime)
        assert prime >= start


# ---------------------------------------------------------------------------
# Random primes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bits", [2, 3, 8, 12, 16, 24, 32, 40])
def test_random_primes_have_exactly_the_requested_size(bits):
    """
    A prime one bit short would make the modulus smaller than the row
    of the table says it is.
    """
    import random

    rng = random.Random(bits)
    for _ in range(10):
        prime = random_prime(bits, rng)
        assert prime.bit_length() == bits
        assert is_probable_prime(prime)


def test_a_prime_needs_at_least_two_bits():
    import random

    with pytest.raises(ValueError, match="at least 2 bits"):
        random_prime(1, random.Random(0))


# ---------------------------------------------------------------------------
# Moduli
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bits", [16, 20, 24, 32, 40, 48, 64, 80])
def test_generated_moduli_are_exactly_the_requested_size(bits):
    modulus = generate_modulus(bits, seed=bits)
    assert modulus.bits == bits
    assert modulus.n.bit_length() == bits


@pytest.mark.parametrize("bits", [16, 24, 32, 48, 64])
def test_generated_moduli_are_products_of_two_distinct_primes(bits):
    modulus = generate_modulus(bits, seed=bits)
    assert modulus.p * modulus.q == modulus.n
    assert modulus.p < modulus.q
    assert is_probable_prime(modulus.p)
    assert is_probable_prime(modulus.q)


def test_the_same_seed_gives_the_same_modulus():
    """
    Reproducibility, which is what lets the benchmark be re-run and
    compared with the committed results.
    """
    first = generate_modulus(32, seed=1032)
    second = generate_modulus(32, seed=1032)
    assert (first.n, first.p, first.q) == (second.n, second.p, second.q)


def test_different_seeds_give_different_moduli():
    moduli = {generate_modulus(32, seed=seed).n for seed in range(10)}
    assert len(moduli) == 10


def test_a_modulus_too_small_to_be_a_product_is_refused():
    with pytest.raises(ValueError, match="too small"):
        generate_modulus(5, seed=1)


# ---------------------------------------------------------------------------
# Controlled distance between the factors - the instrument of Part V
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("gap", [2, 10, 1000, 10**5, 10**7])
def test_the_gap_is_at_least_the_one_requested(gap):
    """
    `q` is the first prime at or above `p + gap`, so the real distance
    is never below the target and only overshoots by the space to the
    next prime.
    """
    modulus = modulus_with_gap(40, gap, seed=gap)
    assert modulus.gap >= gap
    assert modulus.gap < gap + 1000
    assert is_probable_prime(modulus.p)
    assert is_probable_prime(modulus.q)


def test_wider_targets_give_wider_gaps():
    gaps = [modulus_with_gap(40, gap, seed=5).gap for gap in (10, 10**3, 10**6)]
    assert gaps == sorted(gaps)


def test_moduli_with_different_gaps_stay_about_the_same_size():
    """
    Part V compares moduli of similar size at different distances, so
    widening the gap must not change the size out from under the
    comparison.
    """
    sizes = {modulus_with_gap(40, gap, seed=5).bits for gap in (2, 100, 10**4)}
    assert max(sizes) - min(sizes) <= 1


def test_a_non_positive_gap_is_refused():
    with pytest.raises(ValueError, match="must be positive"):
        modulus_with_gap(40, 0, seed=1)


# ---------------------------------------------------------------------------
# The container itself
# ---------------------------------------------------------------------------


def test_a_modulus_checks_its_own_factors():
    with pytest.raises(ValueError, match="is not"):
        RsaModulus(n=3233, p=53, q=60)


def test_a_modulus_requires_ordered_factors():
    with pytest.raises(ValueError, match="must be ordered"):
        RsaModulus(n=3233, p=61, q=53)


def test_bits_and_gap():
    modulus = RsaModulus(n=3233, p=53, q=61)
    assert modulus.bits == 12
    assert modulus.gap == 8
