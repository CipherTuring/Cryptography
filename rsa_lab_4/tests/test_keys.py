"""
Exercise 5: RSA encryption/decryption consistency.

The assignment asks for the round trip to be tested, and that is the
core of this file: for keys built from known primes, `decrypt` must undo
`encrypt` for every representable message. The relation is checked in
both directions and against its underlying identity, `e * d = 1 mod
phi(n)`, so a key that merely happened to work on one message could not
pass.
"""

import math
import random

import pytest

from rsalib.keys import (
    PrivateKey,
    PublicKey,
    decrypt,
    encrypt,
    private_exponent,
    recover_private_key,
    totient,
)

RANDOM = random.Random(20260923)

SMALL_PRIMES = [53, 61, 97, 101, 103, 197, 199, 211, 997, 1009]


# e = 17 is the assignment's exponent and is tried first; the others are
# the usual alternatives, needed because a public exponent has to be
# coprime with phi(n) and 17 divides phi for some of these prime pairs.
PUBLIC_EXPONENTS = (17, 65537, 7, 5, 3)


def key_pair(p: int, q: int) -> tuple[PublicKey, PrivateKey]:
    """A usable key pair built from two known primes."""
    phi = totient(p, q)
    for e in PUBLIC_EXPONENTS:
        if e < phi and math.gcd(e, phi) == 1:
            public = PublicKey(n=p * q, e=e)
            return public, recover_private_key(public, p, q)
    raise AssertionError(f"no usable public exponent for p = {p}, q = {q}")


# ---------------------------------------------------------------------------
# The pieces
# ---------------------------------------------------------------------------


def test_totient_of_the_assignment_modulus():
    assert totient(61, 53) == 3120
    assert totient(53, 61) == 3120  # the order of the factors is irrelevant


@pytest.mark.parametrize(
    ("p", "q", "expected"), [(3, 5, 8), (7, 11, 60), (97, 97, 9216)]
)
def test_totient_known_values(p, q, expected):
    assert totient(p, q) == expected


@pytest.mark.parametrize(("p", "q"), [(1, 5), (0, 5), (5, 1), (-3, 7)])
def test_totient_rejects_factors_below_two(p, q):
    with pytest.raises(ValueError, match="must be primes"):
        totient(p, q)


@pytest.mark.parametrize(
    ("p", "q"),
    [
        (2, 95865),  # 191730 = 2 * 3 * 5 * 7 * 11 * 83
        (3, 35),  # 105, the cofactor Trial Division reports
        (4, 9),
        (95865, 4),  # both composite
    ],
)
def test_totient_rejects_composite_factors(p, q):
    """
    (p-1)(q-1) is Euler's totient only when both factors are prime.

    A factorization algorithm returns one divisor and whatever is left,
    and what is left need not be prime. Accepting such a pair here would
    produce a private exponent that decrypts almost nothing, without any
    error to show for it, so the precondition is enforced rather than
    assumed.
    """
    with pytest.raises(ValueError, match="composite"):
        totient(p, q)


def test_a_number_with_more_than_two_prime_factors_has_no_key():
    """
    The regression: 191730 factors correctly as 2 * 95865, but it is not
    an RSA modulus, and the key that used to come out of it was wrong
    for almost every message.
    """
    public = PublicKey(n=191730, e=17)
    with pytest.raises(ValueError, match="not a product of two primes"):
        recover_private_key(public, 2, 95865)


def test_the_private_exponent_of_exercise_four():
    """The number the whole attack exists to produce."""
    assert private_exponent(17, 3120) == 2753


def test_the_private_exponent_inverts_the_public_one():
    for p, q in [(53, 61), (97, 101), (997, 1009)]:
        phi = totient(p, q)
        d = private_exponent(17, phi)
        assert 17 * d % phi == 1


def test_an_exponent_sharing_a_factor_with_phi_is_refused():
    """
    phi(3233) = 3120 is divisible by 13, so e = 13 has no inverse and
    the key pair cannot exist. This has to raise rather than produce a
    number that decrypts nothing.
    """
    with pytest.raises(ValueError, match="no inverse"):
        private_exponent(13, 3120)


# ---------------------------------------------------------------------------
# Encryption and decryption
# ---------------------------------------------------------------------------


def test_the_assignment_ciphertext_decrypts():
    public = PublicKey(n=3233, e=17)
    private = recover_private_key(public, 61, 53)
    assert private.d == 2753
    assert private.decrypt(2790) == 65
    assert public.encrypt(65) == 2790


def test_decrypt_undoes_encrypt_for_every_message():
    """
    Exhaustive over the whole message space of a small modulus: with
    n = 3233 there are 3233 representable messages and all of them are
    checked, which leaves no room for a lucky case.
    """
    public, private = key_pair(53, 61)
    for message in range(public.n):
        assert private.decrypt(public.encrypt(message)) == message


@pytest.mark.parametrize("p", SMALL_PRIMES)
def test_round_trip_across_many_keys(p):
    q = RANDOM.choice([other for other in SMALL_PRIMES if other != p])
    public, private = key_pair(p, q)
    for _ in range(50):
        message = RANDOM.randrange(0, public.n)
        assert private.decrypt(public.encrypt(message)) == message


def test_encrypt_undoes_decrypt_as_well():
    """
    The two exponents are symmetric: applying d first and e second also
    returns the message. This is what signatures rely on, and it shows
    the round trip is an identity rather than a one-way coincidence.
    """
    public, private = key_pair(101, 103)
    for _ in range(100):
        message = RANDOM.randrange(0, public.n)
        assert public.encrypt(private.decrypt(message)) == message


def test_the_free_functions_agree_with_the_key_objects():
    public, private = key_pair(53, 61)
    assert encrypt(65, public.e, public.n) == public.encrypt(65)
    assert decrypt(2790, private.d, private.n) == private.decrypt(2790)


@pytest.mark.parametrize("message", [3233, 3234, -1, 10**6])
def test_messages_outside_the_modulus_are_refused(message):
    """
    RSA represents integers in [0, n) and nothing else. `pow` would
    happily reduce a larger message and return a different plaintext on
    decryption, so the boundary is enforced instead of being discovered
    later as a wrong answer.
    """
    with pytest.raises(ValueError, match="must lie in"):
        encrypt(message, 17, 3233)


# ---------------------------------------------------------------------------
# Key recovery
# ---------------------------------------------------------------------------


def test_recovery_refuses_factors_that_are_not_the_factors():
    public = PublicKey(n=3233, e=17)
    with pytest.raises(ValueError, match="not the modulus"):
        recover_private_key(public, 53, 60)


def test_the_private_key_carries_only_n_and_d():
    """
    p, q and phi are scaffolding: once d exists they are of no further
    use, which is why decryption needs nothing but the pair (n, d).
    """
    public = PublicKey(n=3233, e=17)
    private = recover_private_key(public, 61, 53)
    assert (private.n, private.d) == (3233, 2753)
    assert not hasattr(private, "p")


def test_keys_are_immutable():
    public = PublicKey(n=3233, e=17)
    with pytest.raises(AttributeError):
        public.e = 3
