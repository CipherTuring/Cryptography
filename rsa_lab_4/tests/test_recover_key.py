"""
Exercise 4 under test: the attack end to end.

The script prints its steps for the oral defense, but the numbers are
produced by `recover()`, which returns them, so the tests assert on
values rather than on text. The validation the assignment provides -
p = 61, q = 53 - is checked here, and so is the part it leaves to us:
that the recovered plaintext re-encrypts to the ciphertext we started
from.
"""

from attacks.recover_key import DEFAULT_C, DEFAULT_E, DEFAULT_N, main, recover
from factorlib.api import ALGORITHM_ORDER
from rsalib.keys import PublicKey, recover_private_key


def test_the_assignment_values():
    """
    The whole of Exercise 4 in one assertion block: factor 3233, get
    phi, invert e, decrypt 2790.
    """
    recovery = recover()
    assert (recovery.p, recovery.q) == (53, 61)  # the expected pair, ordered
    assert recovery.phi == 3120
    assert recovery.private.d == 2753
    assert recovery.message == 65
    assert recovery.verified


def test_the_three_algorithms_are_all_run_and_agree():
    recovery = recover()
    assert set(recovery.factorizations) == set(ALGORITHM_ORDER)
    assert recovery.algorithms_agree
    for result in recovery.factorizations.values():
        assert (result.p, result.q) == (53, 61)


def test_the_recovered_key_is_the_real_private_key():
    """
    Not just "it decrypts this one ciphertext": the recovered d has to
    work for every message under this modulus.
    """
    recovery = recover()
    for message in range(0, DEFAULT_N, 97):
        assert recovery.private.decrypt(recovery.public.encrypt(message)) == message


def test_the_attack_works_on_another_modulus():
    """
    Nothing about the attack is specific to 3233. A fresh key, a fresh
    ciphertext, and the same three steps recover it.
    """
    p, q, e = 997, 1009, 17
    public = PublicKey(n=p * q, e=e)
    secret = 424242
    ciphertext = public.encrypt(secret)

    recovery = recover(public.n, e, ciphertext)
    assert (recovery.p, recovery.q) == (p, q)
    assert recovery.message == secret
    assert recovery.verified
    assert recovery.private.d == recover_private_key(public, p, q).d


def test_timings_are_recorded_for_every_algorithm():
    """A preview of Part IV: one measurement per algorithm, all positive."""
    recovery = recover()
    assert set(recovery.seconds) == set(ALGORITHM_ORDER)
    assert all(seconds > 0 for seconds in recovery.seconds.values())


def test_the_script_succeeds_on_the_default_values(capsys):
    assert main([]) == 0
    printed = capsys.readouterr().out
    assert "(n, d) = (3233, 2753)" in printed
    assert "m = c^d mod n = 2790^2753 mod 3233 = 65" in printed
    assert printed.rstrip().endswith("OK")


def test_the_script_accepts_other_values(capsys):
    assert main(["--n", "1005973", "--e", "17", "--c", "12345"]) == 0
    assert "997 * 1009" in capsys.readouterr().out


def test_the_script_fails_cleanly_on_a_prime_modulus(capsys):
    """
    A prime modulus has no factorization to find. The script must say
    so and return a non-zero status, not raise a traceback at the user.
    """
    assert main(["--n", "7919", "--e", "17", "--c", "42"]) == 1
    assert "the attack failed" in capsys.readouterr().out


def test_the_script_fails_cleanly_on_an_out_of_range_ciphertext(capsys):
    assert main(["--n", "3233", "--e", str(DEFAULT_E), "--c", "99999"]) == 1
    assert "invalid input" in capsys.readouterr().out


def test_the_defaults_are_the_assignment_values():
    """Running the script with no arguments must attack Exercise 4."""
    assert (DEFAULT_N, DEFAULT_E, DEFAULT_C) == (3233, 17, 2790)
