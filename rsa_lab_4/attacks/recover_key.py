"""
Exercise 4: recover an RSA private key and decrypt a ciphertext.

    python -m attacks.recover_key                  # the assignment's values
    python -m attacks.recover_key --n 1005973 --e 17 --c 12345

Given only what is public - the modulus n, the public exponent e and a
ciphertext c - factor n with all three algorithms, rebuild the private
key and read the message. The default values are the ones the
assignment supplies:

    n = 3233, e = 17, c = 2790,   with p = 61 and q = 53 for validation.

All three algorithms are run, not one. They are independent methods, so
agreement between them is the strongest evidence available here that the
factorization is right, and the timings printed alongside are a preview
of what Part IV measures properly.

The attack works because every step after the factorization is cheap.
That asymmetry is the answer to the last question of the analysis:
knowing n does not give phi(n), but knowing p and q does, and phi(n)
gives d.
"""

import argparse
import time
from dataclasses import dataclass

from console import use_utf8_stdout
from factorlib.api import ALGORITHM_ORDER, display_name, factor
from factorlib.result import Budget, FactorizationError, FactorResult
from rsalib.keys import PrivateKey, PublicKey, recover_private_key, totient

__all__ = ["Recovery", "recover", "main"]

# The values of Exercise 4.
DEFAULT_N = 3233
DEFAULT_E = 17
DEFAULT_C = 2790


@dataclass(frozen=True, slots=True)
class Recovery:
    """Everything the attack produced, for printing or for a test."""

    public: PublicKey
    private: PrivateKey
    p: int
    q: int
    phi: int
    ciphertext: int
    message: int
    verified: bool
    factorizations: dict[str, FactorResult]
    seconds: dict[str, float]

    @property
    def algorithms_agree(self) -> bool:
        pairs = {(result.p, result.q) for result in self.factorizations.values()}
        return len(pairs) == 1


def recover(
    n: int = DEFAULT_N,
    e: int = DEFAULT_E,
    c: int = DEFAULT_C,
    *,
    budget: Budget | None = None,
) -> Recovery:
    """
    Run the full attack and return its result.

    Kept separate from `main` so the tests can assert on the numbers
    without parsing printed output.
    """
    public = PublicKey(n=n, e=e)

    factorizations: dict[str, FactorResult] = {}
    seconds: dict[str, float] = {}
    for algorithm in ALGORITHM_ORDER:
        start = time.perf_counter()
        result = factor(n, algorithm, budget=budget)
        seconds[algorithm] = time.perf_counter() - start
        factorizations[algorithm] = result

    # Any of them would do; they are checked against each other below.
    reference = factorizations[ALGORITHM_ORDER[0]]
    p, q = reference.p, reference.q

    phi = totient(p, q)
    private = recover_private_key(public, p, q)
    message = private.decrypt(c)

    return Recovery(
        public=public,
        private=private,
        p=p,
        q=q,
        phi=phi,
        ciphertext=c,
        message=message,
        # The only check that matters: re-encrypting the recovered
        # plaintext has to reproduce the ciphertext we started from.
        verified=public.encrypt(message) == c,
        factorizations=factorizations,
        seconds=seconds,
    )


def report(recovery: Recovery) -> None:
    """Print the attack step by step, as the oral defense will ask for."""
    public = recovery.public
    n, e = public.n, public.e

    print("Exercise 4: recovering an RSA private key by factorization")
    print("=" * 58)
    print()
    print("Public information, all an attacker is given")
    print(f"  n = {n}")
    print(f"  e = {e}")
    print(f"  c = {recovery.ciphertext}")
    print()

    print("Step 1 - factor n with the three algorithms")
    for algorithm, result in recovery.factorizations.items():
        print(
            f"  {display_name(algorithm):<16}"
            f"p = {result.p}, q = {result.q}"
            f"   {result.iterations:>10,} iterations"
            f"   {recovery.seconds[algorithm]:.6f} s"
        )
    verdict = "agree" if recovery.algorithms_agree else "DISAGREE"
    print(f"  The three algorithms {verdict}: {n} = {recovery.p} * {recovery.q}")
    print()

    print("Step 2 - Euler's totient, which n alone does not reveal")
    print(
        f"  phi(n) = (p - 1)(q - 1) = {recovery.p - 1} * {recovery.q - 1}"
        f" = {recovery.phi}"
    )
    print()

    print("Step 3 - invert the public exponent")
    print(f"  d = e^-1 mod phi(n) = {e}^-1 mod {recovery.phi} = {recovery.private.d}")
    print(
        f"  check: e * d mod phi(n) = {e} * {recovery.private.d}"
        f" mod {recovery.phi} = {e * recovery.private.d % recovery.phi}"
    )
    print()

    print("Step 4 - the reconstructed private key")
    print(f"  (n, d) = ({recovery.private.n}, {recovery.private.d})")
    print()

    print("Step 5 - decrypt")
    print(
        f"  m = c^d mod n = {recovery.ciphertext}^{recovery.private.d}"
        f" mod {n} = {recovery.message}"
    )
    print()

    print("Step 6 - verify")
    encrypted = public.encrypt(recovery.message)
    mark = "OK" if recovery.verified else "FAILED"
    print(
        f"  m^e mod n = {recovery.message}^{e} mod {n} = {encrypted}"
        f"   (c = {recovery.ciphertext})   {mark}"
    )


def main(argv: list[str] | None = None) -> int:
    use_utf8_stdout()
    parser = argparse.ArgumentParser(
        prog="python -m attacks.recover_key",
        description="Factor an RSA modulus, rebuild the private key, decrypt.",
    )
    parser.add_argument("--n", type=int, default=DEFAULT_N, help="the modulus")
    parser.add_argument("--e", type=int, default=DEFAULT_E, help="public exponent")
    parser.add_argument("--c", type=int, default=DEFAULT_C, help="ciphertext")
    parser.add_argument(
        "--budget",
        type=float,
        default=None,
        help="seconds allowed per algorithm before giving up",
    )
    arguments = parser.parse_args(argv)

    budget = Budget(seconds=arguments.budget) if arguments.budget else None
    try:
        recovery = recover(arguments.n, arguments.e, arguments.c, budget=budget)
    except FactorizationError as error:
        print(f"the attack failed: {error}")
        return 1
    except ValueError as error:
        print(f"invalid input: {error}")
        return 1

    report(recovery)
    return 0 if recovery.verified and recovery.algorithms_agree else 1


if __name__ == "__main__":
    raise SystemExit(main())
