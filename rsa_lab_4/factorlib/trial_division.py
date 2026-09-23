"""
Exercise 1: Trial Division.

The direct attack. Test every candidate divisor in turn, from the
smallest upwards, and stop at sqrt(n): if n had no divisor at or below
its square root, then both of its factors would be larger than sqrt(n)
and their product would exceed n. So a modulus that survives the search
up to sqrt(n) is prime.

Two candidates are tested per unit of progress rather than one: 2 is
handled separately and the loop then walks the odd numbers only, as the
assignment asks. Every even number above 2 is a multiple of 2, which has
already been ruled out, so testing it cannot find anything new.

Cost is what matters for Part IV. The loop runs up to sqrt(n)/2 times,
and sqrt(n) = 2^(b/2) for a modulus of b bits, so each extra bit of n
multiplies the work by about 1.41 and every two extra bits double it.
That is exponential in the size of the key, which is why this is
hopeless against real RSA and instructive against a 48-bit toy.
"""

from .arith import isqrt
from .result import Budget, FactorResult, NotFactorable

__all__ = ["NAME", "trial_division"]

NAME = "trial-division"


def trial_division(n: int, *, budget: Budget | None = None) -> FactorResult:
    """
    Factor `n` by testing candidate divisors up to `isqrt(n)`.

    `iterations` counts the candidates actually tested, so it is the
    honest measure of the work done and can be compared against the
    sqrt(n)/2 the analysis predicts.

    Raises `NotFactorable` if `n` is prime or below 4, and
    `FactorizationTimeout` if a budget is given and runs out.
    """
    if n < 4:
        raise NotFactorable(f"{n} has no non-trivial factorization")

    if budget is not None:
        budget.start()

    # 2 is the only even prime, so it is tested once and then the whole
    # even half of the search space can be skipped.
    if n % 2 == 0:
        return FactorResult.create(n, 2, iterations=1, algorithm=NAME)

    limit = isqrt(n)
    iterations = 1
    candidate = 3
    while candidate <= limit:
        iterations += 1
        if budget is not None:
            budget.tick(iterations)
        if n % candidate == 0:
            return FactorResult.create(n, candidate, iterations, algorithm=NAME)
        candidate += 2

    raise NotFactorable(f"{n} is prime: no divisor at or below {limit}")
