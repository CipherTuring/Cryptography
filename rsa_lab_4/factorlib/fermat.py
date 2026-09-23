"""
Exercise 2: Fermat factorization.

Every odd number can be written as a difference of two squares:

    n = a^2 - b^2 = (a - b)(a + b),

and the two brackets are then a factorization. Rearranged, the search is
for an `a` such that `a^2 - n` is itself a perfect square. Since
`a = (p + q) / 2` and `b = (q - p) / 2`, the smallest possible `a` is
ceil(sqrt(n)), reached when p and q are as close together as they can
be, so the search starts there and walks upwards.

That is also the whole story of its performance, and the subject of
Part V. The number of iterations is

    a - ceil(sqrt(n)) = (p + q)/2 - sqrt(n),

which for p and q of similar size is close to |p - q|^2 / (8 sqrt(n)):
quadratic in the distance between the factors. Twin-like primes are
found on the first try; primes that differ by a few million turn the
method into something slower than Trial Division. The experiment in
`benchmarks/fermat_distance.py` measures exactly this.
"""

from .arith import is_perfect_square, isqrt
from .result import Budget, FactorResult, NotFactorable

__all__ = ["NAME", "fermat"]

NAME = "fermat"


def fermat(n: int, *, budget: Budget | None = None) -> FactorResult:
    """
    Factor `n` by writing it as a difference of two squares.

    `iterations` counts the values of `a` tried, which is the quantity
    Exercise 7 asks to report against |p - q|.

    Raises `NotFactorable` if `n` is prime or below 4, and
    `FactorizationTimeout` if a budget is given and runs out.
    """
    if n < 4:
        raise NotFactorable(f"{n} has no non-trivial factorization")

    if budget is not None:
        budget.start()

    # An even n is not a difference of two squares unless it is
    # divisible by 4, so the method does not apply to n = 2m with m odd.
    # Dividing out the factor 2 is one operation and is not the
    # algorithm; it is done so that all three share the same domain.
    if n % 2 == 0:
        return FactorResult.create(n, 2, iterations=1, algorithm=NAME)

    a = isqrt(n)
    if a * a < n:
        a += 1  # ceil(sqrt(n)): start at the smallest a with a^2 >= n

    iterations = 0
    while True:
        iterations += 1
        if budget is not None:
            budget.tick(iterations)

        difference = a * a - n
        if is_perfect_square(difference):
            b = isqrt(difference)
            smaller = a - b
            # a = (n+1)/2, b = (n-1)/2 always solves the equation and
            # gives n = 1 * n. Reaching it means nothing better exists.
            if smaller <= 1:
                raise NotFactorable(f"{n} is prime: only n = 1 * n solves it")
            return FactorResult.create(n, smaller, iterations, algorithm=NAME)

        a += 1
