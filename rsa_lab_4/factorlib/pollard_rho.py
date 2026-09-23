"""
Exercise 3: Pollard's Rho.

Neither of the other two methods uses anything about n beyond its size.
This one does. Walk a pseudo-random sequence

    x <- f(x) = x^2 + c  (mod n)

and watch it modulo the unknown factor p. The sequence mod p lives in a
set of only p elements, so by the birthday bound it repeats after about
sqrt(p) steps, long before the sequence mod n does. When two positions
collide mod p but not mod n, their difference is a multiple of p but not
of n, and so

    d = gcd(|x - y|, n)

is p itself. The gcd is what makes the method work: it reads off a
factor from a collision we cannot see directly, because we never know p
while we are looking for it.

Floyd's cycle detection provides the two positions without storing any
history: `x` advances one step per iteration and `y` two, so `y` is
always at twice the distance and the two must meet inside the cycle.

For a balanced RSA modulus the smaller factor is about sqrt(n), so the
cost is about n^(1/4) instead of Trial Division's n^(1/2) - the square
root of the square root. That is the reason it is the only one of the
three still standing at 80 bits in Part IV.

Two things can go wrong, and both are handled by restarting with a fresh
`c` and a fresh starting point:

- `d = n`: the two positions collided modulo every factor at once, so
  the run reveals nothing;
- the trajectory enters a short cycle and never collides usefully.
"""

import random

from .arith import gcd
from .result import Budget, FactorResult, NotFactorable

__all__ = ["NAME", "DEFAULT_SEED", "pollard_rho"]

NAME = "pollard-rho"

# The algorithm is randomised, but the laboratory has to be
# reproducible: the same modulus must give the same iteration count on
# every run, or the benchmark would report a different number each time.
# Pass an explicit `seed` to explore other trajectories.
DEFAULT_SEED = 20260922

MAX_RESTARTS = 24


def pollard_rho(
    n: int,
    *,
    budget: Budget | None = None,
    seed: int = DEFAULT_SEED,
    max_restarts: int = MAX_RESTARTS,
) -> FactorResult:
    """
    Factor `n` with the rho method and Floyd cycle detection.

    `iterations` counts the steps of the sequence, accumulated across
    restarts, so it reflects the total work and not just the work of the
    attempt that happened to succeed.

    Raises `NotFactorable` if `n` is below 4 or if every restart is
    exhausted, which is what happens on a prime: no collision can ever
    reveal a factor that does not exist. Raises `FactorizationTimeout`
    if a budget is given and runs out.
    """
    if n < 4:
        raise NotFactorable(f"{n} has no non-trivial factorization")

    if budget is not None:
        budget.start()

    # f(x) = x^2 + c is a poor generator modulo an even number: the
    # parity of the sequence collapses. Two is stripped first, as in
    # `fermat`, so that all three algorithms accept the same inputs.
    if n % 2 == 0:
        return FactorResult.create(n, 2, iterations=1, algorithm=NAME)

    rng = random.Random(seed)
    iterations = 0

    for _ in range(max_restarts):
        # c = 0 makes the sequence a plain squaring map and c = n - 2
        # degenerates as well, so both are kept out of the draw.
        c = rng.randrange(1, n - 2)
        x = y = rng.randrange(0, n)
        divisor = 1

        while divisor == 1:
            iterations += 1
            if budget is not None:
                budget.tick(iterations)

            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n  # the hare moves twice
            divisor = gcd(abs(x - y), n)

        if divisor != n:
            return FactorResult.create(n, divisor, iterations, algorithm=NAME)
        # divisor == n: this trajectory collided modulo n itself and
        # tells us nothing. Start again elsewhere.

    raise NotFactorable(
        f"{max_restarts} restarts of the rho method found no factor of {n}; "
        "it is prime, or this is a case the method does not handle"
    )
