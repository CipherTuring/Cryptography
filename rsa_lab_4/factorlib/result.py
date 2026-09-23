"""
The shape every factorization algorithm returns, and the time budget
that stops the ones that cannot finish.

Trial Division, Fermat and Pollard's Rho have nothing in common
internally, but they all answer the same question and they are all
compared against each other in Part IV. Giving them one return type and
one way of giving up is what lets the registry, the benchmark and the
shared contract test treat them as interchangeable.
"""

import time
from dataclasses import dataclass, field

__all__ = [
    "FactorizationError",
    "FactorizationTimeout",
    "NotFactorable",
    "Budget",
    "FactorResult",
]


class FactorizationError(Exception):
    """Base class for every failure raised by an algorithm."""


class FactorizationTimeout(FactorizationError):
    """The time budget ran out before a factor was found."""


class NotFactorable(FactorizationError):
    """
    The input is outside what the algorithm can answer for.

    Raised for `n < 4` and for prime `n` (no non-trivial factor exists),
    and by Pollard's Rho for even `n`, where the sequence it relies on
    degenerates. It means "wrong question", not "gave up": a timeout is
    a different exception on purpose, because the benchmark reports the
    two differently.
    """


@dataclass(frozen=True, slots=True)
class FactorResult:
    """
    A non-trivial factorization `n = p * q`, and what it cost to find.

    `p <= q` always. The assignment lists the expected factors of 3233
    as p = 61, q = 53, which is the same pair in the other order; the
    naming is arbitrary since n = pq either way, and fixing an order
    here is what lets the three algorithms be compared for equality
    without caring which one happened to find which factor first.

    `iterations` is the number of times the algorithm went round its
    main loop. It is reported next to the timings because it is a
    property of the algorithm and the input alone, while a time is also
    a property of this particular machine on this particular day.
    Exercise 7 asks for exactly this count.
    """

    n: int
    p: int
    q: int
    iterations: int
    algorithm: str

    def __post_init__(self) -> None:
        if self.p * self.q != self.n:
            raise ValueError(
                f"{self.algorithm} returned {self.p} * {self.q} "
                f"= {self.p * self.q}, which is not {self.n}"
            )
        if self.p <= 1 or self.q <= 1:
            raise ValueError(
                f"{self.algorithm} returned the trivial factorization "
                f"{self.p} * {self.q} of {self.n}"
            )
        if self.p > self.q:
            raise ValueError(
                f"{self.algorithm} returned p = {self.p} > q = {self.q}; "
                "build the result with FactorResult.create to order them"
            )

    @classmethod
    def create(
        cls, n: int, factor: int, iterations: int, algorithm: str
    ) -> "FactorResult":
        """
        Build a result from one factor, deriving the other by division.

        Every algorithm finds a single divisor and gets the cofactor for
        free as `n // factor`; doing the division here means none of them
        has to remember to order the pair, and the invariants above are
        checked once, in one place.
        """
        other = n // factor
        low, high = (factor, other) if factor <= other else (other, factor)
        return cls(n=n, p=low, q=high, iterations=iterations, algorithm=algorithm)


@dataclass(slots=True)
class Budget:
    """
    A wall-clock limit an algorithm checks while it runs.

    Part IV compares algorithms across bit sizes at which some of them
    cannot possibly finish: Trial Division on an 80-bit modulus would
    need to try roughly 2^40 candidates. The benchmark still has to
    report that row, so the algorithms have to be able to give up.

    The deadline is checked inside the loop rather than enforced from
    outside because the alternatives do not fit: `signal.alarm` does not
    exist on Windows, and a worker thread cannot be interrupted while it
    is inside a long integer operation. Checking costs one comparison
    every `check_every` iterations, which is far below the measurement
    noise of the benchmark.

    A budget is stateful and single-use per run; `start()` resets it, and
    the algorithms call it before entering their loop, so one instance
    can be reused across the repetitions of an experiment.
    """

    seconds: float
    check_every: int = 4096
    _deadline: float | None = field(default=None, init=False, repr=False)

    def start(self) -> None:
        """Begin the countdown. Called once, before the main loop."""
        self._deadline = time.perf_counter() + self.seconds

    def tick(self, iterations: int) -> None:
        """
        Check the clock, cheaply, from inside the loop.

        Only every `check_every` iterations actually reads the clock:
        `perf_counter()` is not free, and in Pollard's Rho the loop body
        it guards is a handful of arithmetic operations.
        """
        if self._deadline is None:
            self.start()
            return
        if iterations % self.check_every:
            return
        if time.perf_counter() > self._deadline:
            raise FactorizationTimeout(
                f"budget of {self.seconds:g} s exhausted after "
                f"{iterations} iterations"
            )
