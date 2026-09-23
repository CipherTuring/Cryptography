"""
The registry that lets the three algorithms be used interchangeably.

Everything downstream - the key recovery of Part II, the benchmark of
Part IV, the figures and the shared contract test - wants to say "run
all of them on this n and compare", not "call these three different
functions". They already return the same type and raise the same
exceptions, so one dictionary is enough to close the gap.

The order of `ALGORITHM_ORDER` is fixed and is the order used in every
table and every figure, including the assignment of colours. A series
must not change colour because a filter dropped one of the others.
"""

from collections.abc import Callable

from .fermat import NAME as FERMAT
from .fermat import fermat
from .pollard_rho import NAME as POLLARD_RHO
from .pollard_rho import pollard_rho
from .result import Budget, FactorResult
from .trial_division import NAME as TRIAL_DIVISION
from .trial_division import trial_division

__all__ = [
    "ALGORITHMS",
    "ALGORITHM_ORDER",
    "DISPLAY_NAMES",
    "display_name",
    "factor",
]

ALGORITHMS: dict[str, Callable[..., FactorResult]] = {
    TRIAL_DIVISION: trial_division,
    FERMAT: fermat,
    POLLARD_RHO: pollard_rho,
}

# Exercise order: the order of the assignment, and of every report.
ALGORITHM_ORDER: tuple[str, ...] = (TRIAL_DIVISION, FERMAT, POLLARD_RHO)

DISPLAY_NAMES: dict[str, str] = {
    TRIAL_DIVISION: "Trial Division",
    FERMAT: "Fermat",
    POLLARD_RHO: "Pollard's Rho",
}


def display_name(algorithm: str) -> str:
    """The human-readable label of an algorithm, for tables and axes."""
    return DISPLAY_NAMES.get(algorithm, algorithm)


def factor(
    n: int, algorithm: str = POLLARD_RHO, *, budget: Budget | None = None, **options
) -> FactorResult:
    """
    Factor `n` with the named algorithm.

    `options` is passed through untouched, which is how `pollard_rho`
    receives its `seed` without the other two having to accept one.
    """
    if algorithm not in ALGORITHMS:
        known = ", ".join(ALGORITHM_ORDER)
        raise KeyError(f"unknown algorithm {algorithm!r}; known ones are: {known}")
    return ALGORITHMS[algorithm](n, budget=budget, **options)
