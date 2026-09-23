"""
Part I of the laboratory: factorization of small RSA moduli.

The package is split into the arithmetic the algorithms stand on
(`arith`), the result and budget types they share (`result`), one module
per algorithm, and the registry that makes them interchangeable:

    trial_division   Exercise 1
    fermat           Exercise 2
    pollard_rho      Exercise 3
    api              ALGORITHMS, factor(n, algorithm)

Nothing here factors `n` by calling a library that already knows how.
"""

from .api import ALGORITHM_ORDER, ALGORITHMS, DISPLAY_NAMES, display_name, factor
from .arith import egcd, gcd, is_perfect_square, isqrt, modinv
from .fermat import fermat
from .pollard_rho import pollard_rho
from .result import (
    Budget,
    FactorizationError,
    FactorizationTimeout,
    FactorResult,
    NotFactorable,
)
from .trial_division import trial_division

__all__ = [
    # arithmetic
    "gcd",
    "egcd",
    "modinv",
    "isqrt",
    "is_perfect_square",
    # shared types
    "Budget",
    "FactorResult",
    "FactorizationError",
    "FactorizationTimeout",
    "NotFactorable",
    # algorithms
    "trial_division",
    "fermat",
    "pollard_rho",
    # registry
    "factor",
    "ALGORITHMS",
    "ALGORITHM_ORDER",
    "DISPLAY_NAMES",
    "display_name",
]
