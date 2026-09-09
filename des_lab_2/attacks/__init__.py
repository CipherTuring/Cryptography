"""
attacks: brute-force cryptanalysis of the Laboratory 1 DES.

- `keyspace`:        candidate -> 56 effective bits -> 64-bit DES key mapping.
- `brute_force`:     sequential exhaustive known-plaintext search.
- `parallel_attack`: the same search spread across several processes.

`brute_force` and `parallel_attack` are loaded lazily (PEP 562). Both are
runnable with `python -m`, and an eager import here would make `runpy`
find them already in `sys.modules` and emit a RuntimeWarning when running
them again as `__main__`.
"""

import importlib

from .keyspace import (
    EFFECTIVE_BITS,
    KeySpace,
    add_parity_bits,
    has_odd_parity,
    strip_parity_bits,
)

__all__ = [
    "EFFECTIVE_BITS",
    "KeySpace",
    "add_parity_bits",
    "strip_parity_bits",
    "has_odd_parity",
    "SearchResult",
    "brute_force_des",
    "make_challenge",
    "verify_key",
    "ParallelResult",
    "WorkerReport",
    "parallel_brute_force",
    "split_range",
]

# Public name -> submodule that defines it.
_LAZY = {
    "SearchResult": "brute_force",
    "brute_force_des": "brute_force",
    "make_challenge": "brute_force",
    "verify_key": "brute_force",
    "ParallelResult": "parallel_attack",
    "WorkerReport": "parallel_attack",
    "parallel_brute_force": "parallel_attack",
    "split_range": "parallel_attack",
}


def __getattr__(name: str):
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f".{module_name}", __name__)
    value = getattr(module, name)
    globals()[name] = value  # cache it for subsequent accesses
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
