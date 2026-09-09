"""
benchmarks: performance measurement of the exhaustive search.

- `benchmark_bruteforce` — Exercises 8, 9, 10 and 11 (times, throughput,
  speedup, efficiency and extrapolation to 2^56).
- `plot_results`         — Exercise 10: Workers vs Keys/s and
  Workers vs Speedup plots.
- `sysinfo`              — CPU model and number of cores.

The first two are runnable with `python -m` and are loaded lazily
(PEP 562) to avoid the runpy RuntimeWarning.
"""

import importlib

__all__ = ["benchmark_bruteforce", "plot_results", "sysinfo"]


def __getattr__(name: str):
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f".{name}", __name__)
    globals()[name] = module
    return module


def __dir__() -> list[str]:
    return sorted(__all__)
