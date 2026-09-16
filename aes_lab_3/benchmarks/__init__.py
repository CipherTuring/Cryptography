"""
benchmarks: performance evaluation of the AES core.

- `benchmark_aes`  -- Exercise 3: encryption and decryption time and
  throughput for AES-128, AES-192 and AES-256 over 1, 10 and 100 MB.
- `plot_results`   -- Exercise 4: the figures, drawn from the JSON the
  benchmark writes.
- `report`         -- shared helper that writes each result as a
  readable `.txt` next to its machine-readable `.json`.
- `sysinfo`        -- CPU model and core count, recorded with every run.

The first two are runnable with `python -m` and are loaded lazily
(PEP 562) to avoid the runpy RuntimeWarning.
"""

import importlib

__all__ = ["benchmark_aes", "plot_results", "report", "sysinfo"]


def __getattr__(name: str):
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f".{name}", __name__)
    globals()[name] = module
    return module


def __dir__() -> list[str]:
    return sorted(__all__)
