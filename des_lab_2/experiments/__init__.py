"""
experiments: the Part I experiments (modes of operation).

Every module exposes `run()` and is runnable with `python -m`. The results
are written to `results/` as `.txt` (to be quoted in the report) and
`.json` (raw data).

- `exp_ecb_vs_cbc`        — Exercise 4: repeated blocks in ECB versus CBC.
- `exp_iv_effect`         — Exercise 5: two different IVs over the same (K, P).
- `exp_error_propagation` — Exercise 6: one flipped bit of the ciphertext.

The submodules are loaded lazily (PEP 562) so that running them with
`python -m experiments.<name>` does not trigger the runpy RuntimeWarning.
"""

import importlib

__all__ = ["exp_ecb_vs_cbc", "exp_iv_effect", "exp_error_propagation", "run_all"]


def __getattr__(name: str):
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f".{name}", __name__)
    globals()[name] = module
    return module


def __dir__() -> list[str]:
    return sorted(__all__)
