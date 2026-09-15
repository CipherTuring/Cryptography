"""
aeslib: educational from-scratch implementation of AES (FIPS PUB 197),
without external cryptographic libraries.

Exercise 1 of the laboratory. The package is built in layers, each one
resting on the previous: finite-field arithmetic, the S-box derived from
it, the state and its round transformations, the key schedule, and
finally the block cipher and its public interface.

This module is the public facade: it re-exports the names that callers
are expected to use and grows as each layer is added.
"""

__all__: list[str] = []

__version__ = "1.0.0"
