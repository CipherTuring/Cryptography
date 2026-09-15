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

from .gf import IRREDUCIBLE, add, inverse, mul, xtime
from .sbox import INV_SBOX, SBOX, inv_sub_byte, sub_byte

__all__ = [
    # gf
    "IRREDUCIBLE",
    "add",
    "xtime",
    "mul",
    "inverse",
    # sbox
    "SBOX",
    "INV_SBOX",
    "sub_byte",
    "inv_sub_byte",
]

__version__ = "1.0.0"
