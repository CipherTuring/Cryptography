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
from .state import BLOCK_SIZE, NB, bytes_to_state, format_state, state_to_bytes
from .transforms import (
    add_round_key,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    sub_bytes,
)

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
    # state
    "BLOCK_SIZE",
    "NB",
    "bytes_to_state",
    "state_to_bytes",
    "format_state",
    # transforms
    "sub_bytes",
    "inv_sub_bytes",
    "shift_rows",
    "inv_shift_rows",
    "mix_columns",
    "inv_mix_columns",
    "add_round_key",
]

__version__ = "1.0.0"
