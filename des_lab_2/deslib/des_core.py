"""
DES block core: operates on a single 64-bit block.

This module contains only pure cryptographic operations (integers in,
integers out). It does not print, read files or read keyboard input;
that is the responsibility of code outside the core (see api.py and any
command-line script).
"""

from .feistel import des_round
from .permutation import permute
from .tables import FP, IP


def des_block(block: int, subkeys: list[int]) -> int:
    """
    Process a 64-bit block through the 16 Feistel rounds, using
    `subkeys` in the given order.

    To encrypt: pass subkeys = [k1, k2, ..., k16].
    To decrypt: pass subkeys = [k16, k15, ..., k1] (reversed list).

    Order: IP -> 16 rounds -> R16||L16 (final swap) -> IP^-1.
    """
    permuted = permute(block, IP, 64)
    L = (permuted >> 32) & 0xFFFFFFFF
    R = permuted & 0xFFFFFFFF

    for k in subkeys:
        L, R = des_round(L, R, k)

    # Final swap: after round 16 L and R are NOT swapped,
    # so the pre-output is R16 || L16.
    pre_output = (R << 32) | L
    return permute(pre_output, FP, 64)
