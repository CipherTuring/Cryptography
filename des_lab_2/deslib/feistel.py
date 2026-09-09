"""
Feistel F function and a full DES round.
"""

from .permutation import permute
from .sboxes import substitute
from .tables import E, P


def feistel_f(right: int, subkey: int) -> int:
    """
    Feistel F function: expansion E (32->48), XOR with the subkey,
    S-box substitution (48->32) and the final P permutation.
    """
    expanded = permute(right, E, 32)      # 32 -> 48
    mixed = expanded ^ subkey             # XOR with the 48-bit subkey
    substituted = substitute(mixed)       # 48 -> 32 via S-boxes
    return permute(substituted, P, 32)    # P permutation


def des_round(left: int, right: int, subkey: int) -> tuple[int, int]:
    """A single DES Feistel round over the 32-bit halves (L, R)."""
    new_left = right
    new_right = left ^ feistel_f(right, subkey)
    return new_left, new_right
