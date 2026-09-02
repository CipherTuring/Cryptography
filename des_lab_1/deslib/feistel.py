"""
Función F de Feistel y una ronda completa de DES.
"""

from .permutation import permute
from .sboxes import substitute
from .tables import E, P


def feistel_f(right: int, subkey: int) -> int:
    """
    Función F de Feistel: expansión E (32->48), XOR con la subllave,
    sustitución por S-boxes (48->32) y permutación P final.
    """
    expanded = permute(right, E, 32)      # 32 -> 48
    mixed = expanded ^ subkey             # XOR con subllave de 48 bits
    substituted = substitute(mixed)       # 48 -> 32 vía S-boxes
    return permute(substituted, P, 32)    # permutación P


def des_round(left: int, right: int, subkey: int) -> tuple[int, int]:
    """Una ronda Feistel de DES sobre las mitades de 32 bits (L, R)."""
    new_left = right
    new_right = left ^ feistel_f(right, subkey)
    return new_left, new_right
