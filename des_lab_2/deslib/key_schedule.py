"""
DES key schedule: derives the 16 48-bit subkeys from a 64-bit key
(8 bytes, parity bits included).
"""

from .permutation import permute, rotate_left
from .tables import PC1, PC2, SHIFTS


def des_key_schedule(key: bytes) -> list[int]:
    """
    From an 8-byte key (64 bits, parity bits included), derive the 16
    48-bit subkeys k1..k16 as integers.
    """
    if len(key) != 8:
        raise ValueError(f"La llave DES debe tener 8 bytes, se recibieron {len(key)}")

    key_int = int.from_bytes(key, "big")
    key56 = permute(key_int, PC1, 64)  # 64 -> 56 (drops parity bits)

    C = (key56 >> 28) & 0xFFFFFFF
    D = key56 & 0xFFFFFFF

    subkeys = []
    for shift in SHIFTS:
        C = rotate_left(C, shift, 28)
        D = rotate_left(D, shift, 28)
        CD = (C << 28) | D
        subkeys.append(permute(CD, PC2, 56))
    return subkeys


def des_check_parity(key: bytes) -> bool:
    """
    Check that every key byte has odd parity (the least significant bit
    of each byte is the standard DES parity bit).
    Returns True if all 8 bytes satisfy odd parity.
    """
    if len(key) != 8:
        raise ValueError(f"La llave DES debe tener 8 bytes, se recibieron {len(key)}")

    return all(bin(byte).count("1") % 2 == 1 for byte in key)
