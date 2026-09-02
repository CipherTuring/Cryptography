"""
Key schedule de DES: genera las 16 subllaves de 48 bits a partir de una
llave de 64 bits (8 bytes, incluyendo bits de paridad).
"""

from .permutation import permute, rotate_left
from .tables import PC1, PC2, SHIFTS


def des_key_schedule(key: bytes) -> list[int]:
    """
    A partir de una llave de 8 bytes (64 bits, con bits de paridad
    incluidos), genera las 16 subllaves de 48 bits k1..k16 como enteros.
    """
    if len(key) != 8:
        raise ValueError(f"La llave DES debe tener 8 bytes, se recibieron {len(key)}")

    key_int = int.from_bytes(key, "big")
    key56 = permute(key_int, PC1, 64)  # 64 -> 56 (descarta paridad)

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
    Verifica que cada byte de la llave tenga paridad impar (el bit menos
    significativo de cada byte es el bit de paridad DES estándar).
    Devuelve True si los 8 bytes cumplen paridad impar.
    """
    if len(key) != 8:
        raise ValueError(f"La llave DES debe tener 8 bytes, se recibieron {len(key)}")

    return all(bin(byte).count("1") % 2 == 1 for byte in key)
