"""
API pública de deslib.

Toda validación de longitudes de llave/bloque y las conversiones
bytes <-> entero viven aquí; el núcleo (`des_core`) permanece puro.
"""

from .des_core import des_block
from .key_schedule import des_check_parity, des_key_schedule

__all__ = [
    "des_encrypt_block",
    "des_decrypt_block",
    "des_key_schedule",
    "des_check_parity",
]


def _validate_8_bytes(data: bytes, name: str) -> None:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name} debe ser de tipo bytes, se recibió {type(data).__name__}")
    if len(data) != 8:
        raise ValueError(f"{name} debe tener exactamente 8 bytes, se recibieron {len(data)}")


def des_encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    """Cifra un único bloque de 8 bytes con una llave DES de 8 bytes."""
    _validate_8_bytes(key, "key")
    _validate_8_bytes(plaintext, "plaintext")

    subkeys = des_key_schedule(key)
    block = int.from_bytes(plaintext, "big")
    cipher = des_block(block, subkeys)
    return cipher.to_bytes(8, "big")


def des_decrypt_block(key: bytes, ciphertext: bytes) -> bytes:
    """Descifra un único bloque de 8 bytes con una llave DES de 8 bytes."""
    _validate_8_bytes(key, "key")
    _validate_8_bytes(ciphertext, "ciphertext")

    subkeys = des_key_schedule(key)
    block = int.from_bytes(ciphertext, "big")
    plain = des_block(block, subkeys[::-1])
    return plain.to_bytes(8, "big")
