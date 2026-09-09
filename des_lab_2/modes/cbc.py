"""
CBC mode (Cipher Block Chaining) on top of the Laboratory 1 block DES.

Encryption:   C_0 = IV,   C_i = E_K(P_i XOR C_{i-1})
Decryption:   P_i = D_K(C_i) XOR C_{i-1}

Chaining makes every ciphertext block depend on all the preceding
blocks, so repeated plaintext blocks no longer produce repeated
ciphertext blocks.
"""

import os

from deslib import des_decrypt_block, des_encrypt_block

from .blocks import BLOCK_SIZE, split_blocks, xor_bytes
from .padding import pkcs7_pad, pkcs7_unpad

__all__ = [
    "des_cbc_encrypt",
    "des_cbc_decrypt",
    "des_cbc_encrypt_blocks",
    "des_cbc_decrypt_blocks",
    "random_iv",
]


def random_iv() -> bytes:
    """Generate a cryptographically random 8-byte IV."""
    return os.urandom(BLOCK_SIZE)


def _validate_iv(iv: bytes) -> bytes:
    if not isinstance(iv, (bytes, bytearray)):
        raise TypeError(f"el IV debe ser bytes, se recibió {type(iv).__name__}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(
            f"el IV debe tener exactamente {BLOCK_SIZE} bytes, se recibieron {len(iv)}"
        )
    return bytes(iv)


def des_cbc_encrypt_blocks(key: bytes, data: bytes, iv: bytes) -> bytes:
    """Raw CBC, without padding: `data` must be a multiple of 8 bytes."""
    previous = _validate_iv(iv)
    out = []
    for block in split_blocks(data):
        previous = des_encrypt_block(key, xor_bytes(block, previous))
        out.append(previous)
    return b"".join(out)


def des_cbc_decrypt_blocks(key: bytes, data: bytes, iv: bytes) -> bytes:
    """
    Raw CBC, without stripping padding: `data` must be a multiple of 8 bytes.

    Used in the error-propagation experiment, where flipping one bit of
    the ciphertext destroys the padding of the last block.
    """
    previous = _validate_iv(iv)
    out = []
    for block in split_blocks(data):
        out.append(xor_bytes(des_decrypt_block(key, block), previous))
        previous = block
    return b"".join(out)


def des_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """
    Encrypt a message of arbitrary length in CBC mode.

    PKCS#7 padding is applied automatically. The IV must be 8 bytes long;
    it is not prepended to the output, the caller must transmit it
    separately.
    """
    return des_cbc_encrypt_blocks(key, pkcs7_pad(plaintext, BLOCK_SIZE), iv)


def des_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """
    Decrypt a CBC message and validate/strip the PKCS#7 padding.

    Raises `ValueError` if the ciphertext length is not a positive
    multiple of 8 bytes or if the IV is not 8 bytes long, and
    `PaddingError` if the resulting padding is invalid.
    """
    if len(ciphertext) == 0:
        raise ValueError("el criptograma CBC no puede estar vacío")
    return pkcs7_unpad(des_cbc_decrypt_blocks(key, ciphertext, iv), BLOCK_SIZE)
