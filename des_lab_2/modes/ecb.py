"""
ECB mode (Electronic Codebook) on top of the Laboratory 1 block DES.

    C_i = E_K(P_i)        P_i = D_K(C_i)

Every block is encrypted independently: equal plaintext blocks produce
equal ciphertext blocks under the same key, which leaks the structure of
the message (see `experiments/exp_ecb_vs_cbc.py`).
"""

from deslib import des_decrypt_block, des_encrypt_block

from .blocks import BLOCK_SIZE, split_blocks
from .padding import pkcs7_pad, pkcs7_unpad

__all__ = [
    "des_ecb_encrypt",
    "des_ecb_decrypt",
    "des_ecb_encrypt_blocks",
    "des_ecb_decrypt_blocks",
]


def des_ecb_encrypt_blocks(key: bytes, data: bytes) -> bytes:
    """
    Raw ECB, without padding: `data` must be a multiple of 8 bytes.

    Used in the error-propagation experiments, where the decrypted text
    is not required to carry valid PKCS#7 padding.
    """
    return b"".join(des_encrypt_block(key, block) for block in split_blocks(data))


def des_ecb_decrypt_blocks(key: bytes, data: bytes) -> bytes:
    """Raw ECB, without stripping padding: `data` must be a multiple of 8 bytes."""
    return b"".join(des_decrypt_block(key, block) for block in split_blocks(data))


def des_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt a message of arbitrary length in ECB mode.

    PKCS#7 padding is applied automatically, so the output is always at
    least 8 bytes longer than an exact multiple of the block.
    """
    return des_ecb_encrypt_blocks(key, pkcs7_pad(plaintext, BLOCK_SIZE))


def des_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt an ECB message and validate/strip the PKCS#7 padding.

    Raises `ValueError` if the ciphertext length is not a positive
    multiple of 8 bytes, and `PaddingError` if the resulting padding is
    invalid.
    """
    if len(ciphertext) == 0:
        raise ValueError("el criptograma ECB no puede estar vacío")
    return pkcs7_unpad(des_ecb_decrypt_blocks(key, ciphertext), BLOCK_SIZE)
