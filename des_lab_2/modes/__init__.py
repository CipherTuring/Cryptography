"""
modes: block cipher modes of operation built on top of the Lab 1 DES.

All block encryption and decryption comes from `deslib` (Laboratory 1);
only PKCS#7 padding and block chaining are implemented here.
"""

from .blocks import BLOCK_SIZE, split_blocks, xor_bytes
from .cbc import (
    des_cbc_decrypt,
    des_cbc_decrypt_blocks,
    des_cbc_encrypt,
    des_cbc_encrypt_blocks,
    random_iv,
)
from .ecb import (
    des_ecb_decrypt,
    des_ecb_decrypt_blocks,
    des_ecb_encrypt,
    des_ecb_encrypt_blocks,
)
from .padding import PaddingError, pkcs7_pad, pkcs7_unpad

__all__ = [
    "BLOCK_SIZE",
    "split_blocks",
    "xor_bytes",
    "PaddingError",
    "pkcs7_pad",
    "pkcs7_unpad",
    "des_ecb_encrypt",
    "des_ecb_decrypt",
    "des_ecb_encrypt_blocks",
    "des_ecb_decrypt_blocks",
    "des_cbc_encrypt",
    "des_cbc_decrypt",
    "des_cbc_encrypt_blocks",
    "des_cbc_decrypt_blocks",
    "random_iv",
]
