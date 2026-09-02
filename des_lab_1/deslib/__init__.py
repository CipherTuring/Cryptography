"""
deslib: implementación educativa de DES (FIPS PUB 46-3) desde cero,
sin librerías criptográficas externas.
"""

from .api import (
    des_check_parity,
    des_decrypt_block,
    des_encrypt_block,
    des_key_schedule,
)
from .des_core import des_block
from .feistel import des_round, feistel_f
from .permutation import permute, rotate_left
from .sboxes import sbox_lookup, substitute

__all__ = [
    "des_encrypt_block",
    "des_decrypt_block",
    "des_key_schedule",
    "des_check_parity",
    "des_block",
    "des_round",
    "feistel_f",
    "permute",
    "rotate_left",
    "sbox_lookup",
    "substitute",
]

__version__ = "1.0.0"
