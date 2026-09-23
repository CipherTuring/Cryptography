"""
Part II of the laboratory: RSA key recovery.

Separated from `factorlib` because the assignment asks for it: the
factorization is the attack, and this is what the attack buys. Nothing
here knows how to factor anything.
"""

from .keys import (
    PrivateKey,
    PublicKey,
    decrypt,
    encrypt,
    private_exponent,
    recover_private_key,
    totient,
)

__all__ = [
    "PublicKey",
    "PrivateKey",
    "totient",
    "private_exponent",
    "encrypt",
    "decrypt",
    "recover_private_key",
]
