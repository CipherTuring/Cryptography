"""
The AES block cipher: the reference implementation of Cipher and
InvCipher.

Exercise 1, "complete encryption and decryption". This module follows
FIPS-197 sections 5.1 and 5.3 literally, one named transformation per
step, so that the shape of a round can be read directly off the code.
It is the implementation the tests validate against the published
vectors, and the yardstick the fast backend in `fast` is checked against.

The structure of encryption is:

    AddRoundKey with round key 0
    Nr - 1 full rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey
    final round:        SubBytes, ShiftRows, AddRoundKey

The final round has no MixColumns. The reason is not efficiency: with it,
the last linear step could simply be undone by an attacker, since it
carries no key material after the final AddRoundKey. Leaving it out costs
nothing in security and makes decryption symmetric.

Decryption applies the inverse steps in the opposite order. Note that
InvCipher swaps the order of AddRoundKey and InvMixColumns inside the
loop, because InvMixColumns is linear and does not commute with the key
addition.

The buffer helpers apply the core to each 16-byte block independently.
That is raw ECB and is NOT a secure mode of operation: identical blocks
of plaintext produce identical blocks of ciphertext. They exist so the
benchmark can measure the cost of the core itself, as the assignment
asks.
"""

from .state import BLOCK_SIZE, bytes_to_state, state_to_bytes
from .transforms import (
    add_round_key,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    sub_bytes,
)

__all__ = [
    "encrypt_block",
    "decrypt_block",
    "encrypt_buffer",
    "decrypt_buffer",
]


def _check_block(block: bytes) -> None:
    if len(block) != BLOCK_SIZE:
        raise ValueError(
            f"a block must be exactly {BLOCK_SIZE} bytes, got {len(block)}"
        )


def _check_buffer(data: bytes) -> None:
    if len(data) % BLOCK_SIZE:
        raise ValueError(
            f"the data length must be a multiple of {BLOCK_SIZE} bytes, "
            f"got {len(data)}"
        )


def encrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    """
    Encrypt one 16-byte block with the given round keys.

    `keys` holds Nr + 1 round keys, so the number of rounds is implied by
    its length and the same code serves AES-128, AES-192 and AES-256.
    """
    _check_block(block)
    rounds = len(keys) - 1
    state = bytes_to_state(block)

    add_round_key(state, keys[0])

    for round_index in range(1, rounds):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, keys[round_index])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, keys[rounds])

    return state_to_bytes(state)


def decrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    """Decrypt one 16-byte block, undoing `encrypt_block` step by step."""
    _check_block(block)
    rounds = len(keys) - 1
    state = bytes_to_state(block)

    add_round_key(state, keys[rounds])

    for round_index in range(rounds - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, keys[round_index])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, keys[0])

    return state_to_bytes(state)


def encrypt_buffer(data: bytes, keys: list[bytes]) -> bytes:
    """Encrypt every block of `data` independently (raw ECB, not secure)."""
    _check_buffer(data)
    return b"".join(
        encrypt_block(data[offset : offset + BLOCK_SIZE], keys)
        for offset in range(0, len(data), BLOCK_SIZE)
    )


def decrypt_buffer(data: bytes, keys: list[bytes]) -> bytes:
    """Decrypt every block of `data` independently (raw ECB, not secure)."""
    _check_buffer(data)
    return b"".join(
        decrypt_block(data[offset : offset + BLOCK_SIZE], keys)
        for offset in range(0, len(data), BLOCK_SIZE)
    )
