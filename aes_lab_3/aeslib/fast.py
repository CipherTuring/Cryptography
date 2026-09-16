"""
Table-driven backend, used for the performance evaluation.

The reference implementation in `cipher` follows FIPS-197 one
transformation at a time, which makes it readable but far too slow for
the benchmark: measured on this project it reaches about 0.018 MB/s, so
a single 100 MB run of Exercise 3 would take roughly an hour and a half.

This module computes the same function about 45 times faster, around
0.8 MB/s for AES-128, by folding SubBytes, ShiftRows and MixColumns of a
full round into four table lookups and three XORs per column. The tables
are not pasted in: they are built at import time from `sbox` and
`gf.mul`, so the fast path and the reference path share the same source
of truth. `test_backends` then requires the two to agree byte for byte.

Two observations make this possible:

- A round of AES acts on a column as a linear combination of four
  substituted bytes, one taken from each row. Precomputing that
  combination for all 256 byte values gives T0..T3, and the ShiftRows
  displacement turns into a change of which column each byte is read
  from, costing nothing at run time.
- Decryption uses the equivalent inverse cipher of FIPS-197 section
  5.3.5. The straightforward inverse cipher alternates AddRoundKey and
  InvMixColumns in an order that cannot be folded into tables; applying
  InvMixColumns to the intermediate round keys instead restores the same
  loop shape as encryption, at the cost of transforming the key schedule
  once per call.

The state is held as four 32-bit words, one per column, most significant
byte first, matching the column-major layout of `state`.
"""

import struct

from .gf import mul
from .sbox import INV_SBOX, SBOX
from .state import BLOCK_SIZE, bytes_to_state, state_to_bytes
from .transforms import (
    INV_MIX_COLUMNS_MATRIX,
    MIX_COLUMNS_MATRIX,
    inv_mix_columns,
)

__all__ = [
    "T0",
    "T1",
    "T2",
    "T3",
    "TD0",
    "TD1",
    "TD2",
    "TD3",
    "encrypt_block",
    "decrypt_block",
    "encrypt_buffer",
    "decrypt_buffer",
]

_MASK = 0xFFFFFFFF
_BLOCK = struct.Struct(">4I")


def _build_tables(substitution, matrix):
    """
    One lookup table per input byte of a column.

    Table j holds the contribution of the j-th input byte to all four
    output bytes, so it is built from *column* j of the MixColumns
    matrix, not from row j. Writing e = M . a out by hand,

        e0 = m00.a0 ^ m01.a1 ^ m02.a2 ^ m03.a3
        e1 = m10.a0 ^ m11.a1 ^ m12.a2 ^ m13.a3
        ...

    the a0 terms that T0 has to supply are (m00, m10, m20, m30): the
    first column read downwards. The matrices are taken from
    `transforms`, so the tables cannot drift from the reference
    implementation.
    """
    tables = []
    for column in range(4):
        coefficients = tuple(matrix[row][column] for row in range(4))
        table = []
        for value in range(256):
            substituted = substitution[value]
            table.append(
                (mul(coefficients[0], substituted) << 24)
                | (mul(coefficients[1], substituted) << 16)
                | (mul(coefficients[2], substituted) << 8)
                | mul(coefficients[3], substituted)
            )
        tables.append(tuple(table))
    return tables


# Encryption tables, from the columns of the MixColumns matrix.
T0, T1, T2, T3 = _build_tables(SBOX, MIX_COLUMNS_MATRIX)

# Decryption tables, from the columns of the InvMixColumns matrix.
TD0, TD1, TD2, TD3 = _build_tables(INV_SBOX, INV_MIX_COLUMNS_MATRIX)


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


def _to_words(keys: list[bytes]) -> list[int]:
    """Flatten the round keys into 32-bit words, one per column."""
    return [
        int.from_bytes(key[offset : offset + 4], "big")
        for key in keys
        for offset in range(0, BLOCK_SIZE, 4)
    ]


def _equivalent_decryption_keys(keys: list[bytes]) -> list[bytes]:
    """
    The round keys of the equivalent inverse cipher.

    The schedule is reversed, and InvMixColumns is applied to every round
    key except the first and the last, which are used by an AddRoundKey
    with no MixColumns beside it. `inv_mix_columns` is reused from
    `transforms` so the transformation is the one already tested.
    """
    rounds = len(keys) - 1
    result = [keys[rounds]]
    for index in range(rounds - 1, 0, -1):
        state = bytes_to_state(keys[index])
        inv_mix_columns(state)
        result.append(state_to_bytes(state))
    result.append(keys[0])
    return result


def encrypt_buffer(data: bytes, keys: list[bytes]) -> bytes:
    """
    Encrypt every block of `data` with the table-driven round function.

    The key schedule is converted to words once per call rather than
    once per block, so what the benchmark measures is the core.
    """
    _check_buffer(data)
    rounds = len(keys) - 1
    rk = _to_words(keys)

    # Local names: global and attribute lookups dominate the inner loop.
    t0, t1, t2, t3, sbox = T0, T1, T2, T3, SBOX
    unpack_from = _BLOCK.unpack_from
    pack_into = _BLOCK.pack_into
    mask = _MASK
    last = 4 * rounds

    out = bytearray(len(data))
    for offset in range(0, len(data), BLOCK_SIZE):
        s0, s1, s2, s3 = unpack_from(data, offset)
        s0 ^= rk[0]
        s1 ^= rk[1]
        s2 ^= rk[2]
        s3 ^= rk[3]

        index = 4
        for _ in range(rounds - 1):
            # Each column takes one byte from each row, read from the
            # column ShiftRows would have moved that byte to.
            a0 = (
                t0[s0 >> 24]
                ^ t1[(s1 >> 16) & 0xFF]
                ^ t2[(s2 >> 8) & 0xFF]
                ^ t3[s3 & 0xFF]
                ^ rk[index]
            )
            a1 = (
                t0[s1 >> 24]
                ^ t1[(s2 >> 16) & 0xFF]
                ^ t2[(s3 >> 8) & 0xFF]
                ^ t3[s0 & 0xFF]
                ^ rk[index + 1]
            )
            a2 = (
                t0[s2 >> 24]
                ^ t1[(s3 >> 16) & 0xFF]
                ^ t2[(s0 >> 8) & 0xFF]
                ^ t3[s1 & 0xFF]
                ^ rk[index + 2]
            )
            a3 = (
                t0[s3 >> 24]
                ^ t1[(s0 >> 16) & 0xFF]
                ^ t2[(s1 >> 8) & 0xFF]
                ^ t3[s2 & 0xFF]
                ^ rk[index + 3]
            )
            s0, s1, s2, s3 = a0 & mask, a1 & mask, a2 & mask, a3 & mask
            index += 4

        # Final round: no MixColumns, so the S-box is applied directly.
        pack_into(
            out,
            offset,
            (
                (sbox[s0 >> 24] << 24)
                | (sbox[(s1 >> 16) & 0xFF] << 16)
                | (sbox[(s2 >> 8) & 0xFF] << 8)
                | sbox[s3 & 0xFF]
            )
            ^ rk[last],
            (
                (sbox[s1 >> 24] << 24)
                | (sbox[(s2 >> 16) & 0xFF] << 16)
                | (sbox[(s3 >> 8) & 0xFF] << 8)
                | sbox[s0 & 0xFF]
            )
            ^ rk[last + 1],
            (
                (sbox[s2 >> 24] << 24)
                | (sbox[(s3 >> 16) & 0xFF] << 16)
                | (sbox[(s0 >> 8) & 0xFF] << 8)
                | sbox[s1 & 0xFF]
            )
            ^ rk[last + 2],
            (
                (sbox[s3 >> 24] << 24)
                | (sbox[(s0 >> 16) & 0xFF] << 16)
                | (sbox[(s1 >> 8) & 0xFF] << 8)
                | sbox[s2 & 0xFF]
            )
            ^ rk[last + 3],
        )
    return bytes(out)


def decrypt_buffer(data: bytes, keys: list[bytes]) -> bytes:
    """
    Decrypt every block of `data` with the equivalent inverse cipher.

    The loop mirrors `encrypt_buffer`; only the tables and the direction
    the columns are read in change, because InvShiftRows rotates the rows
    the other way.
    """
    _check_buffer(data)
    rounds = len(keys) - 1
    rk = _to_words(_equivalent_decryption_keys(keys))

    td0, td1, td2, td3, inv_sbox = TD0, TD1, TD2, TD3, INV_SBOX
    unpack_from = _BLOCK.unpack_from
    pack_into = _BLOCK.pack_into
    mask = _MASK
    last = 4 * rounds

    out = bytearray(len(data))
    for offset in range(0, len(data), BLOCK_SIZE):
        s0, s1, s2, s3 = unpack_from(data, offset)
        s0 ^= rk[0]
        s1 ^= rk[1]
        s2 ^= rk[2]
        s3 ^= rk[3]

        index = 4
        for _ in range(rounds - 1):
            a0 = (
                td0[s0 >> 24]
                ^ td1[(s3 >> 16) & 0xFF]
                ^ td2[(s2 >> 8) & 0xFF]
                ^ td3[s1 & 0xFF]
                ^ rk[index]
            )
            a1 = (
                td0[s1 >> 24]
                ^ td1[(s0 >> 16) & 0xFF]
                ^ td2[(s3 >> 8) & 0xFF]
                ^ td3[s2 & 0xFF]
                ^ rk[index + 1]
            )
            a2 = (
                td0[s2 >> 24]
                ^ td1[(s1 >> 16) & 0xFF]
                ^ td2[(s0 >> 8) & 0xFF]
                ^ td3[s3 & 0xFF]
                ^ rk[index + 2]
            )
            a3 = (
                td0[s3 >> 24]
                ^ td1[(s2 >> 16) & 0xFF]
                ^ td2[(s1 >> 8) & 0xFF]
                ^ td3[s0 & 0xFF]
                ^ rk[index + 3]
            )
            s0, s1, s2, s3 = a0 & mask, a1 & mask, a2 & mask, a3 & mask
            index += 4

        pack_into(
            out,
            offset,
            (
                (inv_sbox[s0 >> 24] << 24)
                | (inv_sbox[(s3 >> 16) & 0xFF] << 16)
                | (inv_sbox[(s2 >> 8) & 0xFF] << 8)
                | inv_sbox[s1 & 0xFF]
            )
            ^ rk[last],
            (
                (inv_sbox[s1 >> 24] << 24)
                | (inv_sbox[(s0 >> 16) & 0xFF] << 16)
                | (inv_sbox[(s3 >> 8) & 0xFF] << 8)
                | inv_sbox[s2 & 0xFF]
            )
            ^ rk[last + 1],
            (
                (inv_sbox[s2 >> 24] << 24)
                | (inv_sbox[(s1 >> 16) & 0xFF] << 16)
                | (inv_sbox[(s0 >> 8) & 0xFF] << 8)
                | inv_sbox[s3 & 0xFF]
            )
            ^ rk[last + 2],
            (
                (inv_sbox[s3 >> 24] << 24)
                | (inv_sbox[(s2 >> 16) & 0xFF] << 16)
                | (inv_sbox[(s1 >> 8) & 0xFF] << 8)
                | inv_sbox[s0 & 0xFF]
            )
            ^ rk[last + 3],
        )
    return bytes(out)


def encrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    """Encrypt one block. Present so the backend matches `cipher`."""
    _check_block(block)
    return encrypt_buffer(block, keys)


def decrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    """Decrypt one block. Present so the backend matches `cipher`."""
    _check_block(block)
    return decrypt_buffer(block, keys)
