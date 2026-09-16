"""
Equivalence between the reference core and the table-driven backend.

Exercise 2. The performance evaluation of Exercise 3 is run with the
fast backend, because the reference core would need about an hour and a
half for a single 100 MB pass. That is only legitimate if the two
compute exactly the same function, so this file is what licenses the
benchmark: for the three key sizes, in both directions, over buffers of
several blocks, `fast` must agree with `cipher` byte for byte.

The fast backend is also checked against the published vectors directly.
Agreeing with the reference implementation would not be enough on its
own if both happened to be wrong in the same way, and the two are not
fully independent: they share `gf`, `sbox` and the MixColumns matrices.
"""

import random

import pytest

from aeslib import cipher, fast
from aeslib.api import AES
from aeslib.key_schedule import round_keys
from aeslib.gf import mul
from aeslib.sbox import INV_SBOX, SBOX
from aeslib.state import BLOCK_SIZE
from aeslib.transforms import (
    INV_MIX_COLUMNS_MATRIX,
    MIX_COLUMNS_MATRIX,
)

from .vectors import (
    APPENDIX_C_PLAINTEXT,
    APPENDIX_C_VECTORS,
    SP800_38A_ECB_VECTORS,
    SP800_38A_PLAINTEXT,
)

_RANDOM = random.Random(20260916)

KEY_SIZES_IN_BYTES = [16, 24, 32]
BLOCK_COUNTS = [1, 2, 3, 7, 32]


def random_bytes(size: int) -> bytes:
    return bytes(_RANDOM.randrange(256) for _ in range(size))


# ---------------------------------------------------------------------------
# The tables are derived, not pasted
# ---------------------------------------------------------------------------


def check_tables(tables, substitution, matrix):
    """
    Every byte of every entry must be a MixColumns coefficient times a
    substituted value: table j, byte r, holds matrix[r][j] . sub(x).

    Note that the inverse matrix has no coefficient equal to 1, so the
    inverse S-box never appears unmultiplied in TD0..TD3; the tables can
    only be checked through the field multiplication.
    """
    for column, table in enumerate(tables):
        for value in range(256):
            entry = table[value]
            for row in range(4):
                byte = (entry >> (8 * (3 - row))) & 0xFF
                expected = mul(matrix[row][column], substitution[value])
                assert byte == expected, f"table {column}, byte {row}, input {value}"


def test_the_encryption_tables_are_built_from_the_sbox_and_the_matrix():
    """
    The tables are a re-encoding of the S-box and MixColumns, not an
    independent constant: this rebuilds them from `gf.mul`.
    """
    check_tables(
        (fast.T0, fast.T1, fast.T2, fast.T3), SBOX, MIX_COLUMNS_MATRIX
    )


def test_the_decryption_tables_are_built_from_the_inverse_sbox_and_matrix():
    check_tables(
        (fast.TD0, fast.TD1, fast.TD2, fast.TD3),
        INV_SBOX,
        INV_MIX_COLUMNS_MATRIX,
    )


@pytest.mark.parametrize(
    "table", ["T0", "T1", "T2", "T3", "TD0", "TD1", "TD2", "TD3"]
)
def test_every_table_has_one_entry_per_byte(table):
    entries = getattr(fast, table)
    assert len(entries) == 256
    assert all(0 <= entry <= 0xFFFFFFFF for entry in entries)


# ---------------------------------------------------------------------------
# The fast backend against the published vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key, expected", APPENDIX_C_VECTORS)
def test_fast_encryption_matches_fips_197_appendix_c(key, expected):
    assert fast.encrypt_block(APPENDIX_C_PLAINTEXT, round_keys(key)) == expected


@pytest.mark.parametrize("key, ciphertext", APPENDIX_C_VECTORS)
def test_fast_decryption_matches_fips_197_appendix_c(key, ciphertext):
    assert fast.decrypt_block(ciphertext, round_keys(key)) == APPENDIX_C_PLAINTEXT


@pytest.mark.parametrize("key, expected", SP800_38A_ECB_VECTORS)
def test_fast_encryption_matches_sp_800_38a(key, expected):
    assert fast.encrypt_buffer(SP800_38A_PLAINTEXT, round_keys(key)) == expected


@pytest.mark.parametrize("key, ciphertext", SP800_38A_ECB_VECTORS)
def test_fast_decryption_matches_sp_800_38a(key, ciphertext):
    assert fast.decrypt_buffer(ciphertext, round_keys(key)) == SP800_38A_PLAINTEXT


# ---------------------------------------------------------------------------
# The two backends agree
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
@pytest.mark.parametrize("blocks", BLOCK_COUNTS)
def test_the_backends_encrypt_identically(key_size, blocks):
    keys = round_keys(random_bytes(key_size))
    data = random_bytes(BLOCK_SIZE * blocks)
    assert fast.encrypt_buffer(data, keys) == cipher.encrypt_buffer(data, keys)


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
@pytest.mark.parametrize("blocks", BLOCK_COUNTS)
def test_the_backends_decrypt_identically(key_size, blocks):
    keys = round_keys(random_bytes(key_size))
    data = random_bytes(BLOCK_SIZE * blocks)
    assert fast.decrypt_buffer(data, keys) == cipher.decrypt_buffer(data, keys)


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_the_backends_agree_on_extreme_inputs(key_size):
    """All-zero and all-ones blocks, and an all-zero key."""
    for key in (bytes(key_size), bytes([0xFF]) * key_size):
        keys = round_keys(key)
        for data in (bytes(BLOCK_SIZE), bytes([0xFF]) * BLOCK_SIZE):
            assert fast.encrypt_buffer(data, keys) == cipher.encrypt_buffer(data, keys)
            assert fast.decrypt_buffer(data, keys) == cipher.decrypt_buffer(data, keys)


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_each_backend_decrypts_what_the_other_encrypted(key_size):
    """
    The strongest form of the equivalence: the two are interchangeable
    mid-operation, not merely equal on their own outputs.
    """
    keys = round_keys(random_bytes(key_size))
    plaintext = random_bytes(BLOCK_SIZE * 4)
    assert cipher.decrypt_buffer(fast.encrypt_buffer(plaintext, keys), keys) == plaintext
    assert fast.decrypt_buffer(cipher.encrypt_buffer(plaintext, keys), keys) == plaintext


# ---------------------------------------------------------------------------
# The equivalent inverse cipher key schedule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_the_decryption_schedule_reverses_the_round_keys(key_size):
    """
    First and last round keys are used unchanged; only the ones between
    them get InvMixColumns applied.
    """
    keys = round_keys(random_bytes(key_size))
    decryption_keys = fast._equivalent_decryption_keys(keys)
    assert len(decryption_keys) == len(keys)
    assert decryption_keys[0] == keys[-1]
    assert decryption_keys[-1] == keys[0]


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_the_intermediate_decryption_keys_are_transformed(key_size):
    keys = round_keys(random_bytes(key_size))
    decryption_keys = fast._equivalent_decryption_keys(keys)
    for index in range(1, len(keys) - 1):
        assert decryption_keys[index] != keys[len(keys) - 1 - index]


# ---------------------------------------------------------------------------
# Through the public interface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_the_aes_class_gives_the_same_result_with_either_backend(key_size):
    key = random_bytes(key_size)
    plaintext = random_bytes(BLOCK_SIZE * 4)
    reference = AES(key, backend="reference")
    accelerated = AES(key, backend="fast")
    assert accelerated.encrypt(plaintext) == reference.encrypt(plaintext)
    assert accelerated.decrypt(plaintext) == reference.decrypt(plaintext)


def test_the_fast_backend_is_selectable():
    aes = AES(bytes(16), backend="fast")
    assert aes.backend == "fast"
    assert "fast" in repr(aes)


@pytest.mark.parametrize("length", [1, 15, 17, 31])
def test_the_fast_backend_validates_its_arguments(length):
    keys = round_keys(bytes(16))
    with pytest.raises(ValueError):
        fast.encrypt_buffer(bytes(length), keys)
    with pytest.raises(ValueError):
        fast.decrypt_block(bytes(length), keys)
