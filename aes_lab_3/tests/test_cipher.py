"""
Tests for the complete encryption and decryption.

Exercise 2, the two central requirements: the recognised AES test
vectors and the round trip D_K(E_K(P)) = P.

The vectors come from two independent documents. FIPS-197 Appendix C
fixes one block per key size; NIST SP 800-38A Appendix F.1 fixes four
consecutive blocks per key size, which also exercises the buffer path.
Passing both means the cipher, the key schedule and every transformation
underneath agree with the standards for AES-128, AES-192 and AES-256.
"""

import random

import pytest

from aeslib.cipher import (
    decrypt_block,
    decrypt_buffer,
    encrypt_block,
    encrypt_buffer,
)
from aeslib.key_schedule import round_keys
from aeslib.state import BLOCK_SIZE

from .vectors import (
    APPENDIX_B_CIPHERTEXT,
    APPENDIX_B_KEY,
    APPENDIX_B_PLAINTEXT,
    APPENDIX_C_PLAINTEXT,
    APPENDIX_C_VECTORS,
    SP800_38A_ECB_VECTORS,
    SP800_38A_PLAINTEXT,
)

_RANDOM = random.Random(20260916)

KEY_SIZES_IN_BYTES = [16, 24, 32]


def random_bytes(size: int) -> bytes:
    return bytes(_RANDOM.randrange(256) for _ in range(size))


def hamming_distance(left: bytes, right: bytes) -> int:
    """Number of differing bits between two buffers of equal length."""
    return sum(bin(a ^ b).count("1") for a, b in zip(left, right))


# ---------------------------------------------------------------------------
# Recognised test vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key, expected", APPENDIX_C_VECTORS)
def test_encryption_matches_fips_197_appendix_c(key, expected):
    assert encrypt_block(APPENDIX_C_PLAINTEXT, round_keys(key)) == expected


@pytest.mark.parametrize("key, ciphertext", APPENDIX_C_VECTORS)
def test_decryption_matches_fips_197_appendix_c(key, ciphertext):
    assert decrypt_block(ciphertext, round_keys(key)) == APPENDIX_C_PLAINTEXT


def test_encryption_matches_the_fips_197_appendix_b_example():
    """The same run whose first round is checked in test_transforms."""
    result = encrypt_block(APPENDIX_B_PLAINTEXT, round_keys(APPENDIX_B_KEY))
    assert result == APPENDIX_B_CIPHERTEXT


def test_decryption_matches_the_fips_197_appendix_b_example():
    result = decrypt_block(APPENDIX_B_CIPHERTEXT, round_keys(APPENDIX_B_KEY))
    assert result == APPENDIX_B_PLAINTEXT


@pytest.mark.parametrize("key, expected", SP800_38A_ECB_VECTORS)
def test_multi_block_encryption_matches_sp_800_38a(key, expected):
    assert encrypt_buffer(SP800_38A_PLAINTEXT, round_keys(key)) == expected


@pytest.mark.parametrize("key, ciphertext", SP800_38A_ECB_VECTORS)
def test_multi_block_decryption_matches_sp_800_38a(key, ciphertext):
    assert decrypt_buffer(ciphertext, round_keys(key)) == SP800_38A_PLAINTEXT


# ---------------------------------------------------------------------------
# D_K(E_K(P)) = P
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
@pytest.mark.parametrize("trial", range(20))
def test_decryption_undoes_encryption_on_random_blocks(key_size, trial):
    keys = round_keys(random_bytes(key_size))
    plaintext = random_bytes(BLOCK_SIZE)
    assert decrypt_block(encrypt_block(plaintext, keys), keys) == plaintext


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
@pytest.mark.parametrize("blocks", [1, 2, 5, 16])
def test_decryption_undoes_encryption_on_random_buffers(key_size, blocks):
    keys = round_keys(random_bytes(key_size))
    plaintext = random_bytes(BLOCK_SIZE * blocks)
    assert decrypt_buffer(encrypt_buffer(plaintext, keys), keys) == plaintext


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_the_round_trip_holds_for_extreme_blocks(key_size):
    keys = round_keys(bytes(key_size))
    for plaintext in (bytes(BLOCK_SIZE), bytes([0xFF]) * BLOCK_SIZE):
        assert decrypt_block(encrypt_block(plaintext, keys), keys) == plaintext


# ---------------------------------------------------------------------------
# Behaviour of the cipher
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_encryption_is_deterministic(key_size):
    keys = round_keys(random_bytes(key_size))
    plaintext = random_bytes(BLOCK_SIZE)
    assert encrypt_block(plaintext, keys) == encrypt_block(plaintext, keys)


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_different_keys_give_different_ciphertexts(key_size):
    plaintext = random_bytes(BLOCK_SIZE)
    first = encrypt_block(plaintext, round_keys(random_bytes(key_size)))
    second = encrypt_block(plaintext, round_keys(random_bytes(key_size)))
    assert first != second


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_the_ciphertext_does_not_resemble_the_plaintext(key_size):
    keys = round_keys(random_bytes(key_size))
    plaintext = bytes(BLOCK_SIZE)
    assert encrypt_block(plaintext, keys) != plaintext


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_flipping_one_plaintext_bit_changes_about_half_the_ciphertext(key_size):
    """
    The avalanche property. A single-bit change must not produce a
    related ciphertext; for a good block cipher roughly 64 of the 128
    bits flip.
    """
    keys = round_keys(random_bytes(key_size))
    distances = []
    for _ in range(30):
        plaintext = bytearray(random_bytes(BLOCK_SIZE))
        original = encrypt_block(bytes(plaintext), keys)
        plaintext[_RANDOM.randrange(BLOCK_SIZE)] ^= 1 << _RANDOM.randrange(8)
        changed = encrypt_block(bytes(plaintext), keys)
        distance = hamming_distance(original, changed)
        assert distance > 30, "a single bit barely propagated"
        distances.append(distance)
    average = sum(distances) / len(distances)
    assert 55 <= average <= 73, f"average avalanche was {average:.1f} bits"


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_identical_blocks_encrypt_identically(key_size):
    """
    Documents why the buffer helpers are not a secure mode: with raw
    ECB, repeated plaintext blocks stay visible in the ciphertext.
    """
    keys = round_keys(random_bytes(key_size))
    block = random_bytes(BLOCK_SIZE)
    ciphertext = encrypt_buffer(block * 3, keys)
    assert ciphertext[:BLOCK_SIZE] == ciphertext[BLOCK_SIZE : 2 * BLOCK_SIZE]


@pytest.mark.parametrize("key_size", KEY_SIZES_IN_BYTES)
def test_a_buffer_is_the_concatenation_of_its_encrypted_blocks(key_size):
    keys = round_keys(random_bytes(key_size))
    blocks = [random_bytes(BLOCK_SIZE) for _ in range(4)]
    expected = b"".join(encrypt_block(block, keys) for block in blocks)
    assert encrypt_buffer(b"".join(blocks), keys) == expected


def test_an_empty_buffer_encrypts_to_nothing():
    keys = round_keys(bytes(16))
    assert encrypt_buffer(b"", keys) == b""
    assert decrypt_buffer(b"", keys) == b""


# ---------------------------------------------------------------------------
# The number of rounds follows the key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_size, expected_rounds", [(16, 10), (24, 12), (32, 14)])
def test_the_cipher_uses_one_round_key_per_round_plus_one(key_size, expected_rounds):
    keys = round_keys(random_bytes(key_size))
    assert len(keys) == expected_rounds + 1


def test_dropping_a_round_key_changes_the_result():
    """
    A guard against the round count being ignored: running AES-256 with
    only the first eleven round keys must not reproduce the AES-256
    ciphertext.
    """
    key = random_bytes(32)
    keys = round_keys(key)
    plaintext = random_bytes(BLOCK_SIZE)
    assert encrypt_block(plaintext, keys) != encrypt_block(plaintext, keys[:11])


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 15, 17, 32])
@pytest.mark.parametrize("function", [encrypt_block, decrypt_block])
def test_blocks_of_the_wrong_size_are_rejected(function, length):
    with pytest.raises(ValueError):
        function(bytes(length), round_keys(bytes(16)))


@pytest.mark.parametrize("length", [1, 15, 17, 31, 33])
@pytest.mark.parametrize("function", [encrypt_buffer, decrypt_buffer])
def test_buffers_that_are_not_a_multiple_of_the_block_are_rejected(function, length):
    with pytest.raises(ValueError):
        function(bytes(length), round_keys(bytes(16)))
