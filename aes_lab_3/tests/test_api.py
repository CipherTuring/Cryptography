"""
Tests for the public `AES` interface.

Exercise 2. The cipher itself is covered in `test_cipher`; what is
checked here is the contract a caller sees: that the key length alone
selects the variant, that the key schedule is computed once and reused,
and that every invalid argument is rejected with a clear error instead
of producing wrong output.
"""

import random

import pytest

from aeslib.api import AES, BACKENDS
from aeslib.key_schedule import round_keys
from aeslib.state import BLOCK_SIZE

from .vectors import (
    APPENDIX_C_PLAINTEXT,
    APPENDIX_C_VECTORS,
    SP800_38A_ECB_VECTORS,
    SP800_38A_PLAINTEXT,
)

_RANDOM = random.Random(20260916)

VARIANTS = [(16, 128, 10), (24, 192, 12), (32, 256, 14)]


def random_bytes(size: int) -> bytes:
    return bytes(_RANDOM.randrange(256) for _ in range(size))


# ---------------------------------------------------------------------------
# The key length selects the variant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_size, bits, rounds", VARIANTS)
def test_the_key_length_determines_the_variant(key_size, bits, rounds):
    aes = AES(random_bytes(key_size))
    assert aes.key_size == bits
    assert aes.rounds == rounds
    assert aes.name == f"AES-{bits}"


@pytest.mark.parametrize("key_size, bits, rounds", VARIANTS)
def test_repr_describes_the_instance(key_size, bits, rounds):
    text = repr(AES(random_bytes(key_size)))
    assert f"key_size={bits}" in text
    assert f"rounds={rounds}" in text
    assert "reference" in text


@pytest.mark.parametrize("key_size, bits, rounds", VARIANTS)
def test_the_key_schedule_is_computed_once_and_matches_the_standalone_one(
    key_size, bits, rounds
):
    key = random_bytes(key_size)
    aes = AES(key)
    assert aes.round_keys == round_keys(key)
    assert len(aes.round_keys) == rounds + 1


def test_the_key_is_stored_as_immutable_bytes():
    """A caller mutating its own buffer must not alter the instance."""
    key = bytearray(random_bytes(16))
    aes = AES(key)
    key[0] ^= 0xFF
    assert aes.key != bytes(key)
    assert isinstance(aes.key, bytes)


# ---------------------------------------------------------------------------
# Encryption through the public interface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key, expected", APPENDIX_C_VECTORS)
def test_encrypt_block_matches_the_published_vectors(key, expected):
    assert AES(key).encrypt_block(APPENDIX_C_PLAINTEXT) == expected


@pytest.mark.parametrize("key, expected", SP800_38A_ECB_VECTORS)
def test_encrypt_matches_the_published_multi_block_vectors(key, expected):
    assert AES(key).encrypt(SP800_38A_PLAINTEXT) == expected


@pytest.mark.parametrize("key_size, bits, rounds", VARIANTS)
@pytest.mark.parametrize("blocks", [1, 3, 10])
def test_decrypt_undoes_encrypt(key_size, bits, rounds, blocks):
    aes = AES(random_bytes(key_size))
    plaintext = random_bytes(BLOCK_SIZE * blocks)
    assert aes.decrypt(aes.encrypt(plaintext)) == plaintext


@pytest.mark.parametrize("key_size, bits, rounds", VARIANTS)
def test_the_same_instance_can_be_reused_for_many_blocks(key_size, bits, rounds):
    """The round keys are state; using them twice must not corrupt them."""
    aes = AES(random_bytes(key_size))
    first = aes.encrypt_block(APPENDIX_C_PLAINTEXT)
    for _ in range(5):
        aes.encrypt_block(random_bytes(BLOCK_SIZE))
    assert aes.encrypt_block(APPENDIX_C_PLAINTEXT) == first


def test_an_empty_buffer_is_accepted():
    aes = AES(random_bytes(16))
    assert aes.encrypt(b"") == b""
    assert aes.decrypt(b"") == b""


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


def test_the_reference_backend_is_available():
    assert "reference" in BACKENDS
    assert AES(bytes(16), backend="reference").backend == "reference"


@pytest.mark.parametrize("name", ["", "Reference", "table", "fastest", None])
def test_unknown_backends_are_rejected(name):
    with pytest.raises(ValueError):
        AES(bytes(16), backend=name)


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 48])
def test_unsupported_key_lengths_are_rejected(length):
    with pytest.raises(ValueError):
        AES(bytes(length))


@pytest.mark.parametrize("bad", ["a 16 byte key!!!", 16, None, [0] * 16])
def test_non_byte_keys_are_rejected(bad):
    with pytest.raises(TypeError):
        AES(bad)


@pytest.mark.parametrize("length", [0, 15, 17, 32])
@pytest.mark.parametrize("method", ["encrypt_block", "decrypt_block"])
def test_the_block_methods_reject_anything_but_one_block(method, length):
    """32 bytes is a valid buffer length, but still not a single block."""
    aes = AES(bytes(16))
    with pytest.raises(ValueError):
        getattr(aes, method)(bytes(length))


@pytest.mark.parametrize("length", [1, 15, 17, 31])
def test_encrypt_rejects_buffers_that_are_not_whole_blocks(length):
    aes = AES(bytes(16))
    with pytest.raises(ValueError):
        aes.encrypt(bytes(length))
    with pytest.raises(ValueError):
        aes.decrypt(bytes(length))
