"""
Tests for the AES key schedule.

Exercise 2, "Key Schedule for the three key sizes". The expansion is
checked against the examples of FIPS-197 Appendix A, and then against
the structural properties that have to hold for any key: the number of
words produced, the position of the original key inside the expansion,
and the fact that the schedule is not a mere repetition of the key.

The AES-256 case deserves the attention it gets here. Its extra SubWord,
applied when Nk > 6 and i mod Nk == 4, is the only branch in the whole
package that depends on the key size, and an implementation that omits
it still produces a plausible-looking expansion of the right length.
"""

import random

import pytest

from aeslib.key_schedule import (
    KEY_SIZES,
    RCON,
    expand_key,
    number_of_rounds,
    rot_word,
    round_keys,
    sub_word,
)
from aeslib.sbox import SBOX
from aeslib.state import BLOCK_SIZE, NB

from .vectors import (
    APPENDIX_A_KEY_128,
    APPENDIX_A_KEY_192,
    APPENDIX_A_KEY_256,
    APPENDIX_A_LAST_ROUND_KEY_192,
    APPENDIX_A_LAST_ROUND_KEY_256,
    APPENDIX_A_ROUND_KEYS_128,
    FIPS197_ROUND_CONSTANTS,
)

_RANDOM = random.Random(20260915)

KEY_SIZES_IN_BYTES = [16, 24, 32]
EXPECTED_ROUNDS = {16: 10, 24: 12, 32: 14}
EXPECTED_WORDS = {16: 44, 24: 52, 32: 60}


def random_key(size: int) -> bytes:
    return bytes(_RANDOM.randrange(256) for _ in range(size))


# ---------------------------------------------------------------------------
# The round constants
# ---------------------------------------------------------------------------


def test_round_constants_match_the_published_values():
    """RCON[0] is an unused placeholder, so the constants start at index 1."""
    assert RCON[1:] == FIPS197_ROUND_CONSTANTS


def test_round_constants_are_successive_powers_of_x():
    for index in range(2, len(RCON)):
        previous = RCON[index - 1]
        doubled = previous << 1
        if doubled & 0x100:
            doubled ^= 0x11B
        assert RCON[index] == doubled


# ---------------------------------------------------------------------------
# The word helpers
# ---------------------------------------------------------------------------


def test_rot_word_moves_the_first_byte_to_the_end():
    assert rot_word((0x09, 0xCF, 0x4F, 0x3C)) == (0xCF, 0x4F, 0x3C, 0x09)


def test_rot_word_applied_four_times_is_the_identity():
    word = (0x01, 0x02, 0x03, 0x04)
    rotated = word
    for _ in range(4):
        rotated = rot_word(rotated)
    assert rotated == word


def test_sub_word_substitutes_each_byte_through_the_sbox():
    word = (0xCF, 0x4F, 0x3C, 0x09)
    assert sub_word(word) == tuple(SBOX[byte] for byte in word)


# ---------------------------------------------------------------------------
# Agreement with FIPS-197 Appendix A
# ---------------------------------------------------------------------------


def test_aes_128_expansion_matches_appendix_a_in_full():
    computed = round_keys(APPENDIX_A_KEY_128)
    assert len(computed) == len(APPENDIX_A_ROUND_KEYS_128)
    for index, (got, expected) in enumerate(zip(computed, APPENDIX_A_ROUND_KEYS_128)):
        assert got == expected, f"round key {index} differs"


def test_aes_192_last_round_key_matches_appendix_a():
    assert round_keys(APPENDIX_A_KEY_192)[-1] == APPENDIX_A_LAST_ROUND_KEY_192


def test_aes_256_last_round_key_matches_appendix_a():
    """
    The value that proves the extra SubWord of AES-256 is applied: an
    expansion missing that branch diverges long before the last key.
    """
    assert round_keys(APPENDIX_A_KEY_256)[-1] == APPENDIX_A_LAST_ROUND_KEY_256


# ---------------------------------------------------------------------------
# Shape of the expansion
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_the_number_of_rounds_follows_the_key_size(size):
    assert number_of_rounds(random_key(size)) == EXPECTED_ROUNDS[size]
    assert KEY_SIZES[size] == EXPECTED_ROUNDS[size]


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_the_expansion_has_four_words_per_round_plus_one(size):
    key = random_key(size)
    words = expand_key(key)
    assert len(words) == EXPECTED_WORDS[size]
    assert len(words) == NB * (number_of_rounds(key) + 1)


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_every_word_is_four_bytes(size):
    for word in expand_key(random_key(size)):
        assert len(word) == 4
        assert all(0 <= byte < 256 for byte in word)


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_the_expansion_starts_with_the_cipher_key(size):
    key = random_key(size)
    words = expand_key(key)
    leading = bytes(byte for word in words[: size // 4] for byte in word)
    assert leading == key


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_there_is_one_round_key_per_round_plus_the_initial_one(size):
    key = random_key(size)
    keys = round_keys(key)
    assert len(keys) == number_of_rounds(key) + 1
    assert all(len(item) == BLOCK_SIZE for item in keys)


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_the_first_round_key_is_the_start_of_the_cipher_key(size):
    key = random_key(size)
    assert round_keys(key)[0] == key[:BLOCK_SIZE]


# ---------------------------------------------------------------------------
# The schedule actually mixes the key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_the_round_keys_are_not_repetitions_of_the_cipher_key(size):
    keys = round_keys(random_key(size))
    assert len(set(keys)) == len(keys)


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_an_all_zero_key_still_produces_varied_round_keys(size):
    """
    The round constants exist to break the symmetry of the schedule:
    without them a constant key would expand into constant round keys.

    The check starts past the raw key material, because the first round
    keys are copied verbatim from the cipher key and are therefore zero
    here. AES-256 is the visible case: a 32-byte key fills two whole
    round keys, so `rk0` and `rk1` are legitimately identical for this
    input.
    """
    keys = round_keys(bytes(size))
    derived = keys[size // BLOCK_SIZE :]
    assert all(key != bytes(BLOCK_SIZE) for key in derived)
    assert len(set(derived)) == len(derived)


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_flipping_one_key_bit_changes_the_last_round_key(size):
    key = bytearray(random_key(size))
    original = round_keys(bytes(key))[-1]
    key[0] ^= 0x01
    assert round_keys(bytes(key))[-1] != original


@pytest.mark.parametrize("size", KEY_SIZES_IN_BYTES)
def test_the_expansion_is_deterministic(size):
    key = random_key(size)
    assert expand_key(key) == expand_key(key)


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 64])
def test_unsupported_key_lengths_are_rejected(length):
    with pytest.raises(ValueError):
        expand_key(bytes(length))


@pytest.mark.parametrize("bad", ["a key", 16, None, [0] * 16])
def test_non_byte_keys_are_rejected(bad):
    with pytest.raises(TypeError):
        expand_key(bad)


def test_bytearray_keys_are_accepted():
    """A mutable buffer is still a sequence of bytes."""
    assert expand_key(bytearray(APPENDIX_A_KEY_128)) == expand_key(APPENDIX_A_KEY_128)
