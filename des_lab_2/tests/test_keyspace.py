"""
Tests of the controlled key space (Exercise 7).

Checks the candidate -> 56 effective bits -> 64-bit DES key mapping, in
particular that the parity bits are generated correctly and that the
mapping is injective.
"""

import pytest

from attacks.keyspace import (
    EFFECTIVE_BITS,
    KEY_BYTES,
    KeySpace,
    add_parity_bits,
    has_odd_parity,
    strip_parity_bits,
)
from deslib import des_check_parity, des_encrypt_block

PLAINTEXT = bytes.fromhex("0123456789ABCDEF")


# ---------------------------------------------------------------------------
# Parity bits
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "key56",
    [0, 1, (1 << EFFECTIVE_BITS) - 1, 0x0123456789ABCD, 0x00FEDCBA987654],
)
def test_parity_round_trip(key56):
    key = add_parity_bits(key56)
    assert len(key) == KEY_BYTES
    assert strip_parity_bits(key) == key56


@pytest.mark.parametrize("key56", [0, 1, 0x0123456789ABCD, (1 << EFFECTIVE_BITS) - 1])
def test_generated_keys_have_odd_parity(key56):
    key = add_parity_bits(key56)
    assert has_odd_parity(key)
    # And the Lab 1 library must agree.
    assert des_check_parity(key) is True


def test_parity_of_zero_key():
    """56 zero bits -> every byte is 0x01 (a single bit, odd parity)."""
    assert add_parity_bits(0) == bytes([0x01] * 8)


def test_parity_of_all_ones_key():
    """56 one bits -> every byte is 0xFE (seven bits, odd parity)."""
    assert add_parity_bits((1 << EFFECTIVE_BITS) - 1) == bytes([0xFE] * 8)


@pytest.mark.parametrize("key56", [-1, 1 << EFFECTIVE_BITS, 1 << 64])
def test_add_parity_rejects_out_of_range(key56):
    with pytest.raises(ValueError):
        add_parity_bits(key56)


@pytest.mark.parametrize("length", [0, 7, 9])
def test_strip_parity_rejects_wrong_length(length):
    with pytest.raises(ValueError):
        strip_parity_bits(bytes(length))


def test_parity_bits_do_not_change_the_ciphertext():
    """
    DES discards the parity bits in PC-1: two keys that differ only in
    them encrypt identically. That is why the effective space is 2^56.
    """
    key56 = 0x0123456789ABCD
    with_parity = add_parity_bits(key56)
    # Flip the parity bit of every byte: the 56 effective bits are intact.
    flipped = bytes(byte ^ 0x01 for byte in with_parity)

    assert flipped != with_parity
    assert strip_parity_bits(flipped) == strip_parity_bits(with_parity)
    assert des_encrypt_block(flipped, PLAINTEXT) == des_encrypt_block(with_parity, PLAINTEXT)


# ---------------------------------------------------------------------------
# KeySpace
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bits", [1, 8, 16, 20, 24, 56])
def test_space_size(bits):
    assert KeySpace(unknown_bits=bits).size == 2**bits


@pytest.mark.parametrize("bits", [0, -1, 57, 64])
def test_rejects_invalid_unknown_bits(bits):
    with pytest.raises(ValueError):
        KeySpace(unknown_bits=bits)


def test_rejects_invalid_base_key():
    with pytest.raises(ValueError):
        KeySpace(unknown_bits=8, base_key56=1 << EFFECTIVE_BITS)


@pytest.mark.parametrize("candidate", [0, 1, 2, 511, 12345, 65535])
def test_candidate_key_round_trip(candidate):
    keyspace = KeySpace(unknown_bits=16, base_key56=0x00FEDCBA987654)
    if candidate >= keyspace.size:
        pytest.skip("candidato fuera del espacio")
    key = keyspace.key(candidate)
    assert has_odd_parity(key)
    assert keyspace.candidate_of(key) == candidate
    assert keyspace.contains(key)


def test_mapping_is_injective_over_a_small_space():
    keyspace = KeySpace(unknown_bits=10, base_key56=0x00112233445566)
    keys = [keyspace.key(c) for c in range(keyspace.size)]
    assert len(set(keys)) == keyspace.size


def test_known_bits_are_preserved():
    """The high 56 - n bits come from base_key56 for every candidate."""
    base = 0x00FEDCBA987654
    keyspace = KeySpace(unknown_bits=20, base_key56=base)
    high_mask = ~keyspace.mask
    for candidate in (0, 1, 999, keyspace.size - 1):
        assert (keyspace.key56(candidate) & high_mask) == (base & high_mask)
        assert (keyspace.key56(candidate) & keyspace.mask) == candidate


@pytest.mark.parametrize("candidate", [-1, 1024, 99999])
def test_rejects_candidate_outside_the_space(candidate):
    with pytest.raises(ValueError):
        KeySpace(unknown_bits=10).key(candidate)


def test_key_outside_the_space_is_rejected():
    keyspace = KeySpace(unknown_bits=8, base_key56=0x00FEDCBA987654)
    foreign = add_parity_bits(0x00112233445566)
    assert not keyspace.contains(foreign)
    with pytest.raises(ValueError):
        keyspace.candidate_of(foreign)


def test_full_space_maps_candidate_to_effective_key_directly():
    """With n = 56 the candidate integer IS the effective key."""
    keyspace = KeySpace(unknown_bits=EFFECTIVE_BITS)
    for candidate in (0, 1, 0x0123456789ABCD):
        assert keyspace.key56(candidate) == candidate
        assert keyspace.key(candidate) == add_parity_bits(candidate)


def test_keyspace_is_hashable_and_immutable():
    """It must be sendable to child processes with multiprocessing."""
    import pickle

    keyspace = KeySpace(unknown_bits=12, base_key56=0x0A0B0C0D0E0F10)
    assert pickle.loads(pickle.dumps(keyspace)) == keyspace
    with pytest.raises(Exception):
        keyspace.unknown_bits = 13  # frozen dataclass
