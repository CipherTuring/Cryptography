"""
Test suite for deslib, covering the Laboratory 1 requirements:
- Known test vector (encryption and decryption).
- Subkeys k1 and k16.
- Round trip over 20+ blocks.
- Avalanche effect (plaintext bit and key bit).
- Rejection of keys/blocks of invalid length.
- Bit order (MSB vs LSB) in the generic permutation.
"""

import random

import pytest

from deslib import (
    des_check_parity,
    des_decrypt_block,
    des_encrypt_block,
    des_key_schedule,
    permute,
)

# ---------------------------------------------------------------------------
# Classic test vector (FIPS 81 / standard DES literature)
# ---------------------------------------------------------------------------
KEY = bytes.fromhex("133457799BBCDFF1")
PLAINTEXT = bytes.fromhex("0123456789ABCDEF")
CIPHERTEXT = bytes.fromhex("85E813540F0AB405")

K1_EXPECTED = 0x1B02EFFC7072
K16_EXPECTED = 0xCB3D8B0E17F5

# Bound for the avalanche effect. The number of differing bits follows a
# Binomial(64, 1/2): mean 32 and standard deviation 4. The band [16, 48] is
# +-4 sigma, so a correct DES stays inside it except with probability ~1e-4.
# (The [20, 44] = +-3 sigma band used in Lab 1 leaves out ~0.5% of the
# legitimate cases and would therefore flag a correct DES as a failure.)
AVALANCHE_MIN = 16
AVALANCHE_MAX = 48


def popcount(value: int) -> int:
    return bin(value).count("1")


# ---------------------------------------------------------------------------
# Known vector
# ---------------------------------------------------------------------------

def test_known_vector_encrypt():
    assert des_encrypt_block(KEY, PLAINTEXT) == CIPHERTEXT


def test_known_vector_decrypt():
    assert des_decrypt_block(KEY, CIPHERTEXT) == PLAINTEXT


# ---------------------------------------------------------------------------
# Round subkeys
# ---------------------------------------------------------------------------

def test_round_key_k1():
    subkeys = des_key_schedule(KEY)
    assert subkeys[0] == K1_EXPECTED


def test_round_key_k16():
    subkeys = des_key_schedule(KEY)
    assert subkeys[15] == K16_EXPECTED


def test_key_schedule_length():
    subkeys = des_key_schedule(KEY)
    assert len(subkeys) == 16
    assert all(0 <= k < (1 << 48) for k in subkeys)


# ---------------------------------------------------------------------------
# Round trip: D_K(E_K(P)) == P for >= 20 blocks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("seed", range(20))
def test_round_trip(seed):
    rng = random.Random(seed)
    key = rng.randbytes(8)
    plaintext = rng.randbytes(8)

    cipher = des_encrypt_block(key, plaintext)
    recovered = des_decrypt_block(key, cipher)
    assert recovered == plaintext


# ---------------------------------------------------------------------------
# Avalanche effect
# ---------------------------------------------------------------------------

def test_avalanche_plaintext_bit_flip():
    rng = random.Random(1234)
    key = rng.randbytes(8)
    plaintext = rng.randbytes(8)

    cipher1 = int.from_bytes(des_encrypt_block(key, plaintext), "big")

    # Flip a single bit of the plaintext.
    flipped = bytearray(plaintext)
    flipped[0] ^= 0x01
    cipher2 = int.from_bytes(des_encrypt_block(key, bytes(flipped)), "big")

    diff_bits = popcount(cipher1 ^ cipher2)
    assert AVALANCHE_MIN <= diff_bits <= AVALANCHE_MAX


def test_avalanche_key_bit_flip():
    rng = random.Random(5678)
    key = bytearray(rng.randbytes(8))
    plaintext = rng.randbytes(8)

    cipher1 = int.from_bytes(des_encrypt_block(bytes(key), plaintext), "big")

    # Flip an effective key bit (not a parity bit, bit 0 of the byte).
    key2 = bytearray(key)
    key2[0] ^= 0x02  # effective bit, not the parity bit (LSB)
    cipher2 = int.from_bytes(des_encrypt_block(bytes(key2), plaintext), "big")

    diff_bits = popcount(cipher1 ^ cipher2)
    assert AVALANCHE_MIN <= diff_bits <= AVALANCHE_MAX


# ---------------------------------------------------------------------------
# Invalid inputs
# ---------------------------------------------------------------------------

def test_rejects_short_key():
    with pytest.raises(ValueError):
        des_encrypt_block(bytes(7), PLAINTEXT)


def test_rejects_long_key():
    with pytest.raises(ValueError):
        des_encrypt_block(bytes(9), PLAINTEXT)


def test_rejects_short_block():
    with pytest.raises(ValueError):
        des_encrypt_block(KEY, bytes(7))


def test_rejects_long_block():
    with pytest.raises(ValueError):
        des_encrypt_block(KEY, bytes(9))


def test_key_schedule_rejects_invalid_length():
    with pytest.raises(ValueError):
        des_key_schedule(bytes(6))


# ---------------------------------------------------------------------------
# Parity check
# ---------------------------------------------------------------------------

def test_check_parity_valid_key():
    # 0x01 has a single bit -> odd parity -> valid.
    key = bytes([0x01] * 8)
    assert des_check_parity(key) is True


def test_check_parity_invalid_key():
    # 0x00 has zero bits -> even parity -> invalid.
    key = bytes([0x00] * 8)
    assert des_check_parity(key) is False


# ---------------------------------------------------------------------------
# Bit order: bit 1 of DES is the MSB, not the LSB.
# ---------------------------------------------------------------------------


def test_bit_order_is_msb_first():
    """
    This test fails if `permute` (or any code that depends on it) reads
    bit 1 of a DES table as the LSB instead of the MSB.

    With an 8-bit identity table [1,2,...,8] applied to the value
    0b10000000 (bit 1 = 1, all the others 0), the expected result is
    identical to the input ONLY if bit 1 is read as the MSB.
    """
    identity_table = tuple(range(1, 9))
    value = 0b10000000  # bit 1 (MSB) on, bit 8 (LSB) off

    result = permute(value, identity_table, 8)
    assert result == value  # 0b10000000

    # If somebody reversed the order (bit 1 == LSB), this same value would
    # produce 0b00000001 instead of 0b10000000.
    assert result != 0b00000001
