"""
Tests of the ECB and CBC modes (Exercises 2, 3, 4, 5 and 6).

Includes official vectors from FIPS PUB 81, round trips over messages of
arbitrary length, the effect of the IV and error propagation.
"""

import random

import pytest

from modes import (
    BLOCK_SIZE,
    PaddingError,
    des_cbc_decrypt,
    des_cbc_decrypt_blocks,
    des_cbc_encrypt,
    des_ecb_decrypt,
    des_ecb_decrypt_blocks,
    des_ecb_encrypt,
    random_iv,
    split_blocks,
    xor_bytes,
)

KEY = bytes.fromhex("133457799BBCDFF1")
IV = bytes.fromhex("0001020304050607")

# FIPS PUB 81, appendix: same (K, P) encrypted in ECB and in CBC.
FIPS81_KEY = bytes.fromhex("0123456789abcdef")
FIPS81_IV = bytes.fromhex("1234567890abcdef")
FIPS81_PLAINTEXT = b"Now is the time for all "  # 24 bytes = exactly 3 blocks
FIPS81_ECB = bytes.fromhex("3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53")
FIPS81_CBC = bytes.fromhex("e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6")

MESSAGES = [
    b"",
    b"A",
    b"12345678",              # exactly one block
    b"123456789",             # one block + 1 byte
    b"ABCDEFGHABCDEFGH",      # exactly two blocks
    b"Mensaje de longitud arbitraria para probar los modos de operacion.",
    bytes(range(256)),
]


def popcount(data: bytes) -> int:
    return sum(bin(byte).count("1") for byte in data)


# ---------------------------------------------------------------------------
# Known-answer vectors (FIPS PUB 81)
# ---------------------------------------------------------------------------

def test_ecb_known_answer_fips81():
    """The first 3 blocks must match; the 4th one is the PKCS#7 padding."""
    ciphertext = des_ecb_encrypt(FIPS81_KEY, FIPS81_PLAINTEXT)
    assert ciphertext[: len(FIPS81_ECB)] == FIPS81_ECB
    assert len(ciphertext) == len(FIPS81_ECB) + BLOCK_SIZE


def test_cbc_known_answer_fips81():
    ciphertext = des_cbc_encrypt(FIPS81_KEY, FIPS81_PLAINTEXT, FIPS81_IV)
    assert ciphertext[: len(FIPS81_CBC)] == FIPS81_CBC
    assert len(ciphertext) == len(FIPS81_CBC) + BLOCK_SIZE


def test_known_answers_decrypt_back():
    assert des_ecb_decrypt(
        FIPS81_KEY, des_ecb_encrypt(FIPS81_KEY, FIPS81_PLAINTEXT)
    ) == FIPS81_PLAINTEXT
    assert des_cbc_decrypt(
        FIPS81_KEY, des_cbc_encrypt(FIPS81_KEY, FIPS81_PLAINTEXT, FIPS81_IV), FIPS81_IV
    ) == FIPS81_PLAINTEXT


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("message", MESSAGES, ids=lambda m: f"len{len(m)}")
def test_ecb_round_trip(message):
    assert des_ecb_decrypt(KEY, des_ecb_encrypt(KEY, message)) == message


@pytest.mark.parametrize("message", MESSAGES, ids=lambda m: f"len{len(m)}")
def test_cbc_round_trip(message):
    assert des_cbc_decrypt(KEY, des_cbc_encrypt(KEY, message, IV), IV) == message


@pytest.mark.parametrize("seed", range(10))
def test_round_trip_random_messages(seed):
    rng = random.Random(seed)
    key = rng.randbytes(8)
    iv = rng.randbytes(8)
    message = rng.randbytes(rng.randrange(0, 200))

    assert des_ecb_decrypt(key, des_ecb_encrypt(key, message)) == message
    assert des_cbc_decrypt(key, des_cbc_encrypt(key, message, iv), iv) == message


@pytest.mark.parametrize("message", MESSAGES, ids=lambda m: f"len{len(m)}")
def test_ciphertext_length_is_padded_multiple(message):
    for ciphertext in (
        des_ecb_encrypt(KEY, message),
        des_cbc_encrypt(KEY, message, IV),
    ):
        assert len(ciphertext) % BLOCK_SIZE == 0
        assert len(ciphertext) > len(message)


# ---------------------------------------------------------------------------
# Exercise 4: repeated blocks
# ---------------------------------------------------------------------------

def test_ecb_leaks_repeated_blocks():
    """Equal plaintext blocks give equal ciphertext blocks."""
    plaintext = b"ABCDEFGH" * 4
    blocks = split_blocks(des_ecb_encrypt(KEY, plaintext))
    assert blocks[0] == blocks[1] == blocks[2] == blocks[3]
    assert len(set(blocks[:4])) == 1


def test_cbc_hides_repeated_blocks():
    plaintext = b"ABCDEFGH" * 4
    blocks = split_blocks(des_cbc_encrypt(KEY, plaintext, IV))
    assert len(set(blocks)) == len(blocks)


def test_ecb_is_deterministic_but_cbc_is_not():
    plaintext = b"mismo mensaje, misma llave"
    assert des_ecb_encrypt(KEY, plaintext) == des_ecb_encrypt(KEY, plaintext)
    a = des_cbc_encrypt(KEY, plaintext, random_iv())
    b = des_cbc_encrypt(KEY, plaintext, random_iv())
    assert a != b


# ---------------------------------------------------------------------------
# Exercise 5: effect of the IV
# ---------------------------------------------------------------------------

def test_different_ivs_give_different_ciphertexts():
    plaintext = b"El mismo mensaje cifrado con dos IVs distintos."
    iv1 = bytes.fromhex("0000000000000000")
    iv2 = bytes.fromhex("0000000000000001")
    assert des_cbc_encrypt(KEY, plaintext, iv1) != des_cbc_encrypt(KEY, plaintext, iv2)


@pytest.mark.parametrize("seed", range(20))
def test_random_iv_pairs_almost_always_differ(seed):
    rng = random.Random(seed)
    plaintext = b"mensaje fijo para el experimento del IV"
    iv1, iv2 = rng.randbytes(8), rng.randbytes(8)
    if iv1 == iv2:  # impossible in practice, but the test must not rely on it
        pytest.skip("los dos IVs aleatorios coincidieron")
    assert des_cbc_encrypt(KEY, plaintext, iv1) != des_cbc_encrypt(KEY, plaintext, iv2)


def test_wrong_iv_corrupts_only_the_first_block():
    """P_1 = D_K(C_1) XOR IV: a wrong IV enters by XOR and does not propagate."""
    plaintext = b"BLOQUE01BLOQUE02BLOQUE03"
    iv1 = bytes.fromhex("0000000000000000")
    iv2 = bytes.fromhex("0000000000000001")  # differs in 1 bit
    ciphertext = des_cbc_encrypt(KEY, plaintext, iv1)

    recovered = des_cbc_decrypt_blocks(KEY, ciphertext, iv2)
    expected = des_cbc_decrypt_blocks(KEY, ciphertext, iv1)

    assert recovered[BLOCK_SIZE:] == expected[BLOCK_SIZE:]
    # The first block differs exactly in the bits where the IVs differ.
    assert xor_bytes(recovered[:BLOCK_SIZE], expected[:BLOCK_SIZE]) == xor_bytes(iv1, iv2)


# ---------------------------------------------------------------------------
# Exercise 6: error propagation
# ---------------------------------------------------------------------------

def _flip_first_bit_of_block(data: bytes, block_index: int) -> bytes:
    out = bytearray(data)
    out[block_index * BLOCK_SIZE] ^= 0x80
    return bytes(out)


def test_ecb_error_does_not_propagate():
    plaintext = b"BLOQUE01BLOQUE02BLOQUE03BLOQUE04"
    ciphertext = des_ecb_encrypt(KEY, plaintext)

    good = split_blocks(des_ecb_decrypt_blocks(KEY, ciphertext))
    bad = split_blocks(des_ecb_decrypt_blocks(KEY, _flip_first_bit_of_block(ciphertext, 1)))

    assert bad[1] != good[1]                       # the touched block is corrupted
    assert [i for i, (a, b) in enumerate(zip(good, bad)) if a != b] == [1]
    # DES avalanche: around half of the 64 bits of the block.
    assert 16 <= popcount(xor_bytes(good[1], bad[1])) <= 48


def test_cbc_error_propagates_to_exactly_two_blocks():
    plaintext = b"BLOQUE01BLOQUE02BLOQUE03BLOQUE04"
    ciphertext = des_cbc_encrypt(KEY, plaintext, IV)

    good = split_blocks(des_cbc_decrypt_blocks(KEY, ciphertext, IV))
    bad = split_blocks(des_cbc_decrypt_blocks(KEY, _flip_first_bit_of_block(ciphertext, 1), IV))

    changed = [i for i, (a, b) in enumerate(zip(good, bad)) if a != b]
    assert changed == [1, 2]                       # neither before nor after

    assert 16 <= popcount(xor_bytes(good[1], bad[1])) <= 48   # P_2: avalanche
    # P_3 changes EXACTLY in the flipped bit of the ciphertext.
    assert popcount(xor_bytes(good[2], bad[2])) == 1
    assert xor_bytes(good[2], bad[2])[0] == 0x80


# ---------------------------------------------------------------------------
# Invalid inputs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_iv", [b"", bytes(7), bytes(9), bytes(16)])
def test_cbc_rejects_iv_of_wrong_length(bad_iv):
    with pytest.raises(ValueError):
        des_cbc_encrypt(KEY, b"mensaje", bad_iv)
    with pytest.raises(ValueError):
        des_cbc_decrypt(KEY, bytes(8), bad_iv)


def test_modes_reject_empty_ciphertext():
    with pytest.raises(ValueError):
        des_ecb_decrypt(KEY, b"")
    with pytest.raises(ValueError):
        des_cbc_decrypt(KEY, b"", IV)


@pytest.mark.parametrize("length", [1, 7, 9, 15])
def test_modes_reject_ciphertext_not_multiple_of_block(length):
    with pytest.raises(ValueError):
        des_ecb_decrypt(KEY, bytes(length))
    with pytest.raises(ValueError):
        des_cbc_decrypt(KEY, bytes(length), IV)


def test_decrypt_with_wrong_key_usually_fails_padding():
    """Decrypting with another key produces invalid padding almost always."""
    ciphertext = des_ecb_encrypt(KEY, b"mensaje secreto de prueba")
    wrong_key = bytes.fromhex("0123456789ABCDEF")
    with pytest.raises(PaddingError):
        des_ecb_decrypt(wrong_key, ciphertext)
