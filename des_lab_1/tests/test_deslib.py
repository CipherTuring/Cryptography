"""
Suite de tests para deslib, cubriendo los requisitos del Laboratorio 1:
- Vector de prueba conocido (cifrado y descifrado).
- Subllaves k1 y k16.
- Round-trip sobre 20+ bloques.
- Efecto avalancha (bit de texto plano y bit de llave).
- Rechazo de llaves/bloques de longitud inválida.
- Orden de bits (MSB vs LSB) en la permutación genérica.
"""

import os
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
# Vector de prueba clásico (FIPS 81 / literatura estándar de DES)
# ---------------------------------------------------------------------------
KEY = bytes.fromhex("133457799BBCDFF1")
PLAINTEXT = bytes.fromhex("0123456789ABCDEF")
CIPHERTEXT = bytes.fromhex("85E813540F0AB405")

K1_EXPECTED = 0x1B02EFFC7072
K16_EXPECTED = 0xCB3D8B0E17F5


def popcount(value: int) -> int:
    return bin(value).count("1")


# ---------------------------------------------------------------------------
# Vector conocido
# ---------------------------------------------------------------------------

def test_known_vector_encrypt():
    assert des_encrypt_block(KEY, PLAINTEXT) == CIPHERTEXT


def test_known_vector_decrypt():
    assert des_decrypt_block(KEY, CIPHERTEXT) == PLAINTEXT


# ---------------------------------------------------------------------------
# Subllaves de ronda
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
# Round-trip: D_K(E_K(P)) == P para >= 20 bloques
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
# Efecto avalancha
# ---------------------------------------------------------------------------

def test_avalanche_plaintext_bit_flip():
    rng = random.Random(1234)
    key = rng.randbytes(8)
    plaintext = rng.randbytes(8)

    cipher1 = int.from_bytes(des_encrypt_block(key, plaintext), "big")

    # Voltea un solo bit del texto plano.
    flipped = bytearray(plaintext)
    flipped[0] ^= 0x01
    cipher2 = int.from_bytes(des_encrypt_block(key, bytes(flipped)), "big")

    diff_bits = popcount(cipher1 ^ cipher2)
    assert 20 <= diff_bits <= 44


def test_avalanche_key_bit_flip():
    rng = random.Random(5678)
    key = bytearray(rng.randbytes(8))
    plaintext = rng.randbytes(8)

    cipher1 = int.from_bytes(des_encrypt_block(bytes(key), plaintext), "big")

    # Voltea un bit efectivo de la llave (no un bit de paridad, bit 0 del byte).
    key2 = bytearray(key)
    key2[0] ^= 0x02  # bit efectivo, no el bit de paridad (LSB)
    cipher2 = int.from_bytes(des_encrypt_block(bytes(key2), plaintext), "big")

    diff_bits = popcount(cipher1 ^ cipher2)
    assert 20 <= diff_bits <= 44


# ---------------------------------------------------------------------------
# Entradas inválidas
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
# Chequeo de paridad
# ---------------------------------------------------------------------------

def test_check_parity_valid_key():
    # 0x01 tiene un solo bit -> paridad impar -> válido.
    key = bytes([0x01] * 8)
    assert des_check_parity(key) is True


def test_check_parity_invalid_key():
    # 0x00 tiene cero bits -> paridad par -> inválido.
    key = bytes([0x00] * 8)
    assert des_check_parity(key) is False


# ---------------------------------------------------------------------------
# Orden de bits: el bit 1 de DES es el MSB, no el LSB.
# ---------------------------------------------------------------------------

def test_bit_order_is_msb_first():
    """
    Esta prueba falla si `permute` (o cualquier código que dependa de ella)
    interpreta el bit 1 de una tabla DES como el LSB en lugar del MSB.

    Con una tabla identidad de 8 bits [1,2,...,8] sobre el valor 0b10000000
    (bit 1 = 1, todos los demás 0), el resultado esperado es idéntico a la
    entrada SOLO si el bit 1 se lee como el MSB.
    """
    identity_table = tuple(range(1, 9))
    value = 0b10000000  # bit 1 (MSB) encendido, bit 8 (LSB) apagado

    result = permute(value, identity_table, 8)
    assert result == value  # 0b10000000

    # Si alguien invirtiera el orden (bit 1 == LSB), este mismo valor
    # produciría 0b00000001 en lugar de 0b10000000.
    assert result != 0b00000001
