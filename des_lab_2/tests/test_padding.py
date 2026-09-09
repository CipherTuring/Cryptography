"""
PKCS#7 padding tests (Exercise 1).

Covers `unpad(pad(M)) = M` for a range of lengths and the explicit
rejection of invalid paddings.
"""

import pytest

from modes.padding import BLOCK_SIZE, PaddingError, pkcs7_pad, pkcs7_unpad


# ---------------------------------------------------------------------------
# Example from the lab statement
# ---------------------------------------------------------------------------

def test_example_from_the_lab_statement():
    # 41 42 43 44 45  ->  41 42 43 44 45 03 03 03
    assert pkcs7_pad(bytes.fromhex("4142434445")) == bytes.fromhex("4142434445030303")


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("length", range(0, 33))
def test_round_trip_for_every_length(length):
    message = bytes(range(length))
    assert pkcs7_unpad(pkcs7_pad(message)) == message


@pytest.mark.parametrize("length", range(0, 33))
def test_padded_length_is_a_positive_multiple_of_the_block(length):
    padded = pkcs7_pad(bytes(length))
    assert len(padded) % BLOCK_SIZE == 0
    assert len(padded) > length  # the padding is never empty


def test_exact_multiple_gets_a_whole_extra_block():
    """A message that already fills whole blocks gets one full extra block."""
    message = b"A" * BLOCK_SIZE
    padded = pkcs7_pad(message)
    assert len(padded) == 2 * BLOCK_SIZE
    assert padded[BLOCK_SIZE:] == bytes([BLOCK_SIZE]) * BLOCK_SIZE
    assert pkcs7_unpad(padded) == message


def test_pad_value_equals_number_of_bytes_added():
    for length in range(0, 17):
        padded = pkcs7_pad(bytes(length))
        added = len(padded) - length
        assert padded[-added:] == bytes([added]) * added


@pytest.mark.parametrize("block_size", [1, 4, 8, 16, 255])
def test_other_block_sizes(block_size):
    message = b"mensaje de prueba"
    padded = pkcs7_pad(message, block_size)
    assert len(padded) % block_size == 0
    assert pkcs7_unpad(padded, block_size) == message


# ---------------------------------------------------------------------------
# Invalid padding
# ---------------------------------------------------------------------------

def test_rejects_empty_input():
    with pytest.raises(PaddingError):
        pkcs7_unpad(b"")


def test_rejects_length_not_multiple_of_block():
    with pytest.raises(PaddingError):
        pkcs7_unpad(b"1234567")  # 7 bytes


def test_rejects_zero_pad_byte():
    with pytest.raises(PaddingError):
        pkcs7_unpad(b"ABCDEFG\x00")


def test_rejects_pad_byte_larger_than_block():
    with pytest.raises(PaddingError):
        pkcs7_unpad(b"ABCDEFG\x09")  # 9 > 8


def test_rejects_inconsistent_padding_bytes():
    # It claims there are 3 padding bytes, but the three are not equal.
    with pytest.raises(PaddingError):
        pkcs7_unpad(b"ABCDE\x01\x03\x03")


def test_rejects_padding_that_is_almost_right():
    with pytest.raises(PaddingError):
        pkcs7_unpad(b"ABCD\x04\x04\x04\x05")


def test_padding_error_is_a_value_error():
    """PaddingError must also be catchable as a ValueError."""
    assert issubclass(PaddingError, ValueError)
    with pytest.raises(ValueError):
        pkcs7_unpad(b"ABCDEFG\x00")


@pytest.mark.parametrize("block_size", [0, -1, 256, 1000])
def test_rejects_invalid_block_size(block_size):
    with pytest.raises(ValueError):
        pkcs7_pad(b"hola", block_size)
    with pytest.raises(ValueError):
        pkcs7_unpad(b"hola" * 2, block_size)
