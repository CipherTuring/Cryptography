"""
Tests for the 128-bit state representation.

Exercise 2. The column-major layout of FIPS-197 section 3.4 is easy to
get backwards, and a transposed state produces a cipher that is
internally consistent but matches no published vector, so it is pinned
down here explicitly rather than only implied by the cipher tests.
"""

import random

import pytest

from aeslib.state import (
    BLOCK_SIZE,
    NB,
    bytes_to_state,
    copy_state,
    format_state,
    state_to_bytes,
)

_RANDOM = random.Random(20260915)
RANDOM_BLOCKS = [
    bytes(_RANDOM.randrange(256) for _ in range(BLOCK_SIZE)) for _ in range(50)
]


def test_the_state_is_four_rows_of_four_bytes():
    state = bytes_to_state(bytes(BLOCK_SIZE))
    assert len(state) == 4
    assert all(len(row) == NB for row in state)


def test_the_block_is_read_column_by_column():
    """FIPS-197 section 3.4: s[r][c] = input[r + 4c]."""
    block = bytes(range(BLOCK_SIZE))
    state = bytes_to_state(block)
    for row in range(4):
        for col in range(NB):
            assert state[row][col] == block[row + 4 * col]


def test_the_first_four_bytes_form_the_first_column_not_the_first_row():
    state = bytes_to_state(bytes(range(BLOCK_SIZE)))
    assert [state[row][0] for row in range(4)] == [0, 1, 2, 3]
    assert state[0] != [0, 1, 2, 3]


@pytest.mark.parametrize("block", RANDOM_BLOCKS)
def test_state_to_bytes_inverts_bytes_to_state(block):
    assert state_to_bytes(bytes_to_state(block)) == block


def test_copy_state_is_independent_of_the_original():
    state = bytes_to_state(bytes(BLOCK_SIZE))
    duplicate = copy_state(state)
    duplicate[0][0] = 0xFF
    assert state[0][0] == 0x00


def test_format_state_prints_four_rows_of_hexadecimal():
    rendered = format_state(bytes_to_state(bytes(range(BLOCK_SIZE))))
    assert rendered.splitlines() == [
        "00 04 08 0c",
        "01 05 09 0d",
        "02 06 0a 0e",
        "03 07 0b 0f",
    ]


@pytest.mark.parametrize("length", [0, 1, 15, 17, 32])
def test_bytes_to_state_rejects_blocks_of_the_wrong_length(length):
    with pytest.raises(ValueError):
        bytes_to_state(bytes(length))
