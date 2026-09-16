"""
Tests for the AES round transformations.

Exercise 2, "AES transformations and their inverse operations". Three
kinds of check are used:

- agreement with the round-1 trace of FIPS-197 Appendix B, which fixes
  SubBytes, ShiftRows and MixColumns against the standard itself;
- the round trip of every transformation with its inverse, on random
  states, which is what decryption ultimately relies on;
- the structural properties each step exists to provide: which bytes it
  moves, and how far a single change propagates.
"""

import random

import pytest

from aeslib.state import BLOCK_SIZE, bytes_to_state, copy_state, state_to_bytes
from aeslib.transforms import (
    INV_MIX_COLUMNS_MATRIX,
    MIX_COLUMNS_MATRIX,
    add_round_key,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    sub_bytes,
)

from .vectors import (
    APPENDIX_B_ROUND1_AFTER_MIX_COLUMNS,
    APPENDIX_B_ROUND1_AFTER_SHIFT_ROWS,
    APPENDIX_B_ROUND1_AFTER_SUB_BYTES,
    APPENDIX_B_ROUND1_KEY,
    APPENDIX_B_ROUND1_START,
    MIX_COLUMNS_VECTORS,
)

_RANDOM = random.Random(20260915)
RANDOM_BLOCKS = [
    bytes(_RANDOM.randrange(256) for _ in range(BLOCK_SIZE)) for _ in range(50)
]

FORWARD_AND_INVERSE = [
    (sub_bytes, inv_sub_bytes),
    (shift_rows, inv_shift_rows),
    (mix_columns, inv_mix_columns),
]


def apply_to(block: bytes, transformation) -> bytes:
    """Run one transformation over a block and read the state back out."""
    state = bytes_to_state(block)
    transformation(state)
    return state_to_bytes(state)


# ---------------------------------------------------------------------------
# Agreement with the trace of FIPS-197 Appendix B
# ---------------------------------------------------------------------------


def test_sub_bytes_matches_the_appendix_b_trace():
    result = apply_to(APPENDIX_B_ROUND1_START, sub_bytes)
    assert result == APPENDIX_B_ROUND1_AFTER_SUB_BYTES


def test_shift_rows_matches_the_appendix_b_trace():
    result = apply_to(APPENDIX_B_ROUND1_AFTER_SUB_BYTES, shift_rows)
    assert result == APPENDIX_B_ROUND1_AFTER_SHIFT_ROWS


def test_mix_columns_matches_the_appendix_b_trace():
    result = apply_to(APPENDIX_B_ROUND1_AFTER_SHIFT_ROWS, mix_columns)
    assert result == APPENDIX_B_ROUND1_AFTER_MIX_COLUMNS


def test_a_whole_round_reproduces_the_appendix_b_trace():
    """The four steps chained in the order a round applies them."""
    state = bytes_to_state(APPENDIX_B_ROUND1_START)
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, APPENDIX_B_ROUND1_KEY)
    expected = bytes(
        a ^ b
        for a, b in zip(APPENDIX_B_ROUND1_AFTER_MIX_COLUMNS, APPENDIX_B_ROUND1_KEY)
    )
    assert state_to_bytes(state) == expected


# ---------------------------------------------------------------------------
# Each transformation against its inverse
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("forward, backward", FORWARD_AND_INVERSE)
@pytest.mark.parametrize("block", RANDOM_BLOCKS[:20])
def test_every_transformation_is_undone_by_its_inverse(forward, backward, block):
    state = bytes_to_state(block)
    original = copy_state(state)
    forward(state)
    backward(state)
    assert state == original


@pytest.mark.parametrize("forward, backward", FORWARD_AND_INVERSE)
@pytest.mark.parametrize("block", RANDOM_BLOCKS[:20])
def test_every_inverse_is_undone_by_its_forward_transformation(forward, backward, block):
    state = bytes_to_state(block)
    original = copy_state(state)
    backward(state)
    forward(state)
    assert state == original


@pytest.mark.parametrize("block", RANDOM_BLOCKS[:20])
def test_add_round_key_is_its_own_inverse(block):
    key = bytes(range(BLOCK_SIZE))
    state = bytes_to_state(block)
    original = copy_state(state)
    add_round_key(state, key)
    assert state != original
    add_round_key(state, key)
    assert state == original


# ---------------------------------------------------------------------------
# SubBytes
# ---------------------------------------------------------------------------


def test_sub_bytes_acts_on_each_byte_independently():
    """A change in one byte must not disturb any other byte."""
    substituted = apply_to(bytes(BLOCK_SIZE), sub_bytes)
    for position in range(BLOCK_SIZE):
        block = bytearray(BLOCK_SIZE)
        block[position] = 0xAB
        changed = apply_to(bytes(block), sub_bytes)
        differing = [i for i in range(BLOCK_SIZE) if substituted[i] != changed[i]]
        assert differing == [position]


# ---------------------------------------------------------------------------
# ShiftRows
# ---------------------------------------------------------------------------


def test_shift_rows_leaves_the_first_row_untouched():
    state = bytes_to_state(bytes(range(BLOCK_SIZE)))
    first_row = state[0][:]
    shift_rows(state)
    assert state[0] == first_row


def test_shift_rows_rotates_row_r_by_r_positions():
    state = bytes_to_state(bytes(range(BLOCK_SIZE)))
    before = copy_state(state)
    shift_rows(state)
    for row in range(4):
        assert state[row] == before[row][row:] + before[row][:row]


def test_shift_rows_only_permutes_the_bytes():
    block = RANDOM_BLOCKS[0]
    assert sorted(apply_to(block, shift_rows)) == sorted(block)


def test_inv_shift_rows_rotates_in_the_opposite_direction():
    state = bytes_to_state(bytes(range(BLOCK_SIZE)))
    before = copy_state(state)
    inv_shift_rows(state)
    assert state[0] == before[0]
    for row in range(1, 4):
        assert state[row] == before[row][-row:] + before[row][:-row]


def test_shift_rows_moves_bytes_between_columns():
    """
    The reason the step exists: without it every column would stay
    isolated and AES would be four independent 32-bit ciphers.
    """
    in_row_zero = bytes([0xFF] + [0x00] * 15)
    assert apply_to(in_row_zero, shift_rows) == in_row_zero

    in_row_one = bytes([0x00, 0xFF] + [0x00] * 14)
    shifted = apply_to(in_row_one, shift_rows)
    assert shifted.index(0xFF) // 4 != 0


# ---------------------------------------------------------------------------
# MixColumns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("column, expected", MIX_COLUMNS_VECTORS)
def test_mix_columns_matches_the_published_column_vectors(column, expected):
    """Every column of the state is transformed the same way."""
    assert apply_to(bytes(column) * 4, mix_columns) == bytes(expected) * 4


@pytest.mark.parametrize("column, expected", MIX_COLUMNS_VECTORS)
def test_inv_mix_columns_reverses_the_published_column_vectors(column, expected):
    assert apply_to(bytes(expected) * 4, inv_mix_columns) == bytes(column) * 4


def test_the_matrices_are_the_ones_of_the_specification():
    assert len(MIX_COLUMNS_MATRIX) == len(INV_MIX_COLUMNS_MATRIX) == 4
    assert MIX_COLUMNS_MATRIX[0] == (0x02, 0x03, 0x01, 0x01)
    assert INV_MIX_COLUMNS_MATRIX[0] == (0x0E, 0x0B, 0x0D, 0x09)


def test_mix_columns_treats_each_column_independently():
    """A change in one column must not reach any other column."""
    mixed = apply_to(bytes(BLOCK_SIZE), mix_columns)
    changed_block = bytearray(BLOCK_SIZE)
    changed_block[5] = 0x7A  # second column
    changed = apply_to(bytes(changed_block), mix_columns)
    differing_columns = {i // 4 for i in range(BLOCK_SIZE) if mixed[i] != changed[i]}
    assert differing_columns == {1}


def test_mix_columns_spreads_one_byte_over_its_whole_column():
    """
    The diffusion property: changing a single byte changes all four
    bytes of its column, because the matrix has no zero coefficient.
    """
    mixed = apply_to(bytes(BLOCK_SIZE), mix_columns)
    changed_block = bytearray(BLOCK_SIZE)
    changed_block[0] = 0x01
    changed = apply_to(bytes(changed_block), mix_columns)
    assert [i for i in range(4) if mixed[i] != changed[i]] == [0, 1, 2, 3]


# ---------------------------------------------------------------------------
# AddRoundKey
# ---------------------------------------------------------------------------


def test_add_round_key_xors_the_key_column_by_column():
    state = bytes_to_state(bytes(BLOCK_SIZE))
    key = bytes(range(BLOCK_SIZE))
    add_round_key(state, key)
    assert state_to_bytes(state) == key


def test_add_round_key_with_a_zero_key_changes_nothing():
    block = RANDOM_BLOCKS[0]
    state = bytes_to_state(block)
    add_round_key(state, bytes(BLOCK_SIZE))
    assert state_to_bytes(state) == block


@pytest.mark.parametrize("length", [0, 15, 17, 24])
def test_add_round_key_rejects_keys_of_the_wrong_length(length):
    state = bytes_to_state(bytes(BLOCK_SIZE))
    with pytest.raises(ValueError):
        add_round_key(state, bytes(length))


# ---------------------------------------------------------------------------
# The transformations mutate in place
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "transformation",
    [
        sub_bytes,
        inv_sub_bytes,
        shift_rows,
        inv_shift_rows,
        mix_columns,
        inv_mix_columns,
    ],
)
def test_transformations_return_none_and_mutate_the_state(transformation):
    state = bytes_to_state(RANDOM_BLOCKS[0])
    assert transformation(state) is None
    assert state != bytes_to_state(RANDOM_BLOCKS[0])
