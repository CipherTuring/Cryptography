"""
The four round transformations of AES and their inverses.

Exercise 1: SubBytes, ShiftRows, MixColumns and AddRoundKey, each as a
separate named function so that the structure of a round is visible in
the code rather than folded into a table.

Every function mutates the state in place and returns None, mirroring
the pseudocode of FIPS-197, where a round is a sequence of statements
applied to a single state.

The three layers do different jobs, and the split is deliberate:

- SubBytes is the non-linear layer; it works on each byte independently.
- ShiftRows moves bytes between columns, so that MixColumns cannot keep
  treating the same four bytes together round after round.
- MixColumns mixes the four bytes of a column; combined with ShiftRows
  it is what spreads a single-byte difference over the whole block.
- AddRoundKey is the only step that involves the key.
"""

from .gf import mul
from .sbox import INV_SBOX, SBOX
from .state import BLOCK_SIZE, NB, State

__all__ = [
    "MIX_COLUMNS_MATRIX",
    "INV_MIX_COLUMNS_MATRIX",
    "sub_bytes",
    "inv_sub_bytes",
    "shift_rows",
    "inv_shift_rows",
    "mix_columns",
    "inv_mix_columns",
    "add_round_key",
]


# MixColumns treats each column as a polynomial over GF(2^8) and
# multiplies it by a(x) = {03}x^3 + {01}x^2 + {01}x + {02}, modulo
# x^4 + 1. That product is the circulant matrix below.
MIX_COLUMNS_MATRIX = (
    (0x02, 0x03, 0x01, 0x01),
    (0x01, 0x02, 0x03, 0x01),
    (0x01, 0x01, 0x02, 0x03),
    (0x03, 0x01, 0x01, 0x02),
)

# The inverse polynomial a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}.
# Its coefficients are larger, which is why InvMixColumns is the most
# expensive step of decryption.
INV_MIX_COLUMNS_MATRIX = (
    (0x0E, 0x0B, 0x0D, 0x09),
    (0x09, 0x0E, 0x0B, 0x0D),
    (0x0D, 0x09, 0x0E, 0x0B),
    (0x0B, 0x0D, 0x09, 0x0E),
)


# ---------------------------------------------------------------------------
# SubBytes
# ---------------------------------------------------------------------------


def sub_bytes(state: State) -> None:
    """Replace every byte of the state by its image under the S-box."""
    for row in range(4):
        current = state[row]
        for col in range(NB):
            current[col] = SBOX[current[col]]


def inv_sub_bytes(state: State) -> None:
    """Undo `sub_bytes` using the inverse S-box."""
    for row in range(4):
        current = state[row]
        for col in range(NB):
            current[col] = INV_SBOX[current[col]]


# ---------------------------------------------------------------------------
# ShiftRows
# ---------------------------------------------------------------------------


def shift_rows(state: State) -> None:
    """
    Rotate row r of the state r positions to the left.

    Row 0 is left untouched. Without this step the four columns would
    never interact and AES would reduce to four independent 32-bit
    ciphers.
    """
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]


def inv_shift_rows(state: State) -> None:
    """Rotate row r of the state r positions to the right."""
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]


# ---------------------------------------------------------------------------
# MixColumns
# ---------------------------------------------------------------------------


def _mix_columns_with(state: State, matrix: tuple[tuple[int, ...], ...]) -> None:
    """
    Multiply every column of the state by a fixed 4x4 matrix over GF(2^8).

    MixColumns and InvMixColumns differ only in the matrix, so they share
    this routine: the forward and inverse steps cannot drift apart.
    """
    for col in range(NB):
        column = (state[0][col], state[1][col], state[2][col], state[3][col])
        for row in range(4):
            coefficients = matrix[row]
            state[row][col] = (
                mul(coefficients[0], column[0])
                ^ mul(coefficients[1], column[1])
                ^ mul(coefficients[2], column[2])
                ^ mul(coefficients[3], column[3])
            )


def mix_columns(state: State) -> None:
    """Mix the four bytes of each column, as a product in GF(2^8)[x]/(x^4+1)."""
    _mix_columns_with(state, MIX_COLUMNS_MATRIX)


def inv_mix_columns(state: State) -> None:
    """Undo `mix_columns` by multiplying with the inverse polynomial."""
    _mix_columns_with(state, INV_MIX_COLUMNS_MATRIX)


# ---------------------------------------------------------------------------
# AddRoundKey
# ---------------------------------------------------------------------------


def add_round_key(state: State, round_key: bytes) -> None:
    """
    XOR a 16-byte round key into the state, column by column.

    The round key is read with the same column-major convention as the
    block, so byte `r + 4c` of the key meets `state[r][c]`. Being a XOR,
    the step is its own inverse, which is why decryption needs no
    separate InvAddRoundKey.
    """
    if len(round_key) != BLOCK_SIZE:
        raise ValueError(
            f"a round key must be exactly {BLOCK_SIZE} bytes, got {len(round_key)}"
        )
    for row in range(4):
        current = state[row]
        for col in range(NB):
            current[col] ^= round_key[row + 4 * col]
