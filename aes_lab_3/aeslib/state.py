"""
The AES state: the 128-bit block the round transformations operate on.

Exercise 1, "128-bit state representation". FIPS-197 section 3.4 lays the
16 bytes of a block out in a 4x4 array of bytes, filled *column by
column*:

    s[r][c] = input[r + 4c]

so the first four bytes of the block form the first column, not the
first row. This detail matters: ShiftRows operates on rows while the key
is applied by columns, and getting the order wrong produces a cipher
that is self-consistent but disagrees with every published test vector.

A state is represented as a list of four rows, each a list of four ints,
so that `state[r][c]` reads exactly like the s[r][c] of the standard.
The transformations in `transforms` mutate a state in place.
"""

__all__ = [
    "BLOCK_SIZE",
    "NB",
    "bytes_to_state",
    "state_to_bytes",
    "copy_state",
    "format_state",
]

# A block is always 128 bits in AES, for every key size.
BLOCK_SIZE = 16

# Number of columns of the state. Rijndael allowed other values; AES
# fixes it at 4.
NB = 4

State = list[list[int]]


def bytes_to_state(block: bytes) -> State:
    """
    Lay a 16-byte block out as a 4x4 state, column by column.

    Raises ValueError if the block is not exactly `BLOCK_SIZE` bytes.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(
            f"a block must be exactly {BLOCK_SIZE} bytes, got {len(block)}"
        )
    return [[block[row + 4 * col] for col in range(NB)] for row in range(4)]


def state_to_bytes(state: State) -> bytes:
    """Read a state back out, column by column: the inverse of `bytes_to_state`."""
    return bytes(state[row][col] for col in range(NB) for row in range(4))


def copy_state(state: State) -> State:
    """Independent copy, so that a transformation cannot alter the original."""
    return [row[:] for row in state]


def format_state(state: State) -> str:
    """
    Render a state as four rows of hexadecimal, for demos and debugging.

    The layout matches the way FIPS-197 prints the state, which makes it
    easy to compare a run against the traces of the standard.
    """
    return "\n".join(" ".join(f"{byte:02x}" for byte in row) for row in state)
