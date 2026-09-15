"""
The AES substitution box, computed from the field rather than tabulated.

Exercise 1: the S-box behind SubBytes. FIPS-197 section 5.1.1 defines it
as the composition of two maps applied to each byte:

    1. replace the byte by its multiplicative inverse in GF(2^8),
       with 0x00 mapped to itself;
    2. apply the affine transformation over GF(2)

           b'_i = b_i XOR b_(i+4) XOR b_(i+5) XOR b_(i+6) XOR b_(i+7) XOR c_i

       with indices taken modulo 8 and c = 0x63.

Writing it this way, instead of pasting the published 16x16 table, keeps
the implementation tied to `gf`: the substitution is a consequence of the
field arithmetic, not an independent constant. The published table lives
only in `tests/vectors.py`, where it acts as an external oracle.

The affine step is expressed with byte rotations. A left rotation by k
moves bit j to bit j+k, so the sum of rotations by 1, 2, 3 and 4 gives
exactly the b_(i+7), b_(i+6), b_(i+5) and b_(i+4) terms above.
"""

from .gf import inverse

__all__ = [
    "AFFINE_CONSTANT",
    "SBOX",
    "INV_SBOX",
    "sub_byte",
    "inv_sub_byte",
]

# c = 0x63, the constant of the affine transformation. It is the reason
# SBOX[0x00] is 0x63: the inverse of zero is zero, so only c survives.
AFFINE_CONSTANT = 0x63


def _rotate_left(value: int, amount: int) -> int:
    """Circular left shift of a byte."""
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def _affine_transform(value: int) -> int:
    """The affine map over GF(2) applied after the inversion."""
    return (
        value
        ^ _rotate_left(value, 1)
        ^ _rotate_left(value, 2)
        ^ _rotate_left(value, 3)
        ^ _rotate_left(value, 4)
        ^ AFFINE_CONSTANT
    )


def _build_sbox() -> tuple[int, ...]:
    """Invert in the field, then apply the affine transformation."""
    return tuple(_affine_transform(inverse(value)) for value in range(256))


def _invert_permutation(table: tuple[int, ...]) -> tuple[int, ...]:
    """
    Reverse a bijective byte table.

    The S-box is a permutation of the 256 bytes, so its inverse is
    obtained by reading the table backwards. Deriving InvSubBytes this
    way rather than re-deriving it algebraically makes it impossible for
    the two tables to disagree.
    """
    inverted = [0] * 256
    for index, value in enumerate(table):
        inverted[value] = index
    return tuple(inverted)


SBOX = _build_sbox()
INV_SBOX = _invert_permutation(SBOX)


def sub_byte(value: int) -> int:
    """Substitute a single byte through the S-box."""
    if not 0 <= value < 256:
        raise ValueError(f"value must be a byte in [0, 256), got {value}")
    return SBOX[value]


def inv_sub_byte(value: int) -> int:
    """Substitute a single byte through the inverse S-box."""
    if not 0 <= value < 256:
        raise ValueError(f"value must be a byte in [0, 256), got {value}")
    return INV_SBOX[value]
