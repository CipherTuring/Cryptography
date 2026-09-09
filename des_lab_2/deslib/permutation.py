"""
Generic permutation/selection routine for DES.

The main representation of the DES state is handled as Python integers
(not as '0'/'1' strings). The tables from the FIPS PUB 46-3 spec use
1-based numbering, where position 1 corresponds to the MOST significant
bit (MSB) of the input value.
"""


def permute(value: int, table: tuple[int, ...], input_width: int) -> int:
    """
    Apply a DES permutation/selection table (numbered 1..input_width,
    bit 1 = MSB) to `value`, which is interpreted as an `input_width`-bit
    integer.

    Returns a `len(table)`-bit integer, built by placing at output
    position i (left to right) the input bit indicated by table[i].
    """
    result = 0
    for position in table:
        # position is 1-based and counts from the MSB.
        bit = (value >> (input_width - position)) & 1
        result = (result << 1) | bit
    return result


def rotate_left(value: int, shift: int, width: int) -> int:
    """Circular left rotation of `value` (a `width`-bit value)."""
    shift %= width
    mask = (1 << width) - 1
    value &= mask
    return ((value << shift) | (value >> (width - shift))) & mask
