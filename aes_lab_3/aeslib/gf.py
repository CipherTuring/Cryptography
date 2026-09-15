"""
Arithmetic in GF(2^8), the finite field every AES transformation is
defined over.

Exercise 1: "arithmetic in GF(2^8) using the AES irreducible polynomial".
A byte is read as a polynomial whose coefficients are its bits, so 0x57
is x^6 + x^4 + x^2 + x + 1. Addition is the XOR of coefficients, and
multiplication is polynomial multiplication reduced modulo

    m(x) = x^8 + x^4 + x^3 + x + 1      (0x11B)

which is irreducible over GF(2) and therefore turns the 256 bytes into a
field: every non-zero element has a multiplicative inverse.

This module is the *only* place where the field is implemented. The
S-box, MixColumns and the T-tables of the fast backend are all built on
top of these functions, so there is no cryptographic constant written by
hand anywhere in the package.
"""

__all__ = [
    "IRREDUCIBLE",
    "GENERATOR",
    "FIELD_SIZE",
    "MULTIPLICATIVE_ORDER",
    "add",
    "xtime",
    "mul",
    "inverse",
]

# x^8 + x^4 + x^3 + x + 1, the polynomial fixed by FIPS-197 section 4.2.
IRREDUCIBLE = 0x11B

# 0x03 (the polynomial x + 1) is a primitive element: its 255 powers run
# through every non-zero byte, which is what makes the log/antilog tables
# below usable to compute inverses.
GENERATOR = 0x03

FIELD_SIZE = 256
MULTIPLICATIVE_ORDER = FIELD_SIZE - 1


def _check_byte(value: int, name: str) -> None:
    """Reject anything that is not an element of the field."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if not 0 <= value < FIELD_SIZE:
        raise ValueError(f"{name} must be a byte in [0, 256), got {value}")


def _xtime(a: int) -> int:
    """`xtime` without argument checking, for use inside this module."""
    shifted = a << 1
    if shifted & 0x100:
        # Degree reached 8: reduce modulo m(x). The XOR clears bit 8 and
        # folds x^8 back into x^4 + x^3 + x + 1.
        shifted ^= IRREDUCIBLE
    return shifted


def _mul(a: int, b: int) -> int:
    """`mul` without argument checking, for use inside this module."""
    product = 0
    while b:
        if b & 1:
            product ^= a
        a = _xtime(a)
        b >>= 1
    return product


def _build_log_tables() -> tuple[tuple[int, ...], tuple[int, ...]]:
    """
    Antilog and log tables for the generator, used to invert elements.

    Walking the powers of `GENERATOR` visits every non-zero byte exactly
    once, so `antilog[i]` is the i-th power and `log` is its inverse map.
    """
    antilog = [0] * MULTIPLICATIVE_ORDER
    log = [0] * FIELD_SIZE
    value = 1
    for power in range(MULTIPLICATIVE_ORDER):
        antilog[power] = value
        log[value] = power
        value = _mul(value, GENERATOR)
    return tuple(antilog), tuple(log)


_ANTILOG, _LOG = _build_log_tables()


def add(a: int, b: int) -> int:
    """
    Sum of two field elements.

    The characteristic of the field is 2, so addition and subtraction are
    the same operation: the XOR of the coefficients.
    """
    _check_byte(a, "a")
    _check_byte(b, "b")
    return a ^ b


def xtime(a: int) -> int:
    """
    Multiply by x, that is, by 0x02.

    Shifting left raises every exponent by one; if the result reaches
    degree 8 it is reduced modulo the irreducible polynomial. This is the
    primitive MixColumns is written in terms of.
    """
    _check_byte(a, "a")
    return _xtime(a)


def mul(a: int, b: int) -> int:
    """
    Product of two field elements, modulo the irreducible polynomial.

    Implemented as shift-and-add: `b` is scanned bit by bit and, for every
    bit set, the running double of `a` is accumulated into the result.
    """
    _check_byte(a, "a")
    _check_byte(b, "b")
    return _mul(a, b)


def inverse(a: int) -> int:
    """
    Multiplicative inverse, computed through the log tables.

    Since a = g^log(a), its inverse is g^(255 - log(a)). Zero has no
    inverse; AES maps it to itself when building the S-box, and that
    convention is followed here.
    """
    _check_byte(a, "a")
    if a == 0:
        return 0
    return _ANTILOG[(MULTIPLICATIVE_ORDER - _LOG[a]) % MULTIPLICATIVE_ORDER]
