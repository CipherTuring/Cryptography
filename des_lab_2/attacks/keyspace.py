"""
Construction of the controlled key space for the exhaustive search.

Full mapping:  candidate integer  ->  56 effective bits  ->  64-bit DES key

1. `candidate` is an integer in [0, 2^n), where n = `unknown_bits`.

2. The n bits of the candidate are inserted into the n LEAST significant
   bits of a 56-bit effective key; the remaining 56 - n bits are taken
   from `base_key56`, which is public and fixed for the whole attack:

       key56 = (base_key56 & ~mask) | (candidate & mask),   mask = 2^n - 1

3. The 56 effective bits are expanded into the 8 bytes of a DES key by
   inserting the parity bits. The 56 bits are read from MSB to LSB in
   groups of 7; each group occupies the high 7 bits of a byte, and the
   least significant bit of that byte is chosen so that the byte has ODD
   PARITY, which is the DES convention (FIPS PUB 46-3):

       key56 = g0 g1 g2 g3 g4 g5 g6 g7        (8 groups of 7 bits)
       byte_i = (g_i << 1) | parity_bit(g_i)

   This step is a bijection between the 2^56 effective values and the
   2^56 64-bit DES keys with correct parity; `strip_parity_bits` inverts
   it. Note that DES discards the parity bits in PC-1, so two keys that
   differ only in them encrypt identically: that is why the real search
   space is 2^56 and not 2^64.

The unknown bits are deliberately the least significant ones so that the
`range(start, end)` traversal is contiguous and trivial to split across
several workers.
"""

from dataclasses import dataclass

__all__ = [
    "EFFECTIVE_BITS",
    "KEY_BYTES",
    "KeySpace",
    "add_parity_bits",
    "strip_parity_bits",
    "has_odd_parity",
]

KEY_BYTES = 8
EFFECTIVE_BITS = 56

# _PARITY7[v] = the 8-bit byte whose high 7 bits are v and whose least
# significant bit completes the odd parity of the byte.
_PARITY7 = tuple(
    (v << 1) | (0 if bin(v).count("1") % 2 == 1 else 1) for v in range(128)
)


def has_odd_parity(key: bytes) -> bool:
    """True if the 8 bytes of `key` have odd parity (DES convention)."""
    return all(bin(byte).count("1") % 2 == 1 for byte in key)


def add_parity_bits(key56: int) -> bytes:
    """
    Expand 56 effective bits into an 8-byte DES key with odd parity.

    Inverse of `strip_parity_bits`.
    """
    if not 0 <= key56 < (1 << EFFECTIVE_BITS):
        raise ValueError(f"key56 debe ser un entero de {EFFECTIVE_BITS} bits")
    # Group i is bits [49 - 7i, 55 - 7i] counting from the LSB, that is
    # the i-th group of 7 bits reading from MSB to LSB.
    return bytes(_PARITY7[(key56 >> (49 - 7 * i)) & 0x7F] for i in range(KEY_BYTES))


def strip_parity_bits(key: bytes) -> int:
    """
    Extract the 56 effective bits from an 8-byte DES key.

    Discards the parity bit (the least significant one) of every byte,
    without checking it. Inverse of `add_parity_bits`.
    """
    if len(key) != KEY_BYTES:
        raise ValueError(f"la llave debe tener {KEY_BYTES} bytes, se recibieron {len(key)}")
    key56 = 0
    for byte in key:
        key56 = (key56 << 7) | (byte >> 1)
    return key56


@dataclass(frozen=True)
class KeySpace:
    """
    Reduced key space with `unknown_bits` unknown effective bits.

    `base_key56` fixes the 56 - n known bits (its n low bits are
    irrelevant: they are overwritten by the candidate). It is immutable
    and serializable, so it can be sent to child processes with
    `multiprocessing`.
    """

    unknown_bits: int
    base_key56: int = 0

    def __post_init__(self) -> None:
        if not 1 <= self.unknown_bits <= EFFECTIVE_BITS:
            raise ValueError(
                f"unknown_bits debe estar en [1, {EFFECTIVE_BITS}], "
                f"se recibió {self.unknown_bits}"
            )
        if not 0 <= self.base_key56 < (1 << EFFECTIVE_BITS):
            raise ValueError(f"base_key56 debe ser un entero de {EFFECTIVE_BITS} bits")

    @property
    def mask(self) -> int:
        """Mask of the unknown bits inside the effective key."""
        return (1 << self.unknown_bits) - 1

    @property
    def size(self) -> int:
        """Number of candidates in the space: 2^unknown_bits."""
        return 1 << self.unknown_bits

    def key56(self, candidate: int) -> int:
        """The 56-bit effective key corresponding to `candidate`."""
        if not 0 <= candidate < self.size:
            raise ValueError(
                f"candidato fuera del espacio [0, {self.size}): {candidate}"
            )
        return (self.base_key56 & ~self.mask) | candidate

    def key(self, candidate: int) -> bytes:
        """The 8-byte DES key (with parity) corresponding to `candidate`."""
        return add_parity_bits(self.key56(candidate))

    def candidate_of(self, key: bytes) -> int:
        """
        Index of the candidate that generates `key`.

        Raises `ValueError` if `key` does not belong to this space, that
        is if its known bits do not match `base_key56`.
        """
        key56 = strip_parity_bits(key)
        if (key56 & ~self.mask) != (self.base_key56 & ~self.mask):
            raise ValueError("la llave no pertenece a este espacio de búsqueda")
        return key56 & self.mask

    def contains(self, key: bytes) -> bool:
        """True if `key` belongs to this search space."""
        try:
            self.candidate_of(key)
        except ValueError:
            return False
        return True

    def describe(self) -> str:
        """One-line description, for logs and reports."""
        return (
            f"KeySpace(n={self.unknown_bits} bits desconocidos, "
            f"{self.size} candidatos, base_key56=0x{self.base_key56:014X})"
        )
