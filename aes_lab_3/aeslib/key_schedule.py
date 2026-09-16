"""
The AES key schedule, for 128-, 192- and 256-bit keys.

Exercise 1, "Key Schedule for AES-128, AES-192 and AES-256". FIPS-197
section 5.2 expands the cipher key into 4 * (Nr + 1) words of 32 bits,
consumed four at a time as the round keys.

The expansion is a *single* algorithm parameterised by Nk, the length of
the key in words:

    Nk = 4  ->  AES-128, Nr = 10, 44 words
    Nk = 6  ->  AES-192, Nr = 12, 52 words
    Nk = 8  ->  AES-256, Nr = 14, 60 words

with Nr = Nk + 6 in every case. The three versions share the same code;
the only branch specific to a key size is the extra SubWord applied when
Nk > 6, which exists because with eight-word keys the non-linear step
would otherwise be applied too rarely to mix the key material properly.

Note that the round keys do not have to line up with the words of the
key. For AES-192 a round key is four words while the key is six, so
round keys straddle the boundaries of the expansion; reading them as a
flat stream of words, as `round_keys` does, handles the three sizes
uniformly.
"""

from .gf import xtime
from .sbox import SBOX
from .state import BLOCK_SIZE, NB

__all__ = [
    "KEY_SIZES",
    "RCON",
    "Word",
    "rot_word",
    "sub_word",
    "number_of_rounds",
    "expand_key",
    "round_keys",
]

Word = tuple[int, int, int, int]

# Supported key lengths in bytes, mapped to their number of rounds.
# More key material means more rounds, and that is where the cost
# difference between the three versions comes from.
KEY_SIZES = {16: 10, 24: 12, 32: 14}

# The number of words of the key, Nk, determines everything else.
_WORD_SIZE = 4


def _build_round_constants(count: int) -> tuple[int, ...]:
    """
    Successive powers of x in GF(2^8): 0x01, 0x02, 0x04, ..., 0x36.

    Rcon[j] is the word (x^(j-1), 0, 0, 0). Only the leading byte varies,
    so the constants are kept as bytes. They are generated with `xtime`
    rather than written out, for the same reason the S-box is: nothing
    in this package is a pasted cryptographic constant.

    Index 0 is an unused placeholder, so that `RCON[j]` can be read with
    the same j the specification uses.
    """
    constants = [0x00]
    value = 0x01
    for _ in range(count):
        constants.append(value)
        value = xtime(value)
    return tuple(constants)


# AES-128 needs the most constants: i / Nk reaches 10 there.
RCON = _build_round_constants(10)


def rot_word(word: Word) -> Word:
    """Rotate a word one byte to the left: (a0, a1, a2, a3) -> (a1, a2, a3, a0)."""
    return (word[1], word[2], word[3], word[0])


def sub_word(word: Word) -> Word:
    """Apply the S-box to each of the four bytes of a word."""
    return (SBOX[word[0]], SBOX[word[1]], SBOX[word[2]], SBOX[word[3]])


def _xor_words(left: Word, right: Word) -> Word:
    """Bytewise XOR of two words."""
    return (
        left[0] ^ right[0],
        left[1] ^ right[1],
        left[2] ^ right[2],
        left[3] ^ right[3],
    )


def _validate_key(key: bytes) -> int:
    """Check the key length and return its number of words, Nk."""
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"the key must be bytes, got {type(key).__name__}")
    if len(key) not in KEY_SIZES:
        supported = ", ".join(str(size) for size in sorted(KEY_SIZES))
        raise ValueError(
            f"unsupported key length: {len(key)} bytes "
            f"(AES accepts {supported} bytes)"
        )
    return len(key) // _WORD_SIZE


def number_of_rounds(key: bytes) -> int:
    """Number of rounds for this key: 10, 12 or 14."""
    _validate_key(key)
    return KEY_SIZES[len(key)]


def expand_key(key: bytes) -> tuple[Word, ...]:
    """
    Expand a cipher key into 4 * (Nr + 1) words.

    The first Nk words are the key itself. Each later word is the XOR of
    the word Nk positions earlier and a transformed copy of its
    immediate predecessor; the transformation is what stops the schedule
    from being a plain repetition of the key.
    """
    nk = _validate_key(key)
    rounds = KEY_SIZES[len(key)]
    total_words = NB * (rounds + 1)

    words: list[Word] = [
        (
            key[_WORD_SIZE * i],
            key[_WORD_SIZE * i + 1],
            key[_WORD_SIZE * i + 2],
            key[_WORD_SIZE * i + 3],
        )
        for i in range(nk)
    ]

    for i in range(nk, total_words):
        temp = words[i - 1]
        if i % nk == 0:
            # Once per Nk words: rotate, substitute, and add the round
            # constant. The constant is what makes the rounds differ from
            # one another and breaks the symmetry of the schedule.
            temp = _xor_words(sub_word(rot_word(temp)), (RCON[i // nk], 0, 0, 0))
        elif nk > 6 and i % nk == 4:
            # AES-256 only: with eight-word keys the branch above fires
            # half as often per word, so an extra substitution keeps the
            # non-linearity of the schedule comparable.
            temp = sub_word(temp)
        words.append(_xor_words(words[i - nk], temp))

    return tuple(words)


def round_keys(key: bytes) -> list[bytes]:
    """
    Group the expanded key into Nr + 1 round keys of 16 bytes each.

    Read as a flat stream of words, so that the three key sizes are
    handled identically even when a round key straddles the boundaries
    of the original key words, as happens with AES-192.
    """
    words = expand_key(key)
    keys = []
    for start in range(0, len(words), NB):
        chunk = words[start : start + NB]
        keys.append(bytes(byte for word in chunk for byte in word))
    assert all(len(item) == BLOCK_SIZE for item in keys)
    return keys
