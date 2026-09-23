"""
Generation of the RSA moduli the experiments are run on.

Part IV needs moduli of several bit sizes and Part V needs pairs of
primes at a controlled distance from each other. Both are produced here,
from an explicit seed, so that every number in `results/` can be
regenerated exactly. Reproducibility is the point: a benchmark whose
inputs change between runs cannot be compared with itself.

Two rules the assignment sets are respected by construction:

- nothing is hard-coded. The primes are searched for at run time, and
  the factorization algorithms are only ever handed `n`;
- no library factors anything. Miller-Rabin decides *whether* a number
  is prime without producing a factor, which is a different question
  from the one Part I answers and is the standard way key generation
  works in real RSA implementations.

`RsaModulus` keeps p and q next to n, but only so the experiments can
report |p - q| and verify what the algorithms return. The algorithms
themselves receive the modulus alone.
"""

import random
from dataclasses import dataclass

__all__ = [
    "RsaModulus",
    "is_probable_prime",
    "random_prime",
    "next_prime",
    "generate_modulus",
    "modulus_with_gap",
]

# Enough to be deterministic for every n below 3.3 * 10^24, which
# covers all the primes this laboratory generates by a wide margin.
MILLER_RABIN_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


@dataclass(frozen=True, slots=True)
class RsaModulus:
    """A modulus together with the factors it was built from."""

    n: int
    p: int
    q: int

    def __post_init__(self) -> None:
        if self.p * self.q != self.n:
            raise ValueError(f"{self.p} * {self.q} is not {self.n}")
        if self.p > self.q:
            raise ValueError(f"the factors must be ordered, got {self.p} > {self.q}")

    @property
    def bits(self) -> int:
        """Size of the modulus, which is what the benchmark indexes by."""
        return self.n.bit_length()

    @property
    def gap(self) -> int:
        """|p - q|, the quantity Part V plots Fermat's cost against."""
        return self.q - self.p


def is_probable_prime(n: int) -> bool:
    """
    Miller-Rabin with fixed bases.

    Writes n - 1 as d * 2^s and checks, for each base a, whether the
    sequence a^d, a^2d, a^4d, ... reaches -1 before it reaches 1. A
    composite cannot fool all twelve bases below 3.3 * 10^24, so the
    test is deterministic in the range used here.

    It answers "is this prime", never "what are its factors": a witness
    proves compositeness without revealing anything that could be
    divided out. That is why using it here does not violate the rule
    against libraries that factor n.
    """
    if n < 2:
        return False
    for base in MILLER_RABIN_BASES:
        if n % base == 0:
            return n == base

    d = n - 1
    exponent = 0
    while d % 2 == 0:
        d //= 2
        exponent += 1

    for base in MILLER_RABIN_BASES:
        value = pow(base, d, n)
        if value in (1, n - 1):
            continue
        for _ in range(exponent - 1):
            value = value * value % n
            if value == n - 1:
                break
        else:
            return False
    return True


def next_prime(start: int) -> int:
    """The smallest prime greater than or equal to `start`."""
    candidate = max(start, 2)
    if candidate == 2:
        return 2
    if candidate % 2 == 0:
        candidate += 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate


def random_prime(bits: int, rng: random.Random) -> int:
    """
    A random prime of exactly `bits` bits.

    The top bit is forced so the size is exact - a prime one bit short
    would make the product smaller than the experiment asked for - and
    the bottom bit is forced because no even candidate above 2 is worth
    testing.
    """
    if bits < 2:
        raise ValueError(f"a prime needs at least 2 bits, got {bits}")
    if bits == 2:
        return rng.choice([2, 3])

    low = 1 << (bits - 1)
    high = (1 << bits) - 1
    while True:
        candidate = rng.randrange(low, high) | low | 1
        if is_probable_prime(candidate):
            return candidate


def generate_modulus(bits: int, seed: int) -> RsaModulus:
    """
    An RSA modulus of exactly `bits` bits, from two distinct primes of
    roughly half that size.

    Two half-size primes multiply to a number of either `bits` or
    `bits - 1` bits depending on how the leading digits fall, so the
    draw is repeated until the size is exactly the one requested. The
    benchmark indexes its rows by bit size, and a row labelled 40 bits
    holding a 39-bit modulus would misreport the experiment.
    """
    if bits < 6:
        raise ValueError(f"a modulus of {bits} bits is too small to be a product")

    rng = random.Random(seed)
    high_bits = (bits + 1) // 2
    low_bits = bits - high_bits

    while True:
        p = random_prime(low_bits, rng)
        q = random_prime(high_bits, rng)
        if p == q:
            continue
        if p > q:
            p, q = q, p
        if (p * q).bit_length() == bits:
            return RsaModulus(n=p * q, p=p, q=q)


def modulus_with_gap(bits: int, gap: int, seed: int) -> RsaModulus:
    """
    A modulus of about `bits` bits whose factors are roughly `gap` apart.

    The instrument of Part V. `p` is drawn just below sqrt(2^bits) and
    `q` is the first prime at or above `p + gap`, so the requested
    distance is a target and the real one - always available as
    `RsaModulus.gap` - is whatever the primes allow. It is never smaller
    than the target and, by the density of primes in this range, rarely
    more than a few hundred above it.

    The exact bit size is not forced here: pinning both the size and the
    distance would over-constrain the search, and Part V compares moduli
    of *similar* size at different distances, which is what the
    assignment asks for.
    """
    if gap < 1:
        raise ValueError(f"the gap must be positive, got {gap}")

    rng = random.Random(seed)
    half = bits // 2
    p = random_prime(half, rng)
    q = next_prime(p + gap)
    return RsaModulus(n=p * q, p=p, q=q)
