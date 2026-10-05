"""
Part II: turning a factorization into a private key.

This module is short on purpose. Factoring n was the whole difficulty;
once p and q are known, everything that follows is a few lines of
modular arithmetic, and that is precisely the point the laboratory is
making. The security of RSA rests on one step, and it is not this one.

The chain is:

    phi(n) = (p - 1)(q - 1)      what only the owner of the factors knows
    d      = e^-1 mod phi(n)     the private exponent
    m      = c^d mod n           the plaintext

RSA itself is not re-implemented here. Encryption and decryption *are*
`pow(m, e, n)` and `pow(c, d, n)`: the three-argument form of the
built-in does modular exponentiation by repeated squaring, in time
logarithmic in the exponent and without ever building the astronomically
large intermediate `c^d`. What is implemented by hand is `modinv`, in
`factorlib.arith`, because that is where the mathematics of the attack
lives and the assignment asks for it to be tested.
"""

from dataclasses import dataclass

from factorlib.arith import modinv

from .keygen import is_probable_prime

__all__ = [
    "PublicKey",
    "PrivateKey",
    "totient",
    "private_exponent",
    "encrypt",
    "decrypt",
    "recover_private_key",
]


@dataclass(frozen=True, slots=True)
class PublicKey:
    """The pair (n, e) anyone may hold."""

    n: int
    e: int

    def encrypt(self, message: int) -> int:
        return encrypt(message, self.e, self.n)


@dataclass(frozen=True, slots=True)
class PrivateKey:
    """
    The pair (n, d) the attack reconstructs.

    Note what it does not contain: p, q or phi(n). They were needed to
    build d and are of no further use, which is why a real key pair can
    discard them and why recovering the message needs nothing else.
    """

    n: int
    d: int

    def decrypt(self, ciphertext: int) -> int:
        return decrypt(ciphertext, self.d, self.n)


def totient(p: int, q: int) -> int:
    """
    Euler's totient of n = pq, the count of integers below n coprime
    with it: (p - 1)(q - 1).

    This is the quantity an attacker cannot compute from n alone. With
    the factorization it is a subtraction and a multiplication, and the
    private key follows immediately - which is the answer to the last
    question of the experimental analysis.

    Both arguments are verified to be prime, because the formula holds
    only then. A factorization algorithm returns some non-trivial
    divisor and the cofactor that is left, and that cofactor need not be
    prime: 191730 splits as 2 * 95865, which is a correct factorization
    of a number that is not an RSA modulus at all. Feeding those two
    here would produce a number that is not phi(191730), and therefore a
    private exponent that decrypts nothing - silently. Refusing is the
    only honest answer, since no key exists to recover.
    """
    if p < 2 or q < 2:
        raise ValueError(f"the factors must be primes, got p = {p}, q = {q}")
    composite = [factor for factor in (p, q) if not is_probable_prime(factor)]
    if composite:
        listed = " and ".join(str(factor) for factor in composite)
        raise ValueError(
            f"the factors must be primes, but {listed} "
            f"{'are' if len(composite) > 1 else 'is'} composite: "
            f"{p} * {q} = {p * q} is not a product of two primes, "
            "so it carries no RSA key to recover"
        )
    return (p - 1) * (q - 1)


def private_exponent(e: int, phi: int) -> int:
    """
    The private exponent: the inverse of `e` modulo `phi(n)`.

    `e * d = 1 (mod phi)` is exactly what makes decryption undo
    encryption, by Euler's theorem: raising to `e` and then to `d`
    raises to `1 + k*phi`, and `m^phi = 1 (mod n)` for m coprime with n.

    Raises `ValueError` when `e` and `phi` share a factor, in which case
    no inverse exists and the key pair is invalid.
    """
    return modinv(e, phi)


def encrypt(message: int, e: int, n: int) -> int:
    """c = m^e mod n."""
    _check_range(message, n, "message")
    return pow(message, e, n)


def decrypt(ciphertext: int, d: int, n: int) -> int:
    """m = c^d mod n."""
    _check_range(ciphertext, n, "ciphertext")
    return pow(ciphertext, d, n)


def recover_private_key(public: PublicKey, p: int, q: int) -> PrivateKey:
    """
    Rebuild the private key from the public key and the factors.

    The three steps of Exercise 4 in one call: check that the factors
    really are the factors, compute phi(n), invert e modulo it.
    """
    if p * q != public.n:
        raise ValueError(
            f"{p} * {q} = {p * q}, which is not the modulus {public.n}"
        )
    return PrivateKey(n=public.n, d=private_exponent(public.e, totient(p, q)))


def _check_range(value: int, n: int, label: str) -> None:
    """
    RSA operates on integers in [0, n).

    Outside that range the arithmetic still runs but the result is
    meaningless: `pow` reduces modulo n, so a message at or above n
    would come back as a different number and decryption would silently
    return the wrong plaintext. Better to refuse than to lie.
    """
    if not 0 <= value < n:
        raise ValueError(
            f"the {label} must lie in [0, {n}), got {value}; "
            "RSA cannot represent it under this modulus"
        )
