"""
Integer arithmetic the three factorization algorithms are built on.

Four primitives, each one required by the assignment and each one used
by something else in the laboratory:

    gcd                Pollard's Rho: a factor of n is gcd(|x - y|, n)
    modinv             key recovery:  d = e^-1 mod phi(n)
    isqrt              Trial Division stops at sqrt(n); Fermat starts there
    is_perfect_square  Fermat's stopping condition: b^2 = a^2 - n

Everything here is exact integer arithmetic. `math.sqrt` is deliberately
absent: it returns a 64-bit float with 53 bits of mantissa, so beyond
about 9e15 it answers with a rounded value, and both Trial Division and
Fermat would then read the wrong bound and silently miss a factor. The
standard library does offer `math.gcd`, `math.isqrt` and the three
argument `pow(x, -1, m)`, but the assignment asks for these to be
implemented and tested, so they are written out here; the standard
versions appear only inside the tests, as an independent oracle.
"""

__all__ = ["gcd", "egcd", "modinv", "isqrt", "is_perfect_square"]


def gcd(a: int, b: int) -> int:
    """
    Greatest common divisor of `a` and `b`, by Euclid's algorithm.

    Each step replaces (a, b) with (b, a mod b), which preserves the set
    of common divisors and strictly shrinks the second argument, so the
    loop ends at (gcd, 0). Iterative rather than recursive: Pollard's Rho
    calls this once per iteration, millions of times, and Python's
    recursion limit and call overhead are both real costs there.

    The result is always non-negative. `gcd(0, 0)` is 0.
    """
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclid: return `(g, x, y)` with `g = gcd(a, b)` and

        a*x + b*y = g.

    Bezout's identity is what makes the modular inverse computable: with
    `b = m` and `g = 1` the equation reads `a*x = 1 - m*y`, that is
    `a*x = 1 (mod m)`, so `x` is the inverse of `a`.

    The coefficients are carried alongside the remainders: every row of
    the table satisfies the identity, so the row where the remainder
    reaches the gcd carries the coefficients we want.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """
    Modular inverse: the unique `x` in `[0, m)` with `a*x = 1 (mod m)`.

    Raises `ValueError` when `gcd(a, m) != 1`, because then no inverse
    exists. This is not a corner case to paper over: in RSA it means the
    public exponent `e` shares a factor with `phi(n)` and the key pair is
    invalid, which the key generator has to detect rather than produce.
    """
    if m <= 0:
        raise ValueError(f"the modulus must be positive, got {m}")
    divisor, x, _ = egcd(a % m, m)
    if divisor != 1:
        raise ValueError(
            f"{a} has no inverse modulo {m}: gcd({a}, {m}) = {divisor}"
        )
    return x % m


def isqrt(n: int) -> int:
    """
    Integer square root: the largest `r >= 0` with `r*r <= n`.

    Newton's method on f(r) = r^2 - n, run entirely in integers. The
    iteration `r <- (r + n//r) // 2` converges from above, so the first
    time it stops decreasing the previous value is the answer.

    The starting point is `2^ceil(bits/2)`, which is guaranteed to be at
    or above the true root because `n < 2^bits`. Starting above matters:
    the descent is monotone from there, and `y >= x` is then a correct
    stopping test rather than a heuristic.

    Exact for integers of any size, which is the whole reason this
    exists instead of `int(math.sqrt(n))`.
    """
    if n < 0:
        raise ValueError(f"square root of a negative number: {n}")
    if n < 2:
        return n

    estimate = 1 << ((n.bit_length() + 1) // 2)
    while True:
        better = (estimate + n // estimate) // 2
        if better >= estimate:
            return estimate
        estimate = better


def is_perfect_square(n: int) -> bool:
    """
    Whether `n` is the square of an integer.

    Fermat's stopping condition, and the reason `isqrt` has to be exact:
    the test is `isqrt(n)^2 == n`, so a root that is off by one would
    either miss the factorization or report one that does not hold.

    Negative numbers are not squares, and 0 and 1 are.
    """
    if n < 0:
        return False
    root = isqrt(n)
    return root * root == n
