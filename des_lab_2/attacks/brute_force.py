"""
Known-plaintext attack by exhaustive key search (sequential).

The attacker knows a plaintext block P and its encryption C = E_K(P) but
does not know K. A candidate K' is correct if E_K'(P) = C.

The search uses the Laboratory 1 DES unmodified: it calls
`des_key_schedule` + `des_block` (the internal path of
`des_encrypt_block`) to avoid repeating, for every candidate, the length
validation and the bytes <-> integer conversions, which are identical
across all 2^n iterations.

A note on false positives: with a single 64-bit (P, C) pair and a space
of 2^n candidates with n <= 24, the probability that a wrong key produces
the same ciphertext is of the order of 2^(n-64) ~ 10^-12, so in practice
the first hit is the key. `verify_key` allows confirming it with extra
pairs.
"""

import argparse
import random
import time
from dataclasses import dataclass

from deslib import des_encrypt_block
from deslib.des_core import des_block
from deslib.key_schedule import des_key_schedule

from .keyspace import EFFECTIVE_BITS, KeySpace, add_parity_bits

__all__ = ["SearchResult", "brute_force_des", "make_challenge", "verify_key"]

# How often (in candidates) the shared stop signal is polled. A large
# chunk amortizes the cost of the poll; a small one reduces the delay
# with which the parallel workers stop after a hit.
DEFAULT_CHUNK = 4096


@dataclass
class SearchResult:
    """Result of an exhaustive search over an interval [start, end)."""

    found: bool
    candidate: int | None
    key: bytes | None
    tested: int
    elapsed: float
    start: int
    end: int

    @property
    def throughput(self) -> float:
        """Keys tested per second, R = N_tested / T."""
        return self.tested / self.elapsed if self.elapsed > 0 else float("nan")

    def summary(self) -> str:
        lines = [
            f"intervalo:   [{self.start}, {self.end})",
            f"candidatos:  {self.tested}",
            f"tiempo:      {self.elapsed:.3f} s",
            f"throughput:  {self.throughput:,.1f} llaves/s",
        ]
        if self.found:
            assert self.key is not None and self.candidate is not None
            fraction = (self.candidate - self.start) / max(self.end - self.start, 1)
            lines += [
                f"llave:       {self.key.hex().upper()}",
                f"candidato:   {self.candidate}  ({fraction:.1%} del intervalo)",
            ]
        else:
            lines.append("llave:       NO ENCONTRADA en el intervalo")
        return "\n".join(lines)


def make_challenge(
    keyspace: KeySpace,
    plaintext: bytes,
    candidate: int | None = None,
    seed: int | None = None,
) -> tuple[bytes, bytes, int]:
    """
    Build a challenge (key, ciphertext, candidate) inside `keyspace`.

    If `candidate` is None one is chosen at random using `seed`. The key
    is never passed to the searcher: it is only used to generate C and to
    verify the result at the end.
    """
    if candidate is None:
        candidate = random.Random(seed).randrange(keyspace.size)
    key = keyspace.key(candidate)
    return key, des_encrypt_block(key, plaintext), candidate


def verify_key(key: bytes, pairs: list[tuple[bytes, bytes]]) -> bool:
    """True if `key` correctly encrypts every given (P, C) pair."""
    return all(des_encrypt_block(key, p) == c for p, c in pairs)


def brute_force_des(
    plaintext: bytes,
    ciphertext: bytes,
    start: int,
    end: int,
    keyspace: KeySpace | None = None,
    stop_event=None,
    chunk: int = DEFAULT_CHUNK,
) -> SearchResult:
    """
    Search for the DES key by testing every candidate in [start, end).

    `keyspace` defines the candidate -> DES key mapping; if omitted, the
    full 56-bit space is used, where the candidate integer IS the
    effective key. The search stops as soon as it finds a match, or when
    `stop_event` (an optional `multiprocessing.Event`) is set because
    another worker already found the key.
    """
    if keyspace is None:
        keyspace = KeySpace(unknown_bits=EFFECTIVE_BITS)
    if len(plaintext) != 8 or len(ciphertext) != 8:
        raise ValueError("el texto plano y el criptograma deben medir 8 bytes")
    if not 0 <= start <= end <= keyspace.size:
        raise ValueError(
            f"intervalo inválido [{start}, {end}) para un espacio de {keyspace.size}"
        )

    # Precomputation outside the hot loop: the known bits of the key and
    # the integer representations of the (P, C) pair.
    base_high = keyspace.base_key56 & ~keyspace.mask
    plain_int = int.from_bytes(plaintext, "big")
    target_int = int.from_bytes(ciphertext, "big")

    # Local names, to avoid attribute lookups on every iteration.
    parity = add_parity_bits
    schedule = des_key_schedule
    encrypt_block = des_block

    found: int | None = None
    tested = 0
    position = start
    clock = time.perf_counter
    t0 = clock()

    while position < end and found is None:
        if stop_event is not None and stop_event.is_set():
            break
        limit = min(position + chunk, end)
        for candidate in range(position, limit):
            tested += 1
            key = parity(base_high | candidate)
            if encrypt_block(plain_int, schedule(key)) == target_int:
                found = candidate
                break
        position = limit

    elapsed = clock() - t0

    return SearchResult(
        found=found is not None,
        candidate=found,
        key=keyspace.key(found) if found is not None else None,
        tested=tested,
        elapsed=elapsed,
        start=start,
        end=end,
    )


def _main() -> None:
    from console import use_utf8_stdout

    use_utf8_stdout()
    parser = argparse.ArgumentParser(
        description="Ataque de texto plano conocido a DES por búsqueda exhaustiva "
        "secuencial sobre un espacio de llaves reducido."
    )
    parser.add_argument(
        "-n", "--bits", type=int, default=16,
        help="bits efectivos desconocidos de la llave (por defecto: 16)",
    )
    parser.add_argument(
        "--base", type=lambda s: int(s, 0), default=0,
        help="valor de los 56 bits efectivos conocidos (por defecto: 0)",
    )
    parser.add_argument(
        "--plaintext", default="0123456789ABCDEF",
        help="bloque de texto plano conocido, en hexadecimal (8 bytes)",
    )
    parser.add_argument(
        "--candidate", type=int, default=None,
        help="posición exacta de la llave en el espacio (por defecto: aleatoria)",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="semilla para elegir la posición de la llave de forma reproducible",
    )
    args = parser.parse_args()

    keyspace = KeySpace(unknown_bits=args.bits, base_key56=args.base)
    plaintext = bytes.fromhex(args.plaintext)
    secret_key, ciphertext, candidate = make_challenge(
        keyspace, plaintext, candidate=args.candidate, seed=args.seed
    )

    print(keyspace.describe())
    print(f"texto plano conocido: {plaintext.hex().upper()}")
    print(f"criptograma conocido: {ciphertext.hex().upper()}")
    print(f"(la llave secreta está en el candidato {candidate}; el buscador no la ve)\n")

    result = brute_force_des(plaintext, ciphertext, 0, keyspace.size, keyspace=keyspace)
    print(result.summary())

    ok = result.found and result.key == secret_key
    print(f"\nllave recuperada correctamente: {ok}")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    _main()
