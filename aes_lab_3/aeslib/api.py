"""
The public interface of the package: the `AES` class.

Exercise 1. Everything below this module is the algorithm; this is the
part a caller is meant to touch. Constructing an `AES` runs the key
schedule once, and the resulting round keys are reused for every block,
which is what the benchmark relies on to measure the cost of the core
rather than the cost of setting up a key.

The key length alone selects the variant:

    16 bytes -> AES-128, 10 rounds
    24 bytes -> AES-192, 12 rounds
    32 bytes -> AES-256, 14 rounds

Two backends compute the same function. `reference` is the literal
implementation of FIPS-197 in `cipher`, used for validation; `fast` is
the table-driven one in `fast`, used for the benchmark because the
reference core is far too slow to process 100 MB. The test suite
requires the two to agree byte for byte, so choosing a backend is a
performance decision and never a correctness one.

Encrypting applies the core to each block independently. That is raw
ECB and is NOT a secure mode of operation; see the note in `cipher`.
"""

from . import cipher
from .key_schedule import KEY_SIZES, number_of_rounds, round_keys
from .state import BLOCK_SIZE

__all__ = ["AES", "BACKENDS"]

# Registered backends. "fast" joins the tuple once `aeslib.fast` is
# part of the package; until then asking for it is a clean error
# rather than an import failure.
BACKENDS = ("reference",)

DEFAULT_BACKEND = "reference"


class AES:
    """
    An AES instance bound to one key.

    The key schedule is computed once, in the constructor. Blocks are
    then encrypted or decrypted with `encrypt_block` / `decrypt_block`,
    and whole buffers whose length is a multiple of the block size with
    `encrypt` / `decrypt`.
    """

    def __init__(self, key: bytes, backend: str = DEFAULT_BACKEND) -> None:
        if backend not in BACKENDS:
            raise ValueError(
                f"unknown backend {backend!r} (available: {', '.join(BACKENDS)})"
            )
        # Raises for any unsupported key length, before any other work.
        self.rounds = number_of_rounds(key)
        self.key = bytes(key)
        self.key_size = len(self.key) * 8
        self.backend = backend
        self.round_keys = round_keys(self.key)
        self._core = self._load_backend(backend)

    @staticmethod
    def _load_backend(name: str):
        """
        Return the module implementing the four core operations.

        The fast backend is imported on demand so that the reference
        path never pays for building its tables.
        """
        if name == "reference":
            return cipher
        from . import fast

        return fast

    # -- single blocks ------------------------------------------------

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt exactly one 16-byte block."""
        return self._core.encrypt_block(block, self.round_keys)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt exactly one 16-byte block."""
        return self._core.decrypt_block(block, self.round_keys)

    # -- whole buffers ------------------------------------------------

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt a buffer whose length is a multiple of the block size.

        No padding is applied and no mode of operation is used: the
        blocks are independent. This is the operation the benchmark
        measures.
        """
        return self._core.encrypt_buffer(data, self.round_keys)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt a buffer whose length is a multiple of the block size."""
        return self._core.decrypt_buffer(data, self.round_keys)

    # -- description --------------------------------------------------

    @property
    def name(self) -> str:
        """The variant in use, for example 'AES-192'."""
        return f"AES-{self.key_size}"

    def __repr__(self) -> str:
        return (
            f"AES(key_size={self.key_size}, rounds={self.rounds}, "
            f"backend={self.backend!r})"
        )


def _sanity_check() -> None:
    """Guard against the tables in `KEY_SIZES` and `BLOCK_SIZE` drifting."""
    assert set(KEY_SIZES) == {16, 24, 32}
    assert BLOCK_SIZE == 16


_sanity_check()
