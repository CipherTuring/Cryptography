"""
Block helpers shared by the modes of operation.

DES operates on 64-bit = 8-byte blocks; `BLOCK_SIZE` is the single source
of truth for that size across `padding.py`, `ecb.py` and `cbc.py`.
"""

BLOCK_SIZE = 8

__all__ = ["BLOCK_SIZE", "split_blocks", "xor_bytes"]


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """
    Split `data` into blocks of `block_size` bytes.

    The length of `data` must be an exact multiple of `block_size`;
    padding is the responsibility of `padding.py`.
    """
    if len(data) % block_size != 0:
        raise ValueError(
            f"la longitud debe ser múltiplo de {block_size} bytes, "
            f"se recibieron {len(data)}"
        )
    return [bytes(data[i : i + block_size]) for i in range(0, len(data), block_size)]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Byte-wise XOR of two sequences of equal length."""
    if len(a) != len(b):
        raise ValueError(
            f"XOR requiere longitudes iguales, se recibieron {len(a)} y {len(b)}"
        )
    return bytes(x ^ y for x, y in zip(a, b))
