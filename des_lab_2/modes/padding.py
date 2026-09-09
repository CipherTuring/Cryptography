"""
PKCS#7 padding (RFC 5652 §6.3) for the DES block size.

If `p` bytes are missing to complete the last block, `p` copies of the
byte whose numeric value is `p` are appended. When the message already
spans an exact number of blocks, a full block of padding is appended
(`p = block_size`), so the padding is never empty and `pkcs7_unpad` is an
exact inverse of `pkcs7_pad`.
"""

from .blocks import BLOCK_SIZE

__all__ = ["PaddingError", "pkcs7_pad", "pkcs7_unpad"]


class PaddingError(ValueError):
    """Invalid PKCS#7 padding. Subclass of ValueError."""


def _validate_block_size(block_size: int) -> None:
    if not isinstance(block_size, int) or isinstance(block_size, bool):
        raise TypeError("block_size debe ser un entero")
    if not 1 <= block_size <= 255:
        # The padding byte stores `p`, so p cannot exceed 255.
        raise ValueError(f"block_size debe estar en [1, 255], se recibió {block_size}")


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Append PKCS#7 padding to `data`.

    The result is always longer than the input: if `len(data)` is already
    a multiple of `block_size`, a full block of padding is added.
    """
    _validate_block_size(block_size)
    pad_len = block_size - (len(data) % block_size)  # always in [1, block_size]
    return bytes(data) + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Strip the PKCS#7 padding from `data`, validating it.

    Raises `PaddingError` (a subclass of `ValueError`) if the padding is
    invalid: empty message, length not a multiple of the block, padding
    byte outside [1, block_size], or inconsistent padding bytes.
    """
    _validate_block_size(block_size)

    if len(data) == 0:
        raise PaddingError("mensaje vacío: no hay relleno PKCS#7 que quitar")
    if len(data) % block_size != 0:
        raise PaddingError(
            f"la longitud ({len(data)}) no es múltiplo del bloque ({block_size})"
        )

    pad_len = data[-1]
    if not 1 <= pad_len <= block_size:
        raise PaddingError(
            f"byte de relleno inválido: {pad_len} (debe estar en [1, {block_size}])"
        )
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise PaddingError(
            f"los últimos {pad_len} bytes no son todos 0x{pad_len:02x}"
        )
    return bytes(data[:-pad_len])
