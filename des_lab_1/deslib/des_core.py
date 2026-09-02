"""
Núcleo de bloque de DES: opera sobre un único bloque de 64 bits.

Este módulo solo contiene operaciones criptográficas puras (enteros
adentro, enteros afuera). No imprime, no lee archivos ni entrada de
teclado; eso es responsabilidad de código fuera del núcleo (ver api.py
y cualquier script de línea de comandos).
"""

from .feistel import des_round
from .permutation import permute
from .tables import FP, IP


def des_block(block: int, subkeys: list[int]) -> int:
    """
    Procesa un bloque de 64 bits a través de las 16 rondas Feistel,
    usando `subkeys` en el orden dado.

    Para cifrar: pasar subkeys = [k1, k2, ..., k16].
    Para descifrar: pasar subkeys = [k16, k15, ..., k1] (lista invertida).

    Orden: IP -> 16 rondas -> R16||L16 (swap final) -> IP^-1.
    """
    permuted = permute(block, IP, 64)
    L = (permuted >> 32) & 0xFFFFFFFF
    R = permuted & 0xFFFFFFFF

    for k in subkeys:
        L, R = des_round(L, R, k)

    # Swap final: después de la ronda 16 NO se intercambian L y R,
    # por lo que el pre-output es R16 || L16.
    pre_output = (R << 32) | L
    return permute(pre_output, FP, 64)
