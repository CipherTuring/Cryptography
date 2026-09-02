"""
Rutina genérica de permutación/selección para DES.

Toda la representación principal del estado de DES se maneja como enteros
de Python (no como strings de '0'/'1'). Las tablas de la especificación
FIPS PUB 46-3 usan numeración 1-based, donde la posición 1 corresponde
al bit MÁS significativo (MSB) del valor de entrada.
"""


def permute(value: int, table: tuple[int, ...], input_width: int) -> int:
    """
    Aplica una tabla de permutación/selección de DES (numerada 1..input_width,
    bit 1 = MSB) sobre `value`, que se interpreta como un entero de
    `input_width` bits.

    Devuelve un entero de `len(table)` bits, construido colocando en la
    posición i de salida (de izquierda a derecha) el bit de entrada indicado
    por table[i].
    """
    result = 0
    for position in table:
        # position es 1-based y cuenta desde el MSB.
        bit = (value >> (input_width - position)) & 1
        result = (result << 1) | bit
    return result


def rotate_left(value: int, shift: int, width: int) -> int:
    """Rotación circular a la izquierda de `value` (de `width` bits)."""
    shift %= width
    mask = (1 << width) - 1
    value &= mask
    return ((value << shift) | (value >> (width - shift))) & mask
