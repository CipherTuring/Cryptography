"""
Exercise 4: ECB versus CBC with a plaintext of repeated blocks.

Encrypts "ABCDEFGH" repeated four times (32 bytes = 4 identical blocks) in
both modes and compares the resulting ciphertext blocks.
"""

from modes import BLOCK_SIZE, des_cbc_encrypt, des_ecb_encrypt
from modes.padding import pkcs7_pad

from .common import Report, blocks_of, printable

KEY = bytes.fromhex("133457799BBCDFF1")
IV = bytes.fromhex("0001020304050607")
PLAINTEXT = b"ABCDEFGH" * 4


def run(echo: bool = True):
    padded = pkcs7_pad(PLAINTEXT, BLOCK_SIZE)
    ecb = des_ecb_encrypt(KEY, PLAINTEXT)
    cbc = des_cbc_encrypt(KEY, PLAINTEXT, IV)

    p_blocks = blocks_of(padded)
    e_blocks = blocks_of(ecb)
    c_blocks = blocks_of(cbc)

    report = Report("Ejercicio 4 — ECB frente a CBC con bloques repetidos")
    report.line(f"Llave K       : {KEY.hex().upper()}")
    report.line(f"IV (solo CBC) : {IV.hex().upper()}")
    report.line(f"Texto plano   : {PLAINTEXT.decode()}  ({len(PLAINTEXT)} bytes)")
    report.line(
        f"Tras PKCS#7   : {len(padded)} bytes = {len(p_blocks)} bloques "
        f"(el bloque {len(p_blocks)} es relleno completo 0808080808080808)"
    )

    report.section("Representación a nivel de bloque")
    report.line(f"{'i':>2}  {'P_i (ASCII)':<12} {'P_i (hex)':<18} "
                f"{'C_i ECB':<18} {'C_i CBC':<18}")
    for i, (p, e, c) in enumerate(zip(p_blocks, e_blocks, c_blocks), start=1):
        report.line(
            f"{i:>2}  {printable(p):<12} {p.hex().upper():<18} "
            f"{e.hex().upper():<18} {c.hex().upper():<18}"
        )

    ecb_unique = len(set(e_blocks))
    cbc_unique = len(set(c_blocks))
    ecb_repeats_visible = ecb_unique < len(e_blocks)
    cbc_repeats_visible = cbc_unique < len(c_blocks)

    report.section("Bloques de criptograma distintos")
    report.line(f"ECB: {ecb_unique} distintos de {len(e_blocks)}  ->  "
                f"los 4 bloques de texto plano iguales producen 4 criptogramas "
                f"{'IGUALES' if ecb_repeats_visible else 'distintos'}")
    report.line(f"CBC: {cbc_unique} distintos de {len(c_blocks)}  ->  "
                f"{'se repiten bloques' if cbc_repeats_visible else 'todos los bloques son distintos'}")

    report.section("Discusión")
    report.line(
        "ECB es una función sin estado: C_i = E_K(P_i) depende únicamente de P_i.\n"
        "Como P_1 = P_2 = P_3 = P_4, necesariamente C_1 = C_2 = C_3 = C_4. El\n"
        "criptograma filtra así el patrón de repetición del texto plano — un\n"
        "adversario deduce dónde se repiten bloques sin recuperar la llave.\n"
        "\n"
        "CBC introduce estado: C_i = E_K(P_i XOR C_{i-1}), con C_0 = IV. Aunque\n"
        "P_i se repita, la entrada real del cifrado incluye C_{i-1}, que cambia\n"
        "en cada posición. Bloques de texto plano idénticos producen entonces\n"
        "bloques de criptograma distintos y el patrón queda oculto."
    )

    report.data = {
        "key": KEY.hex().upper(),
        "iv": IV.hex().upper(),
        "plaintext_ascii": PLAINTEXT.decode(),
        "plaintext_blocks": [b.hex().upper() for b in p_blocks],
        "ecb_blocks": [b.hex().upper() for b in e_blocks],
        "cbc_blocks": [b.hex().upper() for b in c_blocks],
        "ecb_unique_blocks": ecb_unique,
        "cbc_unique_blocks": cbc_unique,
        "ecb_leaks_repetition": ecb_repeats_visible,
        "cbc_leaks_repetition": cbc_repeats_visible,
    }
    report.emit("exp4_ecb_vs_cbc", echo=echo)
    return report


if __name__ == "__main__":
    from console import use_utf8_stdout

    use_utf8_stdout()
    run()
