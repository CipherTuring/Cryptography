"""
Exercise 5: effect of the initialization vector in CBC.

Encrypts the same plaintext with the same key and two different IVs, and
checks that the ciphertexts differ. It also shows what happens when
decrypting with the wrong IV.
"""

from modes import des_cbc_decrypt_blocks, des_cbc_encrypt
from modes.padding import pkcs7_pad

from .common import Report, blocks_of, hamming_blocks, hamming_bytes, printable

KEY = bytes.fromhex("133457799BBCDFF1")
IV1 = bytes.fromhex("0000000000000000")
IV2 = bytes.fromhex("0000000000000001")  # differs from IV1 in a single bit
PLAINTEXT = b"Mensaje identico cifrado dos veces con la misma llave."


def run(echo: bool = True):
    c1 = des_cbc_encrypt(KEY, PLAINTEXT, IV1)
    c2 = des_cbc_encrypt(KEY, PLAINTEXT, IV2)

    b1 = blocks_of(c1)
    b2 = blocks_of(c2)
    per_block = hamming_blocks(c1, c2)
    total_diff = hamming_bytes(c1, c2)

    report = Report("Ejercicio 5 — Efecto del vector de inicialización en CBC")
    report.line(f"Llave K     : {KEY.hex().upper()}")
    report.line(f"IV_1        : {IV1.hex().upper()}")
    report.line(f"IV_2        : {IV2.hex().upper()}   "
                f"(difiere de IV_1 en {hamming_bytes(IV1, IV2)} bit)")
    report.line(f"Texto plano : {PLAINTEXT.decode()}")
    report.line(f"              {len(PLAINTEXT)} bytes -> "
                f"{len(pkcs7_pad(PLAINTEXT))} bytes tras PKCS#7 = {len(b1)} bloques")

    report.section("C_1 = E_CBC(K, P, IV_1)  frente a  C_2 = E_CBC(K, P, IV_2)")
    report.line(f"{'i':>2}  {'C_i con IV_1':<18} {'C_i con IV_2':<18} {'bits distintos':>14}")
    for i, (x, y, d) in enumerate(zip(b1, b2, per_block), start=1):
        report.line(f"{i:>2}  {x.hex().upper():<18} {y.hex().upper():<18} {d:>14}")

    report.line()
    report.line(f"C_1 != C_2                 : {c1 != c2}")
    report.line(f"bits distintos en total    : {total_diff} de {len(c1) * 8}"
                f"  ({total_diff / (len(c1) * 8):.1%})")

    # Decrypt C_1 with the wrong IV: only the first block gets corrupted.
    wrong = des_cbc_decrypt_blocks(KEY, c1, IV2)
    right = des_cbc_decrypt_blocks(KEY, c1, IV1)
    wrong_per_block = hamming_blocks(right, wrong)

    report.section("Descifrar C_1 con el IV equivocado (IV_2)")
    report.line(f"{'i':>2}  {'P_i correcto':<28} {'P_i con IV erróneo':<28} {'bits':>5}")
    for i, (r, w, d) in enumerate(
        zip(blocks_of(right), blocks_of(wrong), wrong_per_block), start=1
    ):
        report.line(f"{i:>2}  {printable(r):<28} {printable(w):<28} {d:>5}")
    report.line()
    report.line(
        "Solo P_1 se ve afectado, y exactamente en los mismos bits en que\n"
        "difieren los dos IVs: en CBC, P_1 = D_K(C_1) XOR IV, así que un IV\n"
        "erróneo se propaga al texto plano por XOR, bit a bit, y no afecta a\n"
        "ningún bloque posterior."
    )

    report.section("Discusión")
    report.line(
        "El IV hace que el cifrado sea PROBABILÍSTICO. Sin él, CBC sería una\n"
        "función determinista de (K, P): cifrar dos veces el mismo mensaje con\n"
        "la misma llave daría el mismo criptograma, y un adversario que observa\n"
        "el canal podría detectar mensajes repetidos, construir un diccionario\n"
        "de criptogramas conocidos o detectar que dos sesiones transmiten el\n"
        "mismo contenido — todo sin recuperar la llave.\n"
        "\n"
        "Con un IV distinto por mensaje, el mismo par (K, P) produce\n"
        "criptogramas distintos y esa fuga desaparece. Nótese que el IV NO es\n"
        "secreto (el receptor lo necesita para descifrar y suele viajar en\n"
        "claro junto al criptograma), pero sí debe ser IMPREDECIBLE para el\n"
        "adversario: si puede predecir el IV del próximo mensaje, puede montar\n"
        "un ataque de texto plano elegido y verificar conjeturas sobre P_1.\n"
        "Por eso `modes.cbc.random_iv()` usa `os.urandom`."
    )

    report.data = {
        "key": KEY.hex().upper(),
        "iv1": IV1.hex().upper(),
        "iv2": IV2.hex().upper(),
        "plaintext": PLAINTEXT.decode(),
        "ciphertext_iv1": c1.hex().upper(),
        "ciphertext_iv2": c2.hex().upper(),
        "ciphertexts_differ": c1 != c2,
        "diff_bits_per_block": per_block,
        "diff_bits_total": total_diff,
        "total_bits": len(c1) * 8,
        "wrong_iv_diff_bits_per_block": wrong_per_block,
    }
    report.emit("exp5_iv_effect", echo=echo)
    return report


if __name__ == "__main__":
    from console import use_utf8_stdout

    use_utf8_stdout()
    run()
