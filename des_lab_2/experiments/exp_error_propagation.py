"""
Exercise 6: error propagation in ECB and CBC.

Encrypts a five-block message in both modes, flips exactly one bit of the
ciphertext and decrypts the altered result, measuring which plaintext
blocks change and by how many bits.

Decryption uses the `*_blocks` variants (without stripping the padding):
flipping one bit of the ciphertext destroys the PKCS#7 padding with very
high probability, and what matters here is the raw plaintext, not the
recovered message.
"""

from modes import (
    des_cbc_decrypt_blocks,
    des_cbc_encrypt,
    des_ecb_decrypt_blocks,
    des_ecb_encrypt,
)

from .common import Report, blocks_of, flip_bit, hamming_blocks, printable

KEY = bytes.fromhex("133457799BBCDFF1")
IV = bytes.fromhex("A1B2C3D4E5F60718")
# 40 bytes = exactly 5 blocks; after PKCS#7 they become 6 blocks.
PLAINTEXT = b"BLOQUE01BLOQUE02BLOQUE03BLOQUE04BLOQUE05"

# Flipped bit: block 2 (index 1), first byte, most significant bit.
CORRUPT_BLOCK = 1
CORRUPT_BYTE_IN_BLOCK = 0
CORRUPT_BIT = 0


def _analyse(name, original_plain, corrupted_plain):
    per_block = hamming_blocks(original_plain, corrupted_plain)
    changed = [i + 1 for i, d in enumerate(per_block) if d > 0]
    return {
        "mode": name,
        "diff_bits_per_block": per_block,
        "changed_blocks": changed,
        "total_diff_bits": sum(per_block),
    }


def run(echo: bool = True):
    byte_index = CORRUPT_BLOCK * 8 + CORRUPT_BYTE_IN_BLOCK

    ecb_ct = des_ecb_encrypt(KEY, PLAINTEXT)
    cbc_ct = des_cbc_encrypt(KEY, PLAINTEXT, IV)

    ecb_bad = flip_bit(ecb_ct, byte_index, CORRUPT_BIT)
    cbc_bad = flip_bit(cbc_ct, byte_index, CORRUPT_BIT)

    ecb_plain = des_ecb_decrypt_blocks(KEY, ecb_ct)
    ecb_plain_bad = des_ecb_decrypt_blocks(KEY, ecb_bad)
    cbc_plain = des_cbc_decrypt_blocks(KEY, cbc_ct, IV)
    cbc_plain_bad = des_cbc_decrypt_blocks(KEY, cbc_bad, IV)

    ecb_stats = _analyse("ECB", ecb_plain, ecb_plain_bad)
    cbc_stats = _analyse("CBC", cbc_plain, cbc_plain_bad)
    n_blocks = len(blocks_of(ecb_ct))

    report = Report("Ejercicio 6 — Propagación de error en ECB y CBC")
    report.line(f"Llave K       : {KEY.hex().upper()}")
    report.line(f"IV (solo CBC) : {IV.hex().upper()}")
    report.line(f"Texto plano   : {PLAINTEXT.decode()}  ({len(PLAINTEXT)} bytes)")
    report.line(f"Criptograma   : {n_blocks} bloques tras PKCS#7")
    report.line(
        f"Bit alterado  : bloque {CORRUPT_BLOCK + 1}, byte {CORRUPT_BYTE_IN_BLOCK} "
        f"(offset {byte_index}), bit {CORRUPT_BIT} contando desde el MSB "
        f"— exactamente 1 bit de todo el criptograma"
    )

    for stats, plain, plain_bad in (
        (ecb_stats, ecb_plain, ecb_plain_bad),
        (cbc_stats, cbc_plain, cbc_plain_bad),
    ):
        report.section(f"{stats['mode']}: descifrado del criptograma alterado")
        report.line(f"{'i':>2}  {'P_i original':<12} {'P_i alterado':<12} "
                    f"{'bits distintos':>14}")
        for i, (a, b, d) in enumerate(
            zip(blocks_of(plain), blocks_of(plain_bad), stats["diff_bits_per_block"]),
            start=1,
        ):
            mark = "  <--" if d else ""
            report.line(
                f"{i:>2}  {printable(a):<12} {printable(b):<12} {d:>14}{mark}"
            )
        report.line()
        report.line(f"bloques afectados : {stats['changed_blocks']}")
        report.line(f"bits alterados    : {stats['total_diff_bits']} "
                    f"de {len(plain) * 8} en todo el mensaje")

    report.section("Comparación con el comportamiento teórico")
    report.line(
        f"ECB — teoría: P_i = D_K(C_i) no depende de ningún otro bloque, así que\n"
        f"  un bit alterado en C_i corrompe ÚNICAMENTE P_i, y por el efecto\n"
        f"  avalancha de DES lo corrompe por completo (~32 de 64 bits, la mitad\n"
        f"  en promedio). El error NO se propaga.\n"
        f"  Medido: bloques {ecb_stats['changed_blocks']}, "
        f"{ecb_stats['total_diff_bits']} bits alterados.\n"
        f"\n"
        f"CBC — teoría: P_i = D_K(C_i) XOR C_(i-1), de modo que C_i interviene en\n"
        f"  dos bloques de texto plano y en ninguno más:\n"
        f"    · P_i     queda completamente corrompido (avalancha de D_K).\n"
        f"    · P_(i+1) cambia EXACTAMENTE en el mismo bit que se alteró en C_i,\n"
        f"      porque ahí C_i entra por XOR directo, sin pasar por DES.\n"
        f"    · P_(i+2) en adelante quedan intactos: el error NO se propaga más\n"
        f"      allá de dos bloques (CBC es auto-sincronizante).\n"
        f"  Medido: bloques {cbc_stats['changed_blocks']}, "
        f"{cbc_stats['total_diff_bits']} bits alterados "
        f"({cbc_stats['diff_bits_per_block'][CORRUPT_BLOCK]} en P_{CORRUPT_BLOCK + 1} "
        f"y {cbc_stats['diff_bits_per_block'][CORRUPT_BLOCK + 1]} en P_{CORRUPT_BLOCK + 2}).\n"
        f"\n"
        f"Ninguno de los dos modos detecta la alteración: ambos entregan texto\n"
        f"plano corrupto sin señalar error. La integridad requiere un MAC o un\n"
        f"modo autenticado; el relleno PKCS#7 no sirve para eso, y usar su\n"
        f"validación como señal de error es justamente lo que abre los ataques\n"
        f"de oráculo de relleno."
    )

    report.data = {
        "key": KEY.hex().upper(),
        "iv": IV.hex().upper(),
        "plaintext": PLAINTEXT.decode(),
        "corrupted_block_index": CORRUPT_BLOCK + 1,
        "corrupted_byte_offset": byte_index,
        "corrupted_bit_from_msb": CORRUPT_BIT,
        "ecb": ecb_stats,
        "cbc": cbc_stats,
    }
    report.emit("exp6_error_propagation", echo=echo)
    return report


if __name__ == "__main__":
    from console import use_utf8_stdout

    use_utf8_stdout()
    run()
