"""
Guided demonstration of deslib + the modes of operation.

All the printing / I/O lives here and in the scripts of `experiments/` and
`benchmarks/`, outside the cryptographic modules (`deslib.*`, `modes.*`,
`attacks.*`), just as the assignment requires.

    python demo.py
"""

from attacks import KeySpace, brute_force_des, make_challenge
from console import use_utf8_stdout
from deslib import des_decrypt_block, des_encrypt_block, des_key_schedule
from modes import (
    des_cbc_decrypt,
    des_cbc_encrypt,
    des_ecb_decrypt,
    des_ecb_encrypt,
    pkcs7_pad,
    pkcs7_unpad,
    split_blocks,
)

KEY = bytes.fromhex("133457799BBCDFF1")
IV = bytes.fromhex("0001020304050607")


def section(title: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))


def demo_block_cipher() -> None:
    """Lab 1: the classic DES test vector is still correct."""
    section("1. Cifrador de bloque DES (Laboratorio 1)")
    plaintext = bytes.fromhex("0123456789ABCDEF")
    expected = "85E813540F0AB405"

    subkeys = des_key_schedule(KEY)
    ciphertext = des_encrypt_block(KEY, plaintext)

    print(f"Llave K              : {KEY.hex().upper()}")
    print(f"Texto plano P        : {plaintext.hex().upper()}")
    print(f"k1                   : {subkeys[0]:012X}")
    print(f"k16                  : {subkeys[15]:012X}")
    print(f"E_K(P) obtenido      : {ciphertext.hex().upper()}")
    print(f"E_K(P) esperado      : {expected}")
    assert ciphertext.hex().upper() == expected
    assert des_decrypt_block(KEY, ciphertext) == plaintext
    print("OK: coincide con el vector conocido y D_K(E_K(P)) = P")


def demo_padding() -> None:
    section("2. Relleno PKCS#7 (Ejercicio 1)")
    for message in (bytes.fromhex("4142434445"), b"12345678", b""):
        padded = pkcs7_pad(message)
        print(f"{message.hex() or '(vacío)':<20} -> {padded.hex()}  "
              f"({len(message)} -> {len(padded)} bytes)")
        assert pkcs7_unpad(padded) == message
    print("OK: unpad(pad(M)) = M en todos los casos")


def demo_ecb_vs_cbc() -> None:
    section("3. ECB frente a CBC con bloques repetidos (Ejercicios 2-4)")
    plaintext = b"ABCDEFGH" * 4
    ecb = des_ecb_encrypt(KEY, plaintext)
    cbc = des_cbc_encrypt(KEY, plaintext, IV)

    print(f"Texto plano : {plaintext.decode()}")
    print(f"{'i':>2}  {'C_i ECB':<18} {'C_i CBC':<18}")
    for i, (e, c) in enumerate(zip(split_blocks(ecb), split_blocks(cbc)), start=1):
        print(f"{i:>2}  {e.hex().upper():<18} {c.hex().upper():<18}")

    print(f"\nECB: {len(set(split_blocks(ecb)))} bloques distintos de "
          f"{len(split_blocks(ecb))}  <- filtra la repetición")
    print(f"CBC: {len(set(split_blocks(cbc)))} bloques distintos de "
          f"{len(split_blocks(cbc))}  <- la oculta")

    assert des_ecb_decrypt(KEY, ecb) == plaintext
    assert des_cbc_decrypt(KEY, cbc, IV) == plaintext
    print("OK: ambos modos descifran correctamente")


def demo_iv_effect() -> None:
    section("4. Efecto del IV (Ejercicio 5)")
    plaintext = b"El mismo mensaje, la misma llave, dos IVs."
    iv1 = bytes.fromhex("0000000000000000")
    iv2 = bytes.fromhex("0000000000000001")
    c1 = des_cbc_encrypt(KEY, plaintext, iv1)
    c2 = des_cbc_encrypt(KEY, plaintext, iv2)

    print(f"IV_1 = {iv1.hex().upper()}  ->  C_1 = {c1[:16].hex().upper()}...")
    print(f"IV_2 = {iv2.hex().upper()}  ->  C_2 = {c2[:16].hex().upper()}...")
    diff = sum(bin(x ^ y).count("1") for x, y in zip(c1, c2))
    print(f"C_1 != C_2: {c1 != c2}   ({diff} de {len(c1) * 8} bits distintos, "
          f"{diff / (len(c1) * 8):.1%})")
    assert c1 != c2


def demo_brute_force() -> None:
    section("5. Fuerza bruta sobre un espacio reducido (Ejercicios 7-8)")
    keyspace = KeySpace(unknown_bits=14, base_key56=0x00FEDCBA987654)
    plaintext = bytes.fromhex("0123456789ABCDEF")
    secret, ciphertext, candidate = make_challenge(keyspace, plaintext, seed=2024)

    print(keyspace.describe())
    print(f"El atacante conoce P = {plaintext.hex().upper()} y "
          f"C = {ciphertext.hex().upper()}, pero no K.")
    print(f"(la llave real está en el candidato {candidate}; el buscador no la ve)\n")

    result = brute_force_des(plaintext, ciphertext, 0, keyspace.size, keyspace=keyspace)
    print(result.summary())
    assert result.found and result.key == secret
    print(f"\nOK: llave recuperada = {result.key.hex().upper()}")


def main() -> None:
    use_utf8_stdout()
    print("=" * 78)
    print("Laboratorio 2 — DES: modos de operación y criptoanálisis por fuerza bruta")
    print("=" * 78)
    demo_block_cipher()
    demo_padding()
    demo_ecb_vs_cbc()
    demo_iv_effect()
    demo_brute_force()
    print("\n" + "=" * 78)
    print("Demostración completa. Para los experimentos y mediciones completos:")
    print("  python -m experiments.run_all")
    print("  python -m benchmarks.benchmark_bruteforce all")
    print("=" * 78)


if __name__ == "__main__":
    main()
