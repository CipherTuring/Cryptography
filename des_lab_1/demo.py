"""
Script de demostración de deslib.

Toda la impresión / I/O vive aquí, fuera de los módulos del núcleo
(`deslib.des_core`, `deslib.feistel`, etc.), tal como pide el enunciado.
"""

from deslib import des_decrypt_block, des_encrypt_block, des_key_schedule

if __name__ == "__main__":
    key = bytes.fromhex("133457799BBCDFF1")
    plaintext = bytes.fromhex("0123456789ABCDEF")
    expected_ciphertext = "85E813540F0AB405"

    subkeys = des_key_schedule(key)

    ciphertext = des_encrypt_block(key, plaintext)
    print("Key:                 ", key.hex().upper())
    print("Plaintext:            ", plaintext.hex().upper())
    print("k1:                  ", f"{subkeys[0]:012X}")
    print("k16:                 ", f"{subkeys[15]:012X}")
    print("Ciphertext obtenido: ", ciphertext.hex().upper())
    print("Ciphertext esperado: ", expected_ciphertext)
    assert ciphertext.hex().upper() == expected_ciphertext

    decrypted = des_decrypt_block(key, ciphertext)
    print("Descifrado obtenido: ", decrypted.hex().upper())
    assert decrypted == plaintext

    print("\nOK: cifrado y descifrado coinciden con el vector de prueba conocido.")
