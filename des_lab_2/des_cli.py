"""
Command-line tool to encrypt and decrypt with DES-ECB and DES-CBC.

Examples
--------
    # Encrypt text in CBC with a random IV (printed so it can be decrypted)
    python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 --text "Hola mundo"

    # Encrypt in ECB
    python des_cli.py encrypt --mode ecb --key 133457799BBCDFF1 --text "Hola mundo"

    # Decrypt
    python des_cli.py decrypt --mode cbc --key 133457799BBCDFF1 \
        --iv 0001020304050607 --hex 2A9F...

    # Encrypt a file
    python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 \
        --in-file mensaje.txt --out-file mensaje.des

WARNING: DES has a 56-bit effective key and is nowadays vulnerable to
exhaustive search (see `benchmarks/`). This tool is teaching material for
the laboratory; it must not be used to protect real data.
"""

import argparse
import sys
from pathlib import Path

from console import use_utf8_stdout
from modes import des_cbc_decrypt, des_cbc_encrypt, des_ecb_decrypt, des_ecb_encrypt, random_iv


def _read_input(args) -> bytes:
    if args.in_file:
        return Path(args.in_file).read_bytes()
    if args.text is not None:
        return args.text.encode("utf-8")
    if args.hex is not None:
        return bytes.fromhex(args.hex)
    raise SystemExit("indica la entrada con --text, --hex o --in-file")


def _hex8(value: str, name: str) -> bytes:
    try:
        data = bytes.fromhex(value)
    except ValueError as error:
        raise SystemExit(f"{name} debe ser hexadecimal: {error}") from error
    if len(data) != 8:
        raise SystemExit(f"{name} debe medir 8 bytes (16 dígitos hex), mide {len(data)}")
    return data


def main() -> None:
    use_utf8_stdout()
    parser = argparse.ArgumentParser(
        description="Cifra y descifra con DES en modo ECB o CBC.",
        epilog="DES es inseguro hoy; esta herramienta es material didáctico.",
    )
    parser.add_argument("action", choices=["encrypt", "decrypt"])
    parser.add_argument("--mode", choices=["ecb", "cbc"], required=True)
    parser.add_argument("--key", required=True, help="llave DES en hex (8 bytes)")
    parser.add_argument("--iv", help="IV en hex (8 bytes); solo CBC")
    parser.add_argument("--text", help="entrada como texto UTF-8")
    parser.add_argument("--hex", help="entrada como hexadecimal")
    parser.add_argument("--in-file", help="entrada desde un archivo binario")
    parser.add_argument("--out-file", help="escribe la salida cruda en un archivo")
    args = parser.parse_args()

    key = _hex8(args.key, "la llave")
    data = _read_input(args)

    if args.mode == "cbc":
        if args.action == "encrypt":
            iv = _hex8(args.iv, "el IV") if args.iv else random_iv()
            output = des_cbc_encrypt(key, data, iv)
            print(f"IV  : {iv.hex().upper()}   <- necesario para descifrar")
        else:
            if not args.iv:
                raise SystemExit("descifrar en CBC requiere --iv")
            output = des_cbc_decrypt(key, data, _hex8(args.iv, "el IV"))
    else:
        if args.iv:
            print("aviso: ECB no usa IV; se ignora --iv", file=sys.stderr)
        output = (
            des_ecb_encrypt(key, data)
            if args.action == "encrypt"
            else des_ecb_decrypt(key, data)
        )

    if args.out_file:
        Path(args.out_file).write_bytes(output)
        print(f"-> {args.out_file}  ({len(output)} bytes)")
        return

    print(f"hex : {output.hex().upper()}")
    if args.action == "decrypt":
        try:
            print(f"texto: {output.decode('utf-8')}")
        except UnicodeDecodeError:
            print("texto: (no es UTF-8 válido)")


if __name__ == "__main__":
    main()
