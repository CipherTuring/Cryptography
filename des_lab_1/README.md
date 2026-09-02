# deslib

Implementación educativa de DES (Data Encryption Standard, FIPS PUB 46-3)
desde cero, sin librerías criptográficas externas. Desarrollada para el
Laboratorio 1 del curso de Criptografía.

## Estructura del proyecto

```
des_lab_1/
├── deslib/
│   ├── __init__.py       # API pública del paquete
│   ├── tables.py         # Tablas oficiales de DES (IP, FP, E, P, PC-1, PC-2, SHIFTS)
│   ├── permutation.py     # Permutación/selección genérica + rotación circular
│   ├── sboxes.py          # Las 8 S-boxes y la sustitución 48->32 bits
│   ├── key_schedule.py    # Generación de subllaves + chequeo de paridad
│   ├── feistel.py         # Función F de Feistel y una ronda
│   ├── des_core.py        # Núcleo puro: IP -> 16 rondas -> swap -> IP^-1
│   └── api.py             # API pública: encrypt/decrypt de bloque, validación
├── tests/
│   └── test_deslib.py     # Suite de pytest
├── demo.py                 # Script de demostración (I/O fuera del núcleo)
└── README.md
```

El núcleo (`des_core.py`, `feistel.py`, `sboxes.py`, `permutation.py`,
`key_schedule.py`) solo contiene operaciones criptográficas puras sobre
enteros de Python — no hay `print`, lectura de archivos ni entrada de
teclado en esos módulos.

## Instalación

Requiere Python 3.11+. No hay dependencias externas para el uso normal
de la librería; `pytest` es necesario solo para correr los tests.

```bash
git clone <url-del-repositorio>
cd des_lab_1
pip install pytest --break-system-packages   # solo para tests
```

## Uso

```python
from deslib import des_encrypt_block, des_decrypt_block, des_key_schedule, des_check_parity

key = bytes.fromhex("133457799BBCDFF1")
plaintext = bytes.fromhex("0123456789ABCDEF")

ciphertext = des_encrypt_block(key, plaintext)
print(ciphertext.hex())  # 85e813540f0ab405

recovered = des_decrypt_block(key, ciphertext)
assert recovered == plaintext

subkeys = des_key_schedule(key)   # lista de 16 enteros de 48 bits
print(des_check_parity(key))       # True/False según paridad impar por byte
```

También puede ejecutarse la demostración incluida:

```bash
python3 demo.py
```

## API pública

| Función | Firma | Descripción |
|---|---|---|
| `des_encrypt_block` | `(key: bytes, plaintext: bytes) -> bytes` | Cifra un bloque de 8 bytes |
| `des_decrypt_block` | `(key: bytes, ciphertext: bytes) -> bytes` | Descifra un bloque de 8 bytes |
| `des_key_schedule` | `(key: bytes) -> list[int]` | Genera las 16 subllaves de 48 bits |
| `des_check_parity` | `(key: bytes) -> bool` | Verifica paridad impar por byte |

Tanto `key` como los bloques de texto deben tener exactamente 8 bytes;
cualquier otra longitud lanza `ValueError`.

## Representación interna

El estado de DES (bloques, mitades L/R, subllaves) se representa
internamente como **enteros de Python**, no como strings de `'0'`/`'1'`.
La función genérica `permute(value, table, input_width)` en
`permutation.py` opera directamente sobre enteros, interpretando el bit 1
de cada tabla DES como el bit más significativo (MSB) del valor de
entrada.

## Tests

```bash
python3 -m pytest tests/ -v
```

La suite cubre:

- **Vector de prueba conocido**: `E_K(P) = C` y `D_K(C) = P` para el
  vector clásico (`K = 133457799BBCDFF1`, `P = 0123456789ABCDEF`,
  `C = 85E813540F0AB405`).
- **Subllaves de ronda**: verifica `k1 = 1B02EFFC7072` y
  `k16 = CB3D8B0E17F5`.
- **Round-trip**: `D_K(E_K(P)) = P` sobre 20 bloques aleatorios distintos.
- **Efecto avalancha**: al voltear un bit del texto plano o un bit
  efectivo de la llave, el número de bits distintos en el ciphertext
  cae en el rango `20 <= dH <= 44`.
- **Entradas inválidas**: llaves y bloques de 7 o 9 bytes son
  rechazados con `ValueError`.
- **Orden de bits**: un test dedicado falla si el bit 1 de una tabla
  DES se interpreta como LSB en lugar de MSB.

## Notas de diseño

- Todos los componentes de DES (permutaciones, S-boxes, key schedule,
  función de Feistel y las 16 rondas de cifrado) fueron implementados
  sin usar PyCryptodome, OpenSSL, `cryptography`, `javax.crypto`,
  Crypto++ ni ninguna otra librería criptográfica existente.
- DES tiene una llave nominal de 64 bits, pero 8 de esos bits son bits
  de paridad (uno por byte), por lo que la llave efectiva es de 56
  bits — un espacio de búsqueda hoy trivialmente atacable por fuerza
  bruta, razón por la cual DES ya no se considera adecuado para
  sistemas modernos (ver Ejercicio de reflexión / reporte).
