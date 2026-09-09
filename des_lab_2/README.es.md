# Laboratorio 2 — DES: modos de operación y criptoanálisis por fuerza bruta

Extiende la librería DES del Laboratorio 1 con **modos de operación**
(PKCS#7, ECB y CBC) y la somete a un **ataque de texto plano conocido por
búsqueda exhaustiva**, secuencial y paralelo, midiendo throughput, speedup y
eficiencia para extrapolar el coste de recorrer las 2⁵⁶ llaves efectivas de
DES.

Todo el cifrado y descifrado de bloque proviene de `deslib/`, la
implementación propia del Laboratorio 1. No se usa PyCryptodome, OpenSSL,
`cryptography` ni ninguna otra librería criptográfica.

---

## Lenguaje y dependencias

| | |
|---|---|
| **Lenguaje** | Python **3.11+** (probado en CPython 3.12.10, Windows 11 x64) |
| **Dependencias de la librería** | ninguna — solo la biblioteca estándar |
| **Dependencias de desarrollo** | `pytest` (tests), `matplotlib` (gráficas del Ejercicio 10) |

`multiprocessing`, `time.perf_counter`, `os.urandom`, `argparse` y `json`
son de la biblioteca estándar. El enunciado permite librerías externas para
medición, gráficas, aleatoriedad, multiproceso y tests — nunca para DES.

## Instalación

```bash
git clone https://github.com/CipherTuring/Cryptography.git
cd Cryptography/des_lab_2

# Opcional pero recomendado
python -m venv .venv
# Windows:        .venv\Scripts\activate
# Linux / macOS:  source .venv/bin/activate

pip install pytest matplotlib
```

No hace falta instalar el proyecto como paquete: `conftest.py` añade la raíz
a `sys.path` para pytest, y los scripts se ejecutan con `python -m` desde
`des_lab_2/`, que es también la raíz de importación.

> **Todos los comandos de este README se ejecutan desde `des_lab_2/`.**

## Ejecutar los tests

```bash
python -m pytest tests/ -v
```

Salida esperada: **265 tests, todos en verde, en unos 4 segundos.** Los
espacios de llaves de los tests son diminutos (n ≤ 11, es decir ≤ 2048
candidatos) a propósito, para que la suite sea rápida.

Solo un subconjunto:

```bash
python -m pytest tests/test_padding.py -v      # Ejercicio 1
python -m pytest tests/test_modes.py -v        # Ejercicios 2-6
python -m pytest tests/test_keyspace.py -v     # Ejercicio 7
python -m pytest tests/test_brute_force.py -v  # Ejercicios 7-9
python -m pytest tests/test_deslib.py -v       # DES del Lab 1 (regresión)
```

## Ejemplo de cifrado

Demostración guiada de todo el laboratorio (bloque DES, relleno, ECB, CBC,
efecto del IV y un ataque de fuerza bruta pequeño):

```bash
python demo.py
```

Herramienta de línea de comandos para cifrar y descifrar datos propios:

```bash
# CBC con IV aleatorio (lo imprime, porque hace falta para descifrar)
python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 --text "Hola mundo"

# CBC con IV explícito
python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 \
    --iv 0001020304050607 --text "Hola mundo"

# Descifrar (el criptograma de arriba: devuelve "Hola mundo")
python des_cli.py decrypt --mode cbc --key 133457799BBCDFF1 \
    --iv 0001020304050607 --hex F26830B4435A428837594DF8703C2F0C

# ECB (no lleva IV)
python des_cli.py encrypt --mode ecb --key 133457799BBCDFF1 --text "Hola mundo"

# Archivos
python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 \
    --in-file mensaje.txt --out-file mensaje.des
```

Desde Python:

```python
from modes import des_cbc_encrypt, des_cbc_decrypt, random_iv

key = bytes.fromhex("133457799BBCDFF1")
iv = random_iv()

ciphertext = des_cbc_encrypt(key, b"Mensaje de longitud arbitraria", iv)
assert des_cbc_decrypt(key, ciphertext, iv) == b"Mensaje de longitud arbitraria"
```

## Ejemplo de fuerza bruta

```bash
# Secuencial: 2^16 = 65 536 candidatos, ~25 s
python -m attacks.brute_force --bits 16 --seed 2024

# Paralelo con 8 procesos: 2^20 = 1 048 576 candidatos
python -m attacks.parallel_attack --bits 20 --workers 8 --seed 2024

# Posición exacta de la llave en el espacio (para reproducir un caso concreto)
python -m attacks.brute_force --bits 18 --candidate 200000
```

Ambos comandos **generan el reto y luego lo resuelven buscando de verdad**:
la llave secreta nunca se pasa a la función de búsqueda, solo se usa al
final para confirmar que la recuperada es la correcta.

## Reproducir los experimentos

### Parte I — modos de operación (Ejercicios 4, 5 y 6)

```bash
python -m experiments.run_all
```

Segundos de ejecución. Escribe en `results/`:

| Archivo | Contenido |
|---|---|
| `exp4_ecb_vs_cbc.{txt,json}` | Bloques repetidos en ECB frente a CBC |
| `exp5_iv_effect.{txt,json}` | Dos IVs distintos sobre el mismo `(K, P)` |
| `exp6_error_propagation.{txt,json}` | Un bit alterado del criptograma |

También pueden lanzarse por separado:

```bash
python -m experiments.exp_ecb_vs_cbc
python -m experiments.exp_iv_effect
python -m experiments.exp_error_propagation
```

### Parte II — rendimiento del ataque (Ejercicios 8 a 11)

```bash
python -m benchmarks.benchmark_bruteforce --physical-cores 4 all \
    --seq-bits 16 18 20 --par-bits 20 --workers 1 2 4 8 --repeats 3

python -m benchmarks.plot_results
```

**Esta corrida tarda cerca de una hora** en la máquina de referencia. Para
una prueba rápida (unos segundos), reduce los parámetros:

```bash
python -m benchmarks.benchmark_bruteforce --physical-cores 4 all \
    --seq-bits 10 12 --par-bits 12 --workers 1 2 --repeats 2
```

Los subcomandos pueden ejecutarse por separado:

```bash
python -m benchmarks.benchmark_bruteforce sequential --bits 16 18 20 --repeats 3
python -m benchmarks.benchmark_bruteforce parallel --bits 20 --workers 1 2 4 8 --repeats 3
python -m benchmarks.benchmark_bruteforce extrapolate          # usa el mejor R medido
python -m benchmarks.benchmark_bruteforce extrapolate --throughput 20000
```

Genera en `results/`: `benchmark_sequential.{txt,json}`,
`benchmark_parallel.{txt,json}`, `extrapolation.{txt,json}`,
`plot_workers_vs_throughput.png` y `plot_workers_vs_speedup.png`.

**Ajusta `--physical-cores` y `--workers` a tu máquina.** El valor se anota
en los resultados junto al modelo de CPU. El barrido tiene sentido con
`p = 1, 2, 4, …, p_max`, donde `p_max` son tus procesadores lógicos.

---

## Cómo se construye el espacio de llaves reducido

El enunciado prohíbe recorrer las 2⁵⁶ llaves reales. En su lugar, solo `n`
bits efectivos son desconocidos y el resto tiene un valor fijo y público.
`attacks/keyspace.py` implementa el mapeo en dos pasos:

```
entero candidato  ──(1)──►  56 bits efectivos  ──(2)──►  llave DES de 64 bits
   [0, 2ⁿ)                      key56                        8 bytes
```

**(1) Candidato → 56 bits efectivos.** Los `n` bits del candidato se insertan
en los `n` bits *menos significativos* de la llave efectiva; los `56 − n`
restantes se copian de `base_key56`:

```
key56 = (base_key56 & ~mask) | (candidate & mask),    mask = 2ⁿ − 1
```

Se eligen los bits bajos para que el espacio sea el rango contiguo
`[0, 2ⁿ)` y repartirlo entre trabajadores sea trivial.

**(2) 56 bits efectivos → llave DES de 64 bits.** Los 56 bits se leen de MSB
a LSB en 8 grupos de 7. Cada grupo ocupa los 7 bits altos de un byte, y el
bit menos significativo de ese byte se elige para que el byte tenga
**paridad impar**, la convención de FIPS PUB 46-3:

```
key56  = g₀ g₁ g₂ g₃ g₄ g₅ g₆ g₇          (8 grupos de 7 bits)
byteᵢ  = (gᵢ << 1) | bit_de_paridad(gᵢ)
```

Ejemplo con `n = 20` y `base_key56 = 0x00FEDCBA987654`:

```
candidato 12345      = 0x003039
key56                = 0x00FEDCBA903039
llave DES (8 bytes)  = 017F B697 A880 C173   ← paridad impar en los 8 bytes
```

Este segundo paso es una **biyección** entre los 2⁵⁶ valores efectivos y las
2⁵⁶ llaves DES con paridad correcta; `strip_parity_bits` lo invierte y
`tests/test_keyspace.py` lo verifica. Nótese que DES descarta los bits de
paridad en PC-1: dos llaves que solo difieren en ellos cifran idénticamente,
y por eso el espacio de búsqueda real es 2⁵⁶ y no 2⁶⁴.

---

## Estructura del proyecto

```
des_lab_2/
├── deslib/                     # DES de bloque del Laboratorio 1 (sin cambios)
│   ├── tables.py               #   IP, FP, E, P, PC-1, PC-2, SHIFTS
│   ├── permutation.py          #   permutación genérica + rotación circular
│   ├── sboxes.py               #   las 8 S-boxes, sustitución 48 -> 32
│   ├── key_schedule.py         #   16 subllaves + chequeo de paridad
│   ├── feistel.py              #   función F y una ronda
│   ├── des_core.py             #   IP -> 16 rondas -> swap -> IP⁻¹
│   └── api.py                  #   des_encrypt_block / des_decrypt_block
│
├── modes/                      # Parte I: modos de operación
│   ├── blocks.py               #   BLOCK_SIZE, split_blocks, xor_bytes
│   ├── padding.py              #   Ej. 1 — pkcs7_pad / pkcs7_unpad
│   ├── ecb.py                  #   Ej. 2 — des_ecb_encrypt / des_ecb_decrypt
│   └── cbc.py                  #   Ej. 3 — des_cbc_encrypt / des_cbc_decrypt
│
├── attacks/                    # Parte II: criptoanálisis
│   ├── keyspace.py             #   Ej. 7 — candidato -> 56 bits -> llave DES
│   ├── brute_force.py          #   Ej. 7-8 — búsqueda exhaustiva secuencial
│   └── parallel_attack.py      #   Ej. 9 — la misma búsqueda en p procesos
│
├── benchmarks/
│   ├── benchmark_bruteforce.py #   Ej. 8, 9, 10, 11 — mediciones y extrapolación
│   ├── plot_results.py         #   Ej. 10 — gráficas
│   └── sysinfo.py              #   modelo de CPU y núcleos
│
├── experiments/                # Parte I: experimentos con resultados escritos
│   ├── exp_ecb_vs_cbc.py       #   Ej. 4
│   ├── exp_iv_effect.py        #   Ej. 5
│   ├── exp_error_propagation.py#   Ej. 6
│   ├── run_all.py              #   ejecuta los tres
│   └── common.py               #   formato de bloques, distancia de Hamming
│
├── tests/                      # 265 tests
│   ├── test_deslib.py          #   regresión del DES del Lab 1
│   ├── test_padding.py         #   Ej. 1
│   ├── test_modes.py           #   Ej. 2-6, con vectores FIPS PUB 81
│   ├── test_keyspace.py        #   Ej. 7
│   └── test_brute_force.py     #   Ej. 7-9
│
├── results/                    # salida de experimentos y mediciones (.txt/.json/.png)
├── report/
│   ├── pre-laboratory.md       #   respuestas del pre-laboratorio
│   ├── lab2-report.md          #   reporte técnico (fuente)
│   └── lab2-report.pdf         #   reporte técnico (entregable)
│
├── ARCHITECTURE.md             # diagramas de arquitectura (Mermaid)
├── TESTING.md                  # guía para ejecutar y probar todo
├── demo.py                     # demostración guiada
├── des_cli.py                  # CLI de cifrado/descifrado
├── console.py                  # salida UTF-8 en Windows
├── conftest.py                 # raíz del proyecto en sys.path para pytest
└── README.md
```

**Desviaciones respecto a la estructura sugerida en el enunciado**, todas
aditivas: `modes/blocks.py` recoge las utilidades de bloque compartidas para
no duplicarlas entre `ecb.py` y `cbc.py`; `experiments/` separa el código
experimental de la Parte I del de medición de rendimiento (`benchmarks/`),
manteniendo el criterio del enunciado de aislar código criptográfico,
experimental, tests y resultados; y `demo.py`, `des_cli.py`, `console.py` y
`conftest.py` son utilidades de ejecución.

## Notas de diseño

- **El núcleo criptográfico es puro.** Ni `deslib/`, ni `modes/`, ni
  `attacks/` imprimen, leen archivos ni piden entrada por teclado. Toda la
  I/O vive en `demo.py`, `des_cli.py`, `experiments/` y `benchmarks/`.

- **Procesos, no hilos.** La búsqueda exhaustiva es CPU-bound y el GIL de
  CPython serializaría los hilos: el speedup con `threading` sería ≈ 1. Se
  usa `multiprocessing` con el contexto `spawn` explícito, para que el
  comportamiento sea idéntico en Windows, macOS y Linux.

- **Terminación temprana.** Los trabajadores comparten un
  `multiprocessing.Event`. Quien encuentra la llave lo activa; los demás lo
  consultan una vez cada `chunk = 4096` candidatos y abandonan. Consultarlo
  en cada candidato costaría más que la propia prueba de llave.

- **`T₁` se mide con el código paralelo usando un solo trabajador**, no con
  la función secuencial. Así el coste de crear procesos está presente en
  todas las configuraciones y `S_p = T₁/T_p` no queda inflado por compararlo
  con una ejecución que no lo paga.

- **En el barrido de speedup la llave se coloca en el último candidato**,
  de modo que todos los trabajadores agotan su intervalo y se prueban los
  2ⁿ candidatos para cualquier `p`. Si la llave cayera en una posición
  aleatoria, `T_p` mediría sobre todo la suerte del reparto. El Ejercicio 8
  sí usa posiciones pseudoaleatorias, porque ahí interesa el caso realista.

- **Reutilización del DES del Lab 1.** El bucle caliente llama a
  `des_key_schedule` + `des_block` (la ruta interna de `des_encrypt_block`)
  para no repetir en cada uno de los 2ⁿ candidatos la validación de
  longitudes y las conversiones `bytes ↔ int`, que son idénticas en todas
  las iteraciones. El algoritmo DES es exactamente el del Laboratorio 1.

- **Falsos positivos.** Con un solo par `(P, C)` de 64 bits y `n ≤ 24`, la
  probabilidad de que una llave incorrecta produzca el mismo criptograma es
  del orden de `2^(n−64) ≈ 10⁻¹²`. `attacks.brute_force.verify_key` permite
  confirmar un hallazgo con pares adicionales.

## Advertencia de seguridad

**DES no es seguro y este código es material didáctico.** La llave efectiva
de 56 bits es hoy trivialmente atacable por fuerza bruta (ver
`results/extrapolation.txt`), ECB filtra la estructura del texto plano, y
ni ECB ni CBC ofrecen integridad: ambos entregan texto plano corrompido sin
señalar error alguno cuando el criptograma se altera. Para uso real,
emplear un modo autenticado moderno (AES-GCM, ChaCha20-Poly1305) de una
librería criptográfica auditada.

## Resultados

Todos los resultados de `results/` provienen de esta máquina:

| | |
|---|---|
| **CPU** | Intel(R) Core(TM) i5-8300H @ 2.30 GHz |
| **Núcleos** | 4 físicos / 8 lógicos (Hyper-Threading) |
| **RAM** | 11.8 GB |
| **SO** | Windows 11 Home Single Language 10.0.26200 |
| **Python** | CPython 3.12.10 (64 bits) |

### Parte I — modos de operación

| Experimento | Resultado |
|---|---|
| **Ej. 4** — 4 bloques de texto plano idénticos | ECB produce 4 criptogramas **idénticos** (2 bloques distintos de 5); CBC produce 5 distintos de 5 |
| **Ej. 5** — un bit de diferencia entre dos IVs | **50.7 %** de los bits del criptograma cambian (227 de 448); con el IV erróneo solo se corrompe `P₁`, y exactamente en 1 bit |
| **Ej. 6** — un bit alterado del criptograma | ECB: 1 bloque afectado (37 bits). CBC: **exactamente 2** — `P₂` completo (31 bits) y `P₃` en **1 solo bit**, el mismo que se alteró |

### Parte II — fuerza bruta

Búsqueda secuencial (Ej. 8), llave en posición pseudoaleatoria, 3 repeticiones:

| n | 2ⁿ | Tiempo medio [s] | Llaves/s |
|---|---|---|---|
| 16 | 65 536 | 7.085 | 2 615 |
| 18 | 262 144 | 20.950 | 2 583 |
| 20 | 1 048 576 | 163.766 | 2 645 |

Búsqueda paralela (Ej. 9-10), `n = 20`, espacio recorrido completo, 3 repeticiones:

| Workers | Tiempo [s] | Llaves/s | Speedup `S_p` | Eficiencia `E_p` |
|---|---|---|---|---|
| 1 | 424.397 | 2 471 | 1.00 | 1.00 |
| 2 | 257.916 | 4 066 | 1.65 | 0.82 |
| 4 | 176.522 | 5 940 | 2.40 | 0.60 |
| 8 | 151.425 | 6 925 | 2.80 | 0.35 |

Extrapolación a 2⁵⁶ (Ej. 11) con `R = 6 925 llaves/s`:

```
T_max = 2⁵⁶ / R ≈ 1.04 × 10¹³ s ≈ 329 742 años
T_avg = 2⁵⁵ / R ≈ 5.20 × 10¹² s ≈ 164 871 años
```

Ese número mide **la lentitud de Python, no la seguridad de DES**: la misma
búsqueda la resolvió en 56 horas una máquina dedicada de 1998. El análisis
completo está en [`report/lab2-report.md`](report/lab2-report.md)
([PDF](report/lab2-report.pdf)).
