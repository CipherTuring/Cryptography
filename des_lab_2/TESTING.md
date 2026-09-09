# Guía para ejecutar y probar el proyecto

Todo lo de esta guía está verificado en la máquina de referencia
(Windows 11, CPython 3.12.10). Los bloques "Salida esperada" son capturas
reales, no ilustrativas.

---

## 0. Preparación (una sola vez)

### 0.1 Comprobar Python

```bash
python --version
```

Necesitas **3.11 o superior**. Si `python` no funciona, prueba `py -3` en
Windows o `python3` en Linux/macOS, y sustitúyelo en todos los comandos.

### 0.2 Instalar dependencias

```bash
pip install pytest matplotlib
```

`pytest` es para los tests y `matplotlib` solo para las gráficas del
Ejercicio 10. **La librería en sí no tiene dependencias**: `deslib`, `modes` y
`attacks` funcionan solo con la biblioteca estándar.

### 0.3 Situarte en el directorio correcto

**Este es el paso que más falla.** Todos los comandos se ejecutan desde
`des_lab_2/`, que es a la vez la raíz de importación del proyecto.

```bash
cd ruta/hasta/Cryptography/des_lab_2
ls
```

Debes ver `deslib`, `modes`, `attacks` y `tests`.

---

## 1. Ejecutar los tests

### 1.1 La suite completa

```bash
python -m pytest tests/ -q
```

**Salida esperada:**

```
........................................................................ [ 81%]
.................................................                        [100%]
265 passed in 3.98s
```

Si ves `265 passed`, todo el proyecto funciona. Tarda ~4 segundos porque los
espacios de llaves de los tests son diminutos a propósito.

### 1.2 Ver cada test por nombre

```bash
python -m pytest tests/ -v
```

**Salida esperada (extracto):**

```
tests/test_padding.py::test_example_from_the_lab_statement PASSED        [  1%]
tests/test_padding.py::test_round_trip_for_every_length[0] PASSED        [  2%]
tests/test_padding.py::test_round_trip_for_every_length[1] PASSED        [  3%]
```

Los `[0]`, `[1]`… son casos parametrizados: un mismo test ejecutado con
distintas entradas.

### 1.3 Un archivo concreto

Cada archivo corresponde a una parte del enunciado:

| Comando | Tests | Cubre |
|---|---|---|
| `python -m pytest tests/test_padding.py -v` | 85 | Ejercicio 1 (PKCS#7) |
| `python -m pytest tests/test_modes.py -v` | 71 | Ejercicios 2-6 (ECB, CBC) |
| `python -m pytest tests/test_keyspace.py -v` | 43 | Ejercicio 7 (espacio de llaves) |
| `python -m pytest tests/test_brute_force.py -v` | 31 | Ejercicios 7-9 (ataque) |
| `python -m pytest tests/test_deslib.py -v` | 35 | DES del Lab 1 (regresión) |

### 1.4 Filtrar por nombre con `-k`

Útil para localizar un comportamiento concreto sin correr todo:

```bash
python -m pytest tests/ -k "fips81" -v
```

**Salida esperada:**

```
collected 265 items / 263 deselected / 2 selected

tests/test_modes.py::test_ecb_known_answer_fips81 PASSED                 [ 50%]
tests/test_modes.py::test_cbc_known_answer_fips81 PASSED                 [100%]

====================== 2 passed, 263 deselected in 0.06s ======================
```

Otros filtros que valen la pena:

```bash
python -m pytest tests/ -k "avalanche" -v      # efecto avalancha de DES
python -m pytest tests/ -k "parity" -v         # bits de paridad
python -m pytest tests/ -k "parallel" -v       # multiproceso
python -m pytest tests/ -k "error" -v          # propagación de error
python -m pytest tests/ -k "invalid or reject" # rechazo de entradas malas
```

### 1.5 Otros modificadores útiles

```bash
python -m pytest tests/ -x                  # parar en el primer fallo
python -m pytest tests/ -q --durations=5    # los 5 tests más lentos
python -m pytest tests/ --tb=short          # trazas de error compactas
```

**Salida esperada de `--durations=5`:**

```
============================= slowest 5 durations =============================
0.49s call     tests/test_brute_force.py::test_parallel_and_sequential_agree
0.40s call     tests/test_brute_force.py::test_parallel_stops_early_after_a_hit
0.35s call     tests/test_brute_force.py::test_parallel_recovers_the_key[1]
```

Los más lentos son los de multiproceso, porque arrancar procesos con `spawn`
cuesta unas décimas de segundo.

---

## 2. Comprobar que los tests SIRVEN

Que 265 tests pasen no prueba nada por sí solo: unos tests malos también
pasarían. La forma de convencerte es **romper el código a propósito** y ver si
los tests lo detectan.

### 2.1 Romper el encadenamiento de CBC

Abre `modes/cbc.py` y busca esta línea dentro de `des_cbc_encrypt_blocks`:

```python
previous = des_encrypt_block(key, xor_bytes(block, previous))
```

Quítale el XOR, dejándola así (esto convierte CBC en ECB disfrazado):

```python
previous = des_encrypt_block(key, block)
```

Y ejecuta:

```bash
python -m pytest tests/test_modes.py -q
```

**Salida esperada:**

```
42 failed, 29 passed in 0.84s
```

**Deshaz el cambio** y verifica que vuelven a pasar los 71.

### 2.2 Otras roturas que puedes probar

| Qué romper | Dónde | Qué debería fallar |
|---|---|---|
| Cambiar un número de `SHIFTS` | `deslib/tables.py` | Vector conocido y subllaves |
| Devolver relleno de longitud 0 cuando el mensaje es múltiplo | `modes/padding.py` | Los tests de bloque completo |
| Quitar el ajuste del bit de paridad | `attacks/keyspace.py` | `test_generated_keys_have_odd_parity` |
| Invertir el orden de `L, R` en la ronda | `deslib/feistel.py` | Prácticamente todo |

Si rompes algo y **ningún** test falla, has encontrado un hueco real en la
cobertura.

---

## 3. Probar la funcionalidad

### 3.1 Demostración guiada (empieza por aquí)

```bash
python demo.py
```

Recorre el laboratorio entero en unos 6 segundos: vector conocido de DES,
relleno, ECB frente a CBC, efecto del IV y un ataque de fuerza bruta real
sobre 2^14 candidatos. Todas las afirmaciones llevan `assert`, así que si algo
estuviera mal el script reventaría en vez de imprimir un resultado falso.

Lo que debes ver al final:

```
OK: llave recuperada = 017FB697A8C2F157
```

### 3.2 Cifrar y descifrar datos propios

```bash
python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 --text "Hola mundo"
```

**Salida esperada:**

```
IV  : <8 bytes aleatorios>   <- necesario para descifrar
hex : <32 dígitos hexadecimales>
```

El IV cambia en cada ejecución (es aleatorio, como debe ser). Para descifrar,
copia el IV y el hex de la salida anterior:

```bash
python des_cli.py decrypt --mode cbc --key 133457799BBCDFF1 --iv <IV> --hex <HEX>
```

Debe devolver `texto: Hola mundo`.

**Prueba clave — ejecuta el cifrado dos veces seguidas.** El criptograma será
distinto cada vez, aunque el mensaje y la llave sean idénticos: eso es el IV
haciendo su trabajo. Ahora hazlo con ECB:

```bash
python des_cli.py encrypt --mode ecb --key 133457799BBCDFF1 --text "Hola mundo"
```

En ECB el resultado es **siempre el mismo**. Esa es exactamente la diferencia
que estudia el Ejercicio 4.

Con IV fijo, para reproducir un resultado exacto:

```bash
python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 --iv 0001020304050607 --text "Hola mundo"
```

**Salida esperada (siempre esta):**

```
IV  : 0001020304050607   <- necesario para descifrar
hex : F26830B4435A428837594DF8703C2F0C
```

Con archivos:

```bash
echo "contenido secreto" > mensaje.txt
python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 --iv 0001020304050607 --in-file mensaje.txt --out-file mensaje.des
python des_cli.py decrypt --mode cbc --key 133457799BBCDFF1 --iv 0001020304050607 --in-file mensaje.des
```

### 3.3 Verificar contra vectores oficiales a mano

Esta es la comprobación más convincente: contrastar contra valores publicados
por el NIST que no salen de este código.

```bash
python -c "from modes import des_ecb_encrypt, des_cbc_encrypt; K=bytes.fromhex('0123456789abcdef'); IV=bytes.fromhex('1234567890abcdef'); P=b'Now is the time for all '; print('ECB obtenido:', des_ecb_encrypt(K,P)[:24].hex()); print('ECB FIPS 81 : 3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53'); print('CBC obtenido:', des_cbc_encrypt(K,P,IV)[:24].hex()); print('CBC FIPS 81 : e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6')"
```

Las cuatro líneas deben coincidir dos a dos. Los valores de referencia están
publicados en el **FIPS PUB 81** (NIST, 1980).

### 3.4 Los experimentos de la Parte I

```bash
python -m experiments.run_all
```

Tarda segundos e imprime tres informes, dejando copia en `results/`:

| Ejercicio | Qué verás |
|---|---|
| 4 | En ECB los 4 bloques iguales dan **el mismo** criptograma; en CBC los 5 son distintos |
| 5 | Un bit de diferencia en el IV cambia el **50.7 %** del criptograma |
| 6 | ECB corrompe 1 bloque; CBC corrompe **exactamente 2**, y el segundo en **1 solo bit** |

Por separado:

```bash
python -m experiments.exp_ecb_vs_cbc
python -m experiments.exp_iv_effect
python -m experiments.exp_error_propagation
```

Y para revisar lo guardado:

```bash
cat results/exp4_ecb_vs_cbc.txt
```

### 3.5 El ataque de fuerza bruta

Empieza pequeño, con 2^12 = 4096 candidatos (~1 segundo):

```bash
python -m attacks.brute_force --bits 12 --seed 7
```

**Salida esperada:**

```
KeySpace(n=12 bits desconocidos, 4096 candidatos, base_key56=0x00000000000000)
texto plano conocido: 0123456789ABCDEF
criptograma conocido: E54971289CBAF354
(la llave secreta está en el candidato 2652; el buscador no la ve)

intervalo:   [0, 4096)
candidatos:  2653
tiempo:      0.964 s
throughput:  2,750.7 llaves/s
llave:       01010101010129B9
candidato:   2652  (64.7% del intervalo)

llave recuperada correctamente: True
```

Fíjate en dos cosas:

- **`candidatos: 2653` = posición 2652 + 1.** La búsqueda se detuvo justo al
  encontrarla; no siguió probando.
- El mensaje **"el buscador no la ve"** no es decorativo: la llave secreta
  nunca se pasa a `brute_force_des`, solo se usa al final para confirmar.

Sube el tamaño para notar el crecimiento exponencial (cada +2 bits multiplica
el tiempo por 4):

```bash
python -m attacks.brute_force --bits 14 --seed 7    # ~4 s
python -m attacks.brute_force --bits 16 --seed 7    # ~25 s
```

Para reproducir una posición exacta en vez de una aleatoria:

```bash
python -m attacks.brute_force --bits 14 --candidate 16000
```

### 3.6 El ataque paralelo

```bash
python -m attacks.parallel_attack --bits 16 --workers 4 --seed 7
```

La salida detalla el intervalo de cada trabajador y cuántos candidatos probó.
Verás que **el que encuentra la llave prueba menos que los demás** (paró a
mitad de su intervalo) y que los otros también paran antes de agotar el suyo:
eso es el `stop_event` compartido funcionando.

Compara tiempos con distinto número de procesos:

```bash
python -m attacks.parallel_attack --bits 16 --workers 1 --candidate 65000
python -m attacks.parallel_attack --bits 16 --workers 4 --candidate 65000
```

Se fija `--candidate` al final del espacio para que la comparación sea justa:
así todos los trabajadores recorren su intervalo completo y el tiempo mide
paralelismo, no la suerte de dónde cayó la llave.

---

## 4. Los benchmarks

### 4.1 Versión rápida (unos segundos)

Para comprobar que el mecanismo funciona sin esperar:

```bash
python -m benchmarks.benchmark_bruteforce --physical-cores 4 all --seq-bits 10 12 --par-bits 12 --workers 1 2 --repeats 2
```

### 4.2 Versión completa (~50 minutos)

**Reproduce los números del reporte.** Ajusta `--physical-cores` y
`--workers` a tu máquina:

```bash
python -m benchmarks.benchmark_bruteforce --physical-cores 4 all --seq-bits 16 18 20 --par-bits 20 --workers 1 2 4 8 --repeats 3
python -m benchmarks.plot_results
```

> Cuidado: esto **sobrescribe** los resultados de `results/`. Si quieres
> conservar los del reporte, haz una copia antes.

Consejo: no uses el ordenador para otra cosa mientras corre. Cualquier carga
extra distorsiona los tiempos, y en un portátil el calentamiento hace bajar la
frecuencia de la CPU.

### 4.3 Solo la extrapolación

No ejecuta ninguna búsqueda, solo hace la aritmética:

```bash
python -m benchmarks.benchmark_bruteforce extrapolate
python -m benchmarks.benchmark_bruteforce extrapolate --throughput 1000000
```

El segundo comando responde la pregunta 6 del pre-laboratorio: cuánto tardaría
un sistema a 10^6 llaves/s (respuesta: ~2 283 años).

---

## 5. Regenerar el reporte en PDF

```bash
python report/build_report.py
python report/build_report.py --source report/pre-laboratory.md --title "Pre-Laboratorio Lab 2"
```

Usa Chrome o Edge en modo headless. Si no encuentra ninguno, deja el `.html`
generado y puedes exportarlo con Ctrl+P → Guardar como PDF.

---

## 6. Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| `ModuleNotFoundError: No module named 'deslib'` | No estás en `des_lab_2/` | `cd` a `des_lab_2/` y reintenta |
| `No module named pytest` | Falta la dependencia | `pip install pytest` |
| `python` no se reconoce | Alias distinto | Usa `py -3` (Windows) o `python3` |
| Acentos mal en la consola | Página de códigos antigua | `chcp 65001` antes de ejecutar |
| El ataque paralelo se cuelga | Falta el guard de `multiprocessing` | Ejecuta siempre con `python -m`, no copiando el código a un script suelto |
| `plot_results` falla | Falta matplotlib, o no hay datos | `pip install matplotlib` y corre antes el subcomando `parallel` |
| Los tiempos no cuadran con el reporte | Otro hardware | Es normal: los números del reporte son de un i5-8300H |

---

## 7. Checklist de 3 minutos

Para convencerte de que todo está bien sin leer nada más:

```bash
cd des_lab_2
python -m pytest tests/ -q                            # -> 265 passed
python demo.py                                        # -> "llave recuperada"
python -m experiments.run_all                         # -> 3 informes
python -m attacks.brute_force --bits 12 --seed 7      # -> "correctamente: True"
```

Si esos cuatro comandos salen bien, el laboratorio completo funciona.
