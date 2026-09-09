# Laboratory 2 — DES: modes of operation and brute-force cryptanalysis

Extends the DES library from Laboratory 1 with **modes of operation**
(PKCS#7, ECB and CBC) and subjects it to a **known-plaintext attack by
exhaustive search**, both sequential and parallel, measuring throughput,
speedup and efficiency in order to extrapolate the cost of sweeping the 2⁵⁶
effective DES keys.

All block encryption and decryption comes from `deslib/`, the in-house
implementation from Laboratory 1. No PyCryptodome, OpenSSL, `cryptography`
or any other cryptographic library is used.

---

## Language and dependencies

| | |
|---|---|
| **Language** | Python **3.11+** (tested on CPython 3.12.10, Windows 11 x64) |
| **Library dependencies** | none — standard library only |
| **Development dependencies** | `pytest` (tests), `matplotlib` (Exercise 10 plots) |

`multiprocessing`, `time.perf_counter`, `os.urandom`, `argparse` and `json`
belong to the standard library. The assignment allows external libraries for
measurement, plotting, randomness, multiprocessing and tests — never for DES.

## Installation

```bash
git clone https://github.com/CipherTuring/Cryptography.git
cd Cryptography/des_lab_2

# Optional but recommended
python -m venv .venv
# Windows:        .venv\Scripts\activate
# Linux / macOS:  source .venv/bin/activate

pip install pytest matplotlib
```

There is no need to install the project as a package: `conftest.py` adds the
root to `sys.path` for pytest, and the scripts are run with `python -m` from
`des_lab_2/`, which is also the import root.

> **Every command in this README is run from `des_lab_2/`.**

## Running the tests

```bash
python -m pytest tests/ -v
```

Expected output: **265 tests, all green, in about 4 seconds.** The key spaces
used by the tests are tiny (n ≤ 11, that is, ≤ 2048 candidates) on purpose,
so that the suite stays fast.

Only a subset:

```bash
python -m pytest tests/test_padding.py -v      # Exercise 1
python -m pytest tests/test_modes.py -v        # Exercises 2-6
python -m pytest tests/test_keyspace.py -v     # Exercise 7
python -m pytest tests/test_brute_force.py -v  # Exercises 7-9
python -m pytest tests/test_deslib.py -v       # DES from Lab 1 (regression)
```

## Encryption example

Guided demonstration of the whole laboratory (DES block, padding, ECB, CBC,
the effect of the IV and a small brute-force attack):

```bash
python demo.py
```

Command-line tool for encrypting and decrypting your own data:

```bash
# CBC with a random IV (it is printed, since it is needed for decryption)
python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 --text "Hola mundo"

# CBC with an explicit IV
python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 \
    --iv 0001020304050607 --text "Hola mundo"

# Decrypt (the ciphertext above: it returns "Hola mundo")
python des_cli.py decrypt --mode cbc --key 133457799BBCDFF1 \
    --iv 0001020304050607 --hex F26830B4435A428837594DF8703C2F0C

# ECB (takes no IV)
python des_cli.py encrypt --mode ecb --key 133457799BBCDFF1 --text "Hola mundo"

# Files
python des_cli.py encrypt --mode cbc --key 133457799BBCDFF1 \
    --in-file mensaje.txt --out-file mensaje.des
```

From Python:

```python
from modes import des_cbc_encrypt, des_cbc_decrypt, random_iv

key = bytes.fromhex("133457799BBCDFF1")
iv = random_iv()

ciphertext = des_cbc_encrypt(key, b"Mensaje de longitud arbitraria", iv)
assert des_cbc_decrypt(key, ciphertext, iv) == b"Mensaje de longitud arbitraria"
```

## Brute-force example

```bash
# Sequential: 2^16 = 65,536 candidates, ~25 s
python -m attacks.brute_force --bits 16 --seed 2024

# Parallel with 8 processes: 2^20 = 1,048,576 candidates
python -m attacks.parallel_attack --bits 20 --workers 8 --seed 2024

# Exact position of the key in the space (to reproduce a specific case)
python -m attacks.brute_force --bits 18 --candidate 200000
```

Both commands **generate the challenge and then genuinely solve it by
searching**: the secret key is never passed to the search function, it is
only used at the end to confirm that the recovered one is correct.

## Reproducing the experiments

### Part I — modes of operation (Exercises 4, 5 and 6)

```bash
python -m experiments.run_all
```

Takes seconds. Writes into `results/`:

| File | Contents |
|---|---|
| `exp4_ecb_vs_cbc.{txt,json}` | Repeated blocks under ECB versus CBC |
| `exp5_iv_effect.{txt,json}` | Two different IVs over the same `(K, P)` |
| `exp6_error_propagation.{txt,json}` | One flipped bit of the ciphertext |

They can also be launched separately:

```bash
python -m experiments.exp_ecb_vs_cbc
python -m experiments.exp_iv_effect
python -m experiments.exp_error_propagation
```

### Part II — attack performance (Exercises 8 to 11)

```bash
python -m benchmarks.benchmark_bruteforce --physical-cores 4 all \
    --seq-bits 16 18 20 --par-bits 20 --workers 1 2 4 8 --repeats 3

python -m benchmarks.plot_results
```

**This run takes close to an hour** on the reference machine. For a quick
check (a few seconds), reduce the parameters:

```bash
python -m benchmarks.benchmark_bruteforce --physical-cores 4 all \
    --seq-bits 10 12 --par-bits 12 --workers 1 2 --repeats 2
```

The subcommands can be run separately:

```bash
python -m benchmarks.benchmark_bruteforce sequential --bits 16 18 20 --repeats 3
python -m benchmarks.benchmark_bruteforce parallel --bits 20 --workers 1 2 4 8 --repeats 3
python -m benchmarks.benchmark_bruteforce extrapolate          # uses the best measured R
python -m benchmarks.benchmark_bruteforce extrapolate --throughput 20000
```

It generates in `results/`: `benchmark_sequential.{txt,json}`,
`benchmark_parallel.{txt,json}`, `extrapolation.{txt,json}`,
`plot_workers_vs_throughput.png` and `plot_workers_vs_speedup.png`.

**Adjust `--physical-cores` and `--workers` to your machine.** The value is
recorded in the results alongside the CPU model. The sweep makes sense with
`p = 1, 2, 4, …, p_max`, where `p_max` is your number of logical processors.

---

## How the reduced key space is built

The assignment forbids sweeping the real 2⁵⁶ keys. Instead, only `n` bits
are effectively unknown and the rest have a fixed, public value.
`attacks/keyspace.py` implements the mapping in two steps:

```
candidate integer  ──(1)──►  56 effective bits  ──(2)──►  64-bit DES key
   [0, 2ⁿ)                        key56                       8 bytes
```

**(1) Candidate → 56 effective bits.** The `n` bits of the candidate are
inserted into the `n` *least significant* bits of the effective key; the
remaining `56 − n` are copied from `base_key56`:

```
key56 = (base_key56 & ~mask) | (candidate & mask),    mask = 2ⁿ − 1
```

The low bits are chosen so that the space is the contiguous range `[0, 2ⁿ)`
and splitting it among workers is trivial.

**(2) 56 effective bits → 64-bit DES key.** The 56 bits are read from MSB to
LSB in 8 groups of 7. Each group occupies the top 7 bits of a byte, and the
least significant bit of that byte is chosen so that the byte has **odd
parity**, the convention of FIPS PUB 46-3:

```
key56  = g₀ g₁ g₂ g₃ g₄ g₅ g₆ g₇          (8 groups of 7 bits)
byteᵢ  = (gᵢ << 1) | parity_bit(gᵢ)
```

Example with `n = 20` and `base_key56 = 0x00FEDCBA987654`:

```
candidate 12345      = 0x003039
key56                = 0x00FEDCBA903039
DES key (8 bytes)    = 017F B697 A880 C173   ← odd parity in all 8 bytes
```

This second step is a **bijection** between the 2⁵⁶ effective values and the
2⁵⁶ DES keys with correct parity; `strip_parity_bits` inverts it and
`tests/test_keyspace.py` verifies it. Note that DES discards the parity bits
in PC-1: two keys that differ only in them encrypt identically, which is why
the real search space is 2⁵⁶ and not 2⁶⁴.

---

## Project structure

```
des_lab_2/
├── deslib/                     # DES block cipher from Laboratory 1 (unchanged)
│   ├── tables.py               #   IP, FP, E, P, PC-1, PC-2, SHIFTS
│   ├── permutation.py          #   generic permutation + circular rotation
│   ├── sboxes.py               #   the 8 S-boxes, 48 -> 32 substitution
│   ├── key_schedule.py         #   16 subkeys + parity check
│   ├── feistel.py              #   F function and one round
│   ├── des_core.py             #   IP -> 16 rounds -> swap -> IP⁻¹
│   └── api.py                  #   des_encrypt_block / des_decrypt_block
│
├── modes/                      # Part I: modes of operation
│   ├── blocks.py               #   BLOCK_SIZE, split_blocks, xor_bytes
│   ├── padding.py              #   Ex. 1 — pkcs7_pad / pkcs7_unpad
│   ├── ecb.py                  #   Ex. 2 — des_ecb_encrypt / des_ecb_decrypt
│   └── cbc.py                  #   Ex. 3 — des_cbc_encrypt / des_cbc_decrypt
│
├── attacks/                    # Part II: cryptanalysis
│   ├── keyspace.py             #   Ex. 7 — candidate -> 56 bits -> DES key
│   ├── brute_force.py          #   Ex. 7-8 — sequential exhaustive search
│   └── parallel_attack.py      #   Ex. 9 — the same search over p processes
│
├── benchmarks/
│   ├── benchmark_bruteforce.py #   Ex. 8, 9, 10, 11 — measurements and extrapolation
│   ├── plot_results.py         #   Ex. 10 — plots
│   └── sysinfo.py              #   CPU model and cores
│
├── experiments/                # Part I: experiments with written results
│   ├── exp_ecb_vs_cbc.py       #   Ex. 4
│   ├── exp_iv_effect.py        #   Ex. 5
│   ├── exp_error_propagation.py#   Ex. 6
│   ├── run_all.py              #   runs the three of them
│   └── common.py               #   block formatting, Hamming distance
│
├── tests/                      # 265 tests
│   ├── test_deslib.py          #   regression for the DES from Lab 1
│   ├── test_padding.py         #   Ex. 1
│   ├── test_modes.py           #   Ex. 2-6, with FIPS PUB 81 test vectors
│   ├── test_keyspace.py        #   Ex. 7
│   └── test_brute_force.py     #   Ex. 7-9
│
├── results/                    # output of experiments and measurements (.txt/.json/.png)
├── report/
│   ├── pre-laboratory.md       #   pre-laboratory answers
│   ├── lab2-report.md          #   technical report (source)
│   └── lab2-report.pdf         #   technical report (deliverable)
│
├── ARCHITECTURE.md             # architecture diagrams (Mermaid)
├── TESTING.md                  # guide to running and testing everything
├── demo.py                     # guided demonstration
├── des_cli.py                  # encryption/decryption CLI
├── console.py                  # UTF-8 output on Windows
├── conftest.py                 # project root on sys.path for pytest
└── README.md
```

**Deviations from the structure suggested in the assignment**, all of them
additive: `modes/blocks.py` gathers the shared block utilities so as not to
duplicate them between `ecb.py` and `cbc.py`; `experiments/` separates the
Part I experimental code from the performance-measurement code
(`benchmarks/`), keeping the assignment's criterion of isolating
cryptographic code, experimental code, tests and results; and `demo.py`,
`des_cli.py`, `console.py` and `conftest.py` are execution utilities.

## Design notes

- **The cryptographic core is pure.** Neither `deslib/`, nor `modes/`, nor
  `attacks/` print, read files or ask for keyboard input. All the I/O lives
  in `demo.py`, `des_cli.py`, `experiments/` and `benchmarks/`.

- **Processes, not threads.** Exhaustive search is CPU-bound and CPython's
  GIL would serialize the threads: the speedup with `threading` would be
  ≈ 1. `multiprocessing` is used with an explicit `spawn` context, so that
  the behaviour is identical on Windows, macOS and Linux.

- **Early termination.** The workers share a `multiprocessing.Event`.
  Whoever finds the key sets it; the rest check it once every
  `chunk = 4096` candidates and give up. Checking it on every candidate
  would cost more than the key test itself.

- **`T₁` is measured with the parallel code using a single worker**, not
  with the sequential function. That way the cost of creating processes is
  present in every configuration and `S_p = T₁/T_p` is not inflated by
  comparing it against a run that does not pay it.

- **In the speedup sweep the key is placed at the last candidate**, so that
  every worker exhausts its interval and all 2ⁿ candidates are tested for
  any `p`. If the key fell at a random position, `T_p` would mostly measure
  the luck of the split. Exercise 8 does use pseudorandom positions, because
  there it is the realistic case that matters.

- **Reuse of the DES from Lab 1.** The hot loop calls `des_key_schedule` +
  `des_block` (the internal path of `des_encrypt_block`) so as not to repeat,
  on each of the 2ⁿ candidates, the length validation and the `bytes ↔ int`
  conversions, which are identical on every iteration. The DES algorithm is
  exactly the one from Laboratory 1.

- **False positives.** With a single 64-bit `(P, C)` pair and `n ≤ 24`, the
  probability that an incorrect key produces the same ciphertext is on the
  order of `2^(n−64) ≈ 10⁻¹²`. `attacks.brute_force.verify_key` makes it
  possible to confirm a finding with additional pairs.

## Security warning

**DES is not secure and this code is teaching material.** The 56-bit
effective key is trivially brute-forceable today (see
`results/extrapolation.txt`), ECB leaks the structure of the plaintext, and
neither ECB nor CBC provides integrity: both hand back corrupted plaintext
without signalling any error when the ciphertext is altered. For real use,
employ a modern authenticated mode (AES-GCM, ChaCha20-Poly1305) from an
audited cryptographic library.

## Results

All the results in `results/` come from this machine:

| | |
|---|---|
| **CPU** | Intel(R) Core(TM) i5-8300H @ 2.30 GHz |
| **Cores** | 4 physical / 8 logical (Hyper-Threading) |
| **RAM** | 11.8 GB |
| **OS** | Windows 11 Home Single Language 10.0.26200 |
| **Python** | CPython 3.12.10 (64-bit) |

### Part I — modes of operation

| Experiment | Result |
|---|---|
| **Ex. 4** — 4 identical plaintext blocks | ECB produces 4 **identical** ciphertext blocks (2 distinct out of 5); CBC produces 5 distinct out of 5 |
| **Ex. 5** — one bit of difference between two IVs | **50.7 %** of the ciphertext bits change (227 out of 448); with the wrong IV only `P₁` is corrupted, and in exactly 1 bit |
| **Ex. 6** — one flipped bit of the ciphertext | ECB: 1 block affected (37 bits). CBC: **exactly 2** — all of `P₂` (31 bits) and `P₃` in a **single bit**, the very one that was flipped |

### Part II — brute force

Sequential search (Ex. 8), key at a pseudorandom position, 3 repetitions:

| n | 2ⁿ | Mean time [s] | Keys/s |
|---|---|---|---|
| 16 | 65,536 | 7.085 | 2,615 |
| 18 | 262,144 | 20.950 | 2,583 |
| 20 | 1,048,576 | 163.766 | 2,645 |

Parallel search (Ex. 9-10), `n = 20`, whole space swept, 3 repetitions:

| Workers | Time [s] | Keys/s | Speedup `S_p` | Efficiency `E_p` |
|---|---|---|---|---|
| 1 | 424.397 | 2,471 | 1.00 | 1.00 |
| 2 | 257.916 | 4,066 | 1.65 | 0.82 |
| 4 | 176.522 | 5,940 | 2.40 | 0.60 |
| 8 | 151.425 | 6,925 | 2.80 | 0.35 |

Extrapolation to 2⁵⁶ (Ex. 11) with `R = 6,925 keys/s`:

```
T_max = 2⁵⁶ / R ≈ 1.04 × 10¹³ s ≈ 329,742 years
T_avg = 2⁵⁵ / R ≈ 5.20 × 10¹² s ≈ 164,871 years
```

That number measures **the slowness of Python, not the security of DES**:
the same search was solved in 56 hours by a dedicated machine back in 1998.