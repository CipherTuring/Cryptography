# Laboratory 3 — AES implementation and evaluation

An implementation of the Advanced Encryption Standard written from FIPS PUB 197,
supporting 128-, 192- and 256-bit keys, with an automatic test suite validated
against the published test vectors and an experimental evaluation of its
performance over 1, 10 and 100 MB.

No cryptographic library is used anywhere in the core. Neither is any
cryptographic constant: the S-box, the inverse S-box, the round constants and
the lookup tables of the fast backend are all computed at import time from the
arithmetic of GF(2⁸). The published tables appear only in `tests/vectors.py`,
where they act as an external oracle rather than as an ingredient.

---

## Language and dependencies

| | |
|---|---|
| Language | Python 3.12 (no cryptographic libraries) |
| Tests | `pytest` |
| Figures | `matplotlib` |
| Core dependencies | none — `aeslib` uses only the standard library |

`aeslib` imports nothing outside the standard library. `pytest` and `matplotlib`
are needed only to run the tests and to draw the figures.

## Installation

```bash
git clone <repository-url>
cd Cryptography/aes_lab_3
pip install pytest matplotlib
```

There is nothing to build. `conftest.py` puts the laboratory directory on
`sys.path`, so the packages import without being installed. Every command below
is run from inside `aes_lab_3/`.

## Running the tests

```bash
python -m pytest tests/ -v
```

1649 tests, about 7 seconds. They must all pass before the performance
evaluation is run; this is the requirement of Exercise 2.

To check one layer at a time:

```bash
python -m pytest tests/test_gf.py -v            # GF(2^8) arithmetic
python -m pytest tests/test_sbox.py -v          # the S-box, against FIPS-197
python -m pytest tests/test_transforms.py -v    # the round transformations
python -m pytest tests/test_key_schedule.py -v  # the key schedule, 3 key sizes
python -m pytest tests/test_cipher.py -v        # the published test vectors
python -m pytest tests/test_backends.py -v      # reference vs fast backend
```

## Using the implementation

```python
from aeslib import AES

key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
aes = AES(key)                      # AES-128, 10 rounds

block = bytes.fromhex("00112233445566778899aabbccddeeff")
ciphertext = aes.encrypt_block(block)
assert ciphertext.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
assert aes.decrypt_block(ciphertext) == block
```

The key length alone selects the variant:

```python
AES(bytes(16)).rounds    # 10   AES-128
AES(bytes(24)).rounds    # 12   AES-192
AES(bytes(32)).rounds    # 14   AES-256
```

Whole buffers whose length is a multiple of 16 bytes:

```python
aes = AES(key, backend="fast")      # the table-driven core
data = bytes(1024)
assert aes.decrypt(aes.encrypt(data)) == data
```

Two backends compute the same function. `reference` is the literal
implementation of FIPS-197, one named transformation per step; `fast` folds a
round into table lookups and is around 45 times quicker. `tests/test_backends.py`
requires them to agree byte for byte, so the choice is about speed and never
about the result.

## Reproducing the experiments

```bash
python -m benchmarks.benchmark_aes      # Exercise 3: the full matrix
python -m benchmarks.plot_results       # Exercise 4: the figures
```

**The full benchmark takes about 50 minutes** and saturates one core. It
measures 1, 10 and 100 MB against the three key sizes, in both directions,
three times each.

While it runs, keep the machine awake and free of heavy applications. Wall-clock
time is what throughput is defined on, so a machine that suspends or is busy
with something else corrupts the measurement. The harness detects this: it
compares wall-clock time against CPU time, and if any timed interval spent too
long off the processor it **writes nothing** and reports which measurements were
affected. A number describing the machine rather than the algorithm is worse
than no number.

To check that the harness works without waiting fifty minutes:

```bash
python -m benchmarks.benchmark_aes --quick          # 1 MB, 2 repetitions, ~20 s
python -m benchmarks.benchmark_aes --sizes 1 5 --repeats 2
python -m benchmarks.benchmark_aes --backend reference --sizes 0.05
```

`--quick` is a smoke test of the plumbing, not a measurement worth reporting.

Drawing the figures re-reads `results/benchmark_aes.json` and never re-measures,
so the figures can be adjusted freely without paying for the benchmark again.

## Project structure

```
aes_lab_3/
├── aeslib/                  Exercise 1: the cryptographic core
│   ├── gf.py                GF(2^8) over x^8+x^4+x^3+x+1; the only place
│   │                        the field is implemented
│   ├── sbox.py              S-box and inverse S-box, computed from gf
│   ├── state.py             the 128-bit state, 4x4 column-major
│   ├── transforms.py        SubBytes/ShiftRows/MixColumns/AddRoundKey
│   │                        and their inverses, one function each
│   ├── key_schedule.py      one algorithm parameterised by Nk = 4, 6, 8
│   ├── cipher.py            Cipher and InvCipher, step by step
│   ├── fast.py              table-driven backend for the benchmark
│   └── api.py               the AES class: the public interface
├── tests/                   Exercise 2: validation
│   ├── vectors.py           FIPS-197 and NIST SP 800-38A, transcribed
│   └── test_*.py            1649 tests
├── benchmarks/              Exercises 3 and 4
│   ├── benchmark_aes.py     times, throughput, reliability check
│   ├── plot_results.py      the four figures
│   ├── report.py            writes each result as .txt next to .json
│   └── sysinfo.py           the machine the numbers come from
├── results/                 the deliverable measurements and figures
├── report/lab3-report.md    the technical report
├── conftest.py              puts the laboratory root on sys.path
└── console.py               UTF-8 stdout on Windows
```

Cryptographic code, tests, benchmarks and results are kept in separate packages,
as the assignment requires. `aeslib` imports nothing from `tests` or
`benchmarks`; `benchmarks` imports `aeslib` but never `tests`.

## Design notes

- **Nothing cryptographic is written by hand.** The S-box is built by inverting
  in GF(2⁸) and applying the affine transformation; the round constants are
  successive powers of x; the eight tables of the fast backend are built from
  the S-box and the MixColumns matrices. Building them costs 13 ms once, at
  import, and nothing afterwards — the tables that result are the same objects a
  pasted constant would give. What it buys is that the comparison against
  FIPS-197 in the tests is a real check rather than a file compared with itself.

- **One key schedule for the three variants.** The expansion is parameterised by
  Nk, with Nr = Nk + 6. The single branch that depends on the key size is the
  extra `SubWord` applied when Nk > 6, which is what distinguishes AES-256.

- **Two backends, proven equivalent.** The reference core reaches 0.018 MB/s,
  which would put a single 100 MB pass at about an hour and a half. The
  table-driven backend reaches 0.83 MB/s. Using it for the benchmark is only
  legitimate because the suite requires the two to produce identical bytes in
  both directions, for all three key sizes, and to be interchangeable
  mid-operation: each decrypts what the other encrypted.

- **The benchmark measures the core.** The key schedule runs once, in the
  constructor, outside the timed region; the data buffer is generated before the
  clock starts; a garbage collection is forced before each repetition. Every
  repetition also decrypts what it encrypted and verifies the plaintext comes
  back, so correctness is confirmed while the numbers are taken.

- **Contaminated measurements are refused, not reported.** CPU time is recorded
  alongside wall-clock time. A first attempt produced a reading of 11 076 s for
  one 100 MB decryption — three hours in which the process was not running. The
  harness now rejects such a run instead of publishing it.

- **Everything is in English**, including exception messages, command-line help
  and figure labels. This departs from `des_lab_2/`, which used English for
  documentation and Spanish for runtime output.

## Security warning

**This implementation is educational and must not be used to protect real data.**

- The buffer operations apply the core to each block independently, which is raw
  ECB. Identical plaintext blocks produce identical ciphertext blocks, so the
  structure of the data is visible in the ciphertext. There is no mode of
  operation, no initialisation vector and no authentication.
- The implementation is not constant-time. The table lookups of the fast backend
  make it vulnerable to cache-timing attacks, which is exactly how AES
  implementations of this shape have been broken in practice.
- The benchmark exists to measure the cryptographic core, as the assignment
  states. It is not a model of how AES should be used.

## Results

Measured on:

| | |
|---|---|
| CPU | Intel Core i5-8300H @ 2.30 GHz |
| Logical cores | 8 |
| Platform | Windows 11 (10.0.26200) |
| Python | CPython 3.12.10 |
| Backend | `fast` |
| Repetitions | 3 per measurement, averaged |
| Off-CPU time | at most 2.0 % of any timed interval |

### Encryption

| Data | AES-128 | AES-192 | AES-256 |
|---|---|---|---|
| 1 MB | 1.32 s — 0.758 MB/s | 1.50 s — 0.667 MB/s | 1.71 s — 0.584 MB/s |
| 10 MB | 12.03 s — 0.831 MB/s | 14.40 s — 0.694 MB/s | 16.74 s — 0.598 MB/s |
| 100 MB | 121.07 s — 0.826 MB/s | 144.44 s — 0.692 MB/s | 167.51 s — 0.597 MB/s |

### Decryption

| Data | AES-128 | AES-192 | AES-256 |
|---|---|---|---|
| 1 MB | 1.30 s — 0.770 MB/s | 1.50 s — 0.666 MB/s | 1.69 s — 0.592 MB/s |
| 10 MB | 11.99 s — 0.834 MB/s | 14.24 s — 0.702 MB/s | 16.57 s — 0.604 MB/s |
| 100 MB | 120.60 s — 0.829 MB/s | 144.09 s — 0.694 MB/s | 166.67 s — 0.600 MB/s |

### Cost follows the number of rounds

Throughput relative to AES-128, against the ratio the round counts predict:

| Data | AES-192 measured | 10/12 | AES-256 measured | 10/14 |
|---|---|---|---|---|
| 1 MB | 0.879 | 0.833 | 0.769 | 0.714 |
| 10 MB | 0.836 | 0.833 | 0.719 | 0.714 |
| 100 MB | 0.838 | 0.833 | 0.723 | 0.714 |

At 10 and 100 MB the prediction holds to within 1 %. The full analysis is in
[`report/lab3-report.md`](report/lab3-report.md); the raw numbers are in
[`results/benchmark_aes.json`](results/benchmark_aes.json) and the figures
alongside them.
