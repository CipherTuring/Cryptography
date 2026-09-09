"""
Benchmark suite for the exhaustive search (Exercises 8, 9, 10 and 11).

Subcommands
-----------
sequential   Attack with a single worker for several sizes n of the reduced
             space. The key is placed at a reproducible pseudo-random
             position, so this measures the realistic case: the search
             stops as soon as it finds the key. (Exercise 8)

parallel     Sweep of p = 1, 2, 4, ... workers over a fixed space. Here the
             key is placed at the LAST candidate so that every worker
             exhausts its interval: that way the 2^n candidates are tested
             in all configurations and T_1/T_p measures real speedup and
             not the luck of where the key happened to fall.
             (Exercises 9 and 10)

extrapolate  From the best measured throughput, estimates the time of an
             exhaustive search over the 2^56 effective keys. It runs no
             search at all. (Exercise 11)

all          Runs the three of them in order.

T_1 is measured with `parallel_brute_force(..., workers=1)`, not with the
sequential function: this way the cost of creating processes is present in
ALL configurations and the speedup is not inflated by comparing it against
a run that does not pay that overhead.
"""

import argparse
import json
import statistics
import time
from pathlib import Path

from attacks.brute_force import brute_force_des, make_challenge
from attacks.keyspace import EFFECTIVE_BITS, KeySpace
from attacks.parallel_attack import parallel_brute_force

from .sysinfo import system_info

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

DEFAULT_PLAINTEXT = bytes.fromhex("0123456789ABCDEF")
DEFAULT_BASE_KEY56 = 0x00FEDCBA987654  # known bits, fixed and public

SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86_400
SECONDS_PER_YEAR = 365.25 * SECONDS_PER_DAY


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _write(stem: str, payload: dict, table: str) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / f"{stem}.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (RESULTS_DIR / f"{stem}.txt").write_text(table, encoding="utf-8")
    print(f"\n-> {RESULTS_DIR / f'{stem}.json'}")
    print(f"-> {RESULTS_DIR / f'{stem}.txt'}")


def _stats(values: list[float]) -> dict:
    return {
        "mean": statistics.fmean(values),
        "min": min(values),
        "max": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "runs": values,
    }


def format_duration(seconds: float) -> str:
    """A duration in seconds, also expressed in hours, days and years."""
    return (
        f"{seconds:,.3g} s = {seconds / SECONDS_PER_HOUR:,.3g} h "
        f"= {seconds / SECONDS_PER_DAY:,.3g} d = {seconds / SECONDS_PER_YEAR:,.3g} años"
    )


# --------------------------------------------------------------------------
# Exercise 8: sequential search
# --------------------------------------------------------------------------

def run_sequential(bits: list[int], repeats: int, seed: int, physical_cores) -> dict:
    rows = []
    print("=" * 78)
    print("Ejercicio 8 — Búsqueda exhaustiva secuencial (1 trabajador)")
    print("=" * 78)

    for n in bits:
        keyspace = KeySpace(unknown_bits=n, base_key56=DEFAULT_BASE_KEY56)
        times, tested_counts, positions = [], [], []

        for repeat in range(repeats):
            # A different seed per repeat: different key positions, but
            # reproducible across runs of the benchmark suite.
            secret, ciphertext, candidate = make_challenge(
                keyspace, DEFAULT_PLAINTEXT, seed=seed + 1000 * n + repeat
            )
            result = brute_force_des(
                DEFAULT_PLAINTEXT, ciphertext, 0, keyspace.size, keyspace=keyspace
            )
            if not result.found or result.key != secret:
                raise RuntimeError(f"la búsqueda secuencial falló con n={n}")

            times.append(result.elapsed)
            tested_counts.append(result.tested)
            positions.append(candidate / keyspace.size)
            print(
                f"  n={n:>2} repetición {repeat + 1}/{repeats}: "
                f"{result.tested:>9,} candidatos en {result.elapsed:8.3f} s "
                f"-> {result.throughput:8,.0f} llaves/s "
                f"(llave al {candidate / keyspace.size:.1%} del espacio)"
            )

        mean_time = statistics.fmean(times)
        mean_tested = statistics.fmean(tested_counts)
        rows.append({
            "unknown_bits": n,
            "space_size": keyspace.size,
            "repeats": repeats,
            "time_s": _stats(times),
            "tested": _stats([float(t) for t in tested_counts]),
            "key_position_fraction": _stats(positions),
            # Mean throughput: total candidates / total time, not the mean
            # of the ratios, which would bias towards the short repeats.
            "throughput_keys_per_s": sum(tested_counts) / sum(times),
            "mean_time_s": mean_time,
            "mean_tested": mean_tested,
        })
        print(f"  n={n:>2} MEDIA: {mean_time:.3f} s, "
              f"{rows[-1]['throughput_keys_per_s']:,.0f} llaves/s\n")

    header = (
        f"{'n':>3} {'2^n':>10} {'candidatos (med)':>17} {'tiempo medio [s]':>17} "
        f"{'llaves/s':>12} {'pos. llave':>11}\n"
    )
    table = (
        "Ejercicio 8 — Búsqueda exhaustiva secuencial (1 trabajador)\n"
        + "=" * 78 + "\n"
        + f"Repeticiones por configuración: {repeats}\n"
        + f"La llave se coloca en una posición pseudoaleatoria reproducible.\n\n"
        + header + "-" * 78 + "\n"
    )
    for row in rows:
        table += (
            f"{row['unknown_bits']:>3} {row['space_size']:>10,} "
            f"{row['mean_tested']:>17,.0f} {row['mean_time_s']:>17.3f} "
            f"{row['throughput_keys_per_s']:>12,.0f} "
            f"{row['key_position_fraction']['mean']:>10.1%}\n"
        )

    payload = {
        "experiment": "sequential",
        "system": system_info(physical_cores),
        "plaintext": DEFAULT_PLAINTEXT.hex().upper(),
        "base_key56": f"0x{DEFAULT_BASE_KEY56:014X}",
        "seed": seed,
        "results": rows,
    }
    _write("benchmark_sequential", payload, table)
    return payload


# --------------------------------------------------------------------------
# Exercises 9 and 10: parallel search and performance
# --------------------------------------------------------------------------

def run_parallel(bits: int, worker_counts: list[int], repeats: int,
                 physical_cores) -> dict:
    keyspace = KeySpace(unknown_bits=bits, base_key56=DEFAULT_BASE_KEY56)
    # Key at the last candidate: every worker exhausts its interval, so
    # the 2^n keys are tested for any p and T_1/T_p is clean.
    secret, ciphertext, candidate = make_challenge(
        keyspace, DEFAULT_PLAINTEXT, candidate=keyspace.size - 1
    )

    print("=" * 78)
    print("Ejercicios 9 y 10 — Búsqueda exhaustiva paralela")
    print("=" * 78)
    print(keyspace.describe())
    print(f"llave en el candidato {candidate} (último): se recorre el espacio completo\n")

    rows = []
    for workers in worker_counts:
        times, tested_counts = [], []
        for repeat in range(repeats):
            result = parallel_brute_force(
                DEFAULT_PLAINTEXT, ciphertext, keyspace, workers=workers
            )
            if not result.found or result.key != secret:
                raise RuntimeError(f"la búsqueda paralela falló con p={workers}")
            times.append(result.elapsed)
            tested_counts.append(result.tested)
            print(
                f"  p={workers:>2} repetición {repeat + 1}/{repeats}: "
                f"{result.tested:>9,} candidatos en {result.elapsed:8.3f} s "
                f"-> {result.throughput:9,.0f} llaves/s"
            )

        mean_time = statistics.fmean(times)
        rows.append({
            "workers": workers,
            "repeats": repeats,
            "time_s": _stats(times),
            "tested": _stats([float(t) for t in tested_counts]),
            "mean_time_s": mean_time,
            "mean_tested": statistics.fmean(tested_counts),
            "throughput_keys_per_s": sum(tested_counts) / sum(times),
        })
        print(f"  p={workers:>2} MEDIA: {mean_time:.3f} s, "
              f"{rows[-1]['throughput_keys_per_s']:,.0f} llaves/s\n")

    # S_p = T_1 / T_p and E_p = S_p / p, with T_1 = the p = 1 row. If the
    # sweep did not include p = 1 there is no baseline and the speedup is
    # undefined; the corresponding columns are marked as not available.
    baseline = next((r for r in rows if r["workers"] == 1), None)
    t1 = baseline["mean_time_s"] if baseline else None
    for row in rows:
        row["speedup"] = t1 / row["mean_time_s"] if t1 else None
        row["efficiency"] = row["speedup"] / row["workers"] if t1 else None

    table = (
        "Ejercicios 9 y 10 — Búsqueda exhaustiva paralela\n"
        + "=" * 78 + "\n"
        + f"Espacio: n = {bits} bits desconocidos = {keyspace.size:,} candidatos\n"
        + f"Repeticiones por configuración: {repeats}\n"
        + f"Llave en el último candidato: se recorre el espacio completo para todo p.\n\n"
        + f"{'Workers':>7} {'Time [s]':>10} {'Keys Tested':>13} {'Keys/s':>12} "
          f"{'Speedup':>9} {'Efficiency':>11}\n"
        + "-" * 78 + "\n"
    )
    for row in rows:
        speedup = f"{row['speedup']:.2f}" if row["speedup"] is not None else "n/d"
        efficiency = f"{row['efficiency']:.2f}" if row["efficiency"] is not None else "n/d"
        table += (
            f"{row['workers']:>7} {row['mean_time_s']:>10.3f} "
            f"{row['mean_tested']:>13,.0f} {row['throughput_keys_per_s']:>12,.0f} "
            f"{speedup:>9} {efficiency:>11}\n"
        )
    if t1 is None:
        table += "\n(sin p = 1 en el barrido no hay T_1, así que S_p y E_p no se definen)\n"

    best = max(rows, key=lambda r: r["throughput_keys_per_s"])
    table += (
        f"\nMejor throughput medido: {best['throughput_keys_per_s']:,.0f} llaves/s "
        f"con p = {best['workers']}\n"
    )

    payload = {
        "experiment": "parallel",
        "system": system_info(physical_cores),
        "unknown_bits": bits,
        "space_size": keyspace.size,
        "plaintext": DEFAULT_PLAINTEXT.hex().upper(),
        "base_key56": f"0x{DEFAULT_BASE_KEY56:014X}",
        "key_candidate": candidate,
        "sequential_time_s": t1,
        "best_throughput_keys_per_s": best["throughput_keys_per_s"],
        "best_workers": best["workers"],
        "results": rows,
    }
    _write("benchmark_parallel", payload, table)
    return payload


# --------------------------------------------------------------------------
# Exercise 11: extrapolation to DES-56
# --------------------------------------------------------------------------

def run_extrapolation(throughput: float | None, physical_cores) -> dict:
    if throughput is None:
        source = RESULTS_DIR / "benchmark_parallel.json"
        if not source.exists():
            raise SystemExit(
                "No hay resultados paralelos. Ejecuta primero el subcomando "
                "'parallel' o pasa --throughput."
            )
        throughput = json.loads(source.read_text(encoding="utf-8"))[
            "best_throughput_keys_per_s"
        ]

    total_keys = 1 << EFFECTIVE_BITS
    t_max = total_keys / throughput
    t_avg = (1 << (EFFECTIVE_BITS - 1)) / throughput

    # Reference: the bound from the assignment, a system at 10^6 keys/s.
    reference_rate = 1e6
    t_max_reference = total_keys / reference_rate

    def breakdown(seconds: float) -> dict:
        return {
            "seconds": seconds,
            "hours": seconds / SECONDS_PER_HOUR,
            "days": seconds / SECONDS_PER_DAY,
            "years": seconds / SECONDS_PER_YEAR,
        }

    table = (
        "Ejercicio 11 — Extrapolación al espacio completo de DES (2^56)\n"
        + "=" * 78 + "\n"
        + f"Throughput medido R      : {throughput:,.0f} llaves/s\n"
        + f"Espacio efectivo de DES  : 2^56 = {total_keys:,} llaves\n\n"
        + f"T_max = 2^56 / R  (peor caso, recorrer todo el espacio)\n"
        + f"  {format_duration(t_max)}\n\n"
        + f"T_avg = 2^55 / R  (caso medio, la llave aparece a mitad del recorrido)\n"
        + f"  {format_duration(t_avg)}\n\n"
        + "-" * 78 + "\n"
        + f"Referencia del enunciado: un sistema a 10^6 llaves/s\n"
        + f"  T_max = {format_duration(t_max_reference)}\n"
        + f"Esta implementación en Python puro es "
          f"{reference_rate / throughput:,.0f}x más lenta que esa referencia.\n"
    )
    print(table)

    payload = {
        "experiment": "extrapolation",
        "system": system_info(physical_cores),
        "throughput_keys_per_s": throughput,
        "effective_key_bits": EFFECTIVE_BITS,
        "total_keys": total_keys,
        "t_max": breakdown(t_max),
        "t_avg": breakdown(t_avg),
        "reference_1e6_keys_per_s": {
            "throughput_keys_per_s": reference_rate,
            "t_max": breakdown(t_max_reference),
            "t_avg": breakdown(t_max_reference / 2),
        },
    }
    _write("extrapolation", payload, table)
    return payload


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Banco de pruebas de la búsqueda exhaustiva de llave DES.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--physical-cores", type=int, default=None,
        help="núcleos físicos de la CPU, para anotarlo en los resultados",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    seq = sub.add_parser("sequential", help="Ejercicio 8: un solo trabajador")
    seq.add_argument("--bits", type=int, nargs="+", default=[16, 18, 20])
    seq.add_argument("--repeats", type=int, default=3)
    seq.add_argument("--seed", type=int, default=2024)

    par = sub.add_parser("parallel", help="Ejercicios 9 y 10: barrido de trabajadores")
    par.add_argument("--bits", type=int, default=20)
    par.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4, 8])
    par.add_argument("--repeats", type=int, default=3)

    ext = sub.add_parser("extrapolate", help="Ejercicio 11: extrapolación a 2^56")
    ext.add_argument(
        "--throughput", type=float, default=None,
        help="llaves/s (por defecto: el mejor valor de benchmark_parallel.json)",
    )

    everything = sub.add_parser("all", help="sequential + parallel + extrapolate")
    everything.add_argument("--seq-bits", type=int, nargs="+", default=[16, 18, 20])
    everything.add_argument("--par-bits", type=int, default=20)
    everything.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4, 8])
    everything.add_argument("--repeats", type=int, default=3)
    everything.add_argument("--seed", type=int, default=2024)
    return parser


def main() -> None:
    from console import use_utf8_stdout

    use_utf8_stdout()
    args = _parser().parse_args()
    cores = args.physical_cores
    started = time.perf_counter()

    if args.command == "sequential":
        run_sequential(args.bits, args.repeats, args.seed, cores)
    elif args.command == "parallel":
        run_parallel(args.bits, args.workers, args.repeats, cores)
    elif args.command == "extrapolate":
        run_extrapolation(args.throughput, cores)
    elif args.command == "all":
        run_sequential(args.seq_bits, args.repeats, args.seed, cores)
        print()
        parallel = run_parallel(args.par_bits, args.workers, args.repeats, cores)
        print()
        run_extrapolation(parallel["best_throughput_keys_per_s"], cores)

    print(f"\nTiempo total del banco de pruebas: "
          f"{time.perf_counter() - started:,.1f} s")


if __name__ == "__main__":
    main()
