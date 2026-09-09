"""
DES exhaustive key search parallelized across several CPU cores.

The space [start, end) is split into `p` nearly equal intervals and each
worker process sweeps one of them. The search is CPU-bound and Python
serializes it under the GIL, so PROCESSES (`multiprocessing`) are used
instead of threads; with threads the speedup would be ~1.

Early termination: the workers share a `multiprocessing.Event`. Whoever
finds the key sets it; the others poll the signal once per block of
`chunk` candidates and abandon their interval as soon as they see it.
That is why the total number of candidates tested is usually smaller than
the size of the space, and why the stop is not instantaneous but at most
`chunk` candidates after the hit.

The "spawn" context is used explicitly so that the behaviour is the same
on Windows, macOS and Linux.
"""

import argparse
import multiprocessing as mp
import os
import queue
import time
from dataclasses import dataclass, field

from .brute_force import DEFAULT_CHUNK, brute_force_des, make_challenge
from .keyspace import KeySpace

__all__ = ["WorkerReport", "ParallelResult", "split_range", "parallel_brute_force"]


@dataclass
class WorkerReport:
    """What a worker reports when it finishes its interval."""

    worker_id: int
    start: int
    end: int
    found: bool
    candidate: int | None
    tested: int
    elapsed: float


@dataclass
class ParallelResult:
    """Aggregated result of a parallel exhaustive search."""

    workers: int
    found: bool
    candidate: int | None
    key: bytes | None
    tested: int
    elapsed: float
    per_worker: list[WorkerReport] = field(default_factory=list)

    @property
    def throughput(self) -> float:
        """Aggregated keys tested per second, R = N_tested / T."""
        return self.tested / self.elapsed if self.elapsed > 0 else float("nan")

    def speedup(self, sequential_time: float) -> float:
        """S_p = T_1 / T_p."""
        return sequential_time / self.elapsed if self.elapsed > 0 else float("nan")

    def efficiency(self, sequential_time: float) -> float:
        """E_p = S_p / p."""
        return self.speedup(sequential_time) / self.workers

    def summary(self) -> str:
        lines = [
            f"trabajadores: {self.workers}",
            f"candidatos:   {self.tested}",
            f"tiempo:       {self.elapsed:.3f} s",
            f"throughput:   {self.throughput:,.1f} llaves/s",
        ]
        if self.found:
            assert self.key is not None
            lines += [
                f"llave:        {self.key.hex().upper()}",
                f"candidato:    {self.candidate}",
            ]
        else:
            lines.append("llave:        NO ENCONTRADA")
        for report in self.per_worker:
            flag = " <-- encontró la llave" if report.found else ""
            lines.append(
                f"  worker {report.worker_id}: [{report.start}, {report.end}) "
                f"probó {report.tested} en {report.elapsed:.3f} s{flag}"
            )
        return "\n".join(lines)


def split_range(start: int, end: int, workers: int) -> list[tuple[int, int]]:
    """
    Split [start, end) into `workers` nearly equal contiguous intervals.

    The remainder of the division is handed out one by one to the first
    intervals, so their sizes differ by at most 1 and their union is
    exactly [start, end).
    """
    if workers < 1:
        raise ValueError(f"workers debe ser >= 1, se recibió {workers}")
    if end < start:
        raise ValueError(f"intervalo inválido [{start}, {end})")

    base, extra = divmod(end - start, workers)
    intervals = []
    position = start
    for i in range(workers):
        size = base + (1 if i < extra else 0)
        intervals.append((position, position + size))
        position += size
    return intervals


def _worker_main(
    worker_id: int,
    plaintext: bytes,
    ciphertext: bytes,
    keyspace: KeySpace,
    start: int,
    end: int,
    chunk: int,
    stop_event,
    result_queue,
) -> None:
    """
    Entry point of a worker process.

    It must live at module level so that the "spawn" context can import
    it in the child process. It always enqueues exactly one report, even
    if it does not find the key, so that the parent knows how many
    results to expect.
    """
    result = brute_force_des(
        plaintext, ciphertext, start, end,
        keyspace=keyspace, stop_event=stop_event, chunk=chunk,
    )
    if result.found:
        # Notify the other workers before enqueueing the result.
        stop_event.set()
    result_queue.put(
        WorkerReport(
            worker_id=worker_id,
            start=start,
            end=end,
            found=result.found,
            candidate=result.candidate,
            tested=result.tested,
            elapsed=result.elapsed,
        )
    )


def _collect(processes: list, result_queue, poll: float = 0.5) -> list[WorkerReport]:
    """
    Collect one report per worker, without hanging if one of them dies.

    A `get()` with no timeout would block forever if a child ended
    abnormally before enqueueing its report (for example because of an
    import failure while starting under "spawn"). Here the queue is
    polled with a timeout and, once no process is alive any more, a final
    drain is performed and whatever is there is returned: the caller
    detects the missing report and warns about it.
    """
    reports: list[WorkerReport] = []
    while len(reports) < len(processes):
        try:
            reports.append(result_queue.get(timeout=poll))
            continue
        except queue.Empty:
            pass
        if any(process.is_alive() for process in processes):
            continue
        # All of them have finished. Drain what is left, with a short
        # timeout instead of get_nowait(): an item enqueued right before
        # the process died may still be in transit through the feeder
        # thread of the queue.
        while len(reports) < len(processes):
            try:
                reports.append(result_queue.get(timeout=poll))
            except queue.Empty:
                return reports
    return reports


def parallel_brute_force(
    plaintext: bytes,
    ciphertext: bytes,
    keyspace: KeySpace,
    workers: int,
    start: int = 0,
    end: int | None = None,
    chunk: int = DEFAULT_CHUNK,
) -> ParallelResult:
    """
    Run the exhaustive search splitting [start, end) across `workers`
    processes, and return the aggregated result.

    The measured time includes process creation: it is the real time the
    parallel attack costs. For the comparison to be fair, T_1 must be
    measured by calling this same function with `workers=1`, so that the
    same overhead is present in every configuration.
    """
    if end is None:
        end = keyspace.size

    context = mp.get_context("spawn")
    stop_event = context.Event()
    result_queue = context.Queue()
    intervals = split_range(start, end, workers)

    clock = time.perf_counter
    t0 = clock()

    processes = [
        context.Process(
            target=_worker_main,
            args=(i, plaintext, ciphertext, keyspace, lo, hi, chunk,
                  stop_event, result_queue),
            daemon=True,
        )
        for i, (lo, hi) in enumerate(intervals)
    ]
    for process in processes:
        process.start()

    # Drain the queue BEFORE joining the processes: a child that has
    # enqueued an object does not finish until the item has been drained,
    # so join() before get() could block indefinitely.
    reports = _collect(processes, result_queue)
    for process in processes:
        process.join()

    if len(reports) != len(processes):
        codes = [p.exitcode for p in processes]
        raise RuntimeError(
            f"solo {len(reports)} de {len(processes)} trabajadores reportaron; "
            f"códigos de salida: {codes}"
        )

    elapsed = clock() - t0
    reports.sort(key=lambda r: r.worker_id)

    winner = next((r for r in reports if r.found), None)
    return ParallelResult(
        workers=workers,
        found=winner is not None,
        candidate=winner.candidate if winner else None,
        key=keyspace.key(winner.candidate) if winner and winner.candidate is not None else None,
        tested=sum(r.tested for r in reports),
        elapsed=elapsed,
        per_worker=reports,
    )


def _main() -> None:
    from console import use_utf8_stdout

    use_utf8_stdout()
    parser = argparse.ArgumentParser(
        description="Ataque de texto plano conocido a DES por búsqueda exhaustiva "
        "paralela sobre un espacio de llaves reducido."
    )
    parser.add_argument(
        "-n", "--bits", type=int, default=18,
        help="bits efectivos desconocidos de la llave (por defecto: 18)",
    )
    parser.add_argument(
        "-p", "--workers", type=int, default=os.cpu_count() or 1,
        help="número de procesos trabajadores (por defecto: núcleos lógicos)",
    )
    parser.add_argument(
        "--base", type=lambda s: int(s, 0), default=0,
        help="valor de los 56 bits efectivos conocidos (por defecto: 0)",
    )
    parser.add_argument(
        "--plaintext", default="0123456789ABCDEF",
        help="bloque de texto plano conocido, en hexadecimal (8 bytes)",
    )
    parser.add_argument(
        "--candidate", type=int, default=None,
        help="posición exacta de la llave en el espacio (por defecto: aleatoria)",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="semilla para elegir la posición de la llave de forma reproducible",
    )
    parser.add_argument(
        "--chunk", type=int, default=DEFAULT_CHUNK,
        help=f"candidatos entre consultas de la señal de parada (por defecto: {DEFAULT_CHUNK})",
    )
    args = parser.parse_args()

    keyspace = KeySpace(unknown_bits=args.bits, base_key56=args.base)
    plaintext = bytes.fromhex(args.plaintext)
    secret_key, ciphertext, candidate = make_challenge(
        keyspace, plaintext, candidate=args.candidate, seed=args.seed
    )

    print(keyspace.describe())
    print(f"texto plano conocido: {plaintext.hex().upper()}")
    print(f"criptograma conocido: {ciphertext.hex().upper()}")
    print(f"(la llave secreta está en el candidato {candidate}; el buscador no la ve)\n")

    result = parallel_brute_force(
        plaintext, ciphertext, keyspace, workers=args.workers, chunk=args.chunk
    )
    print(result.summary())

    ok = result.found and result.key == secret_key
    print(f"\nllave recuperada correctamente: {ok}")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    _main()
