"""
Tests of the exhaustive search, sequential and parallel (Exercises 7, 8 and 9).

All the search spaces are deliberately small (n <= 11, that is <= 2048
candidates) so that the suite finishes in seconds. With the pure-Python DES
of Laboratory 1 about 2.6k keys/s are tested.
"""

import pytest

from attacks.brute_force import brute_force_des, make_challenge, verify_key
from attacks.keyspace import KeySpace
from attacks.parallel_attack import parallel_brute_force, split_range
from deslib import des_encrypt_block

PLAINTEXT = bytes.fromhex("0123456789ABCDEF")
BASE = 0x00FEDCBA987654


# ---------------------------------------------------------------------------
# Splitting the search space
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("total,workers", [(10, 3), (1024, 8), (100, 7), (5, 8), (0, 4)])
def test_split_range_covers_the_space_exactly(total, workers):
    intervals = split_range(0, total, workers)

    assert len(intervals) == workers
    assert intervals[0][0] == 0
    assert intervals[-1][1] == total
    # Contiguous, with no gaps and no overlaps.
    for (_, end), (start, _) in zip(intervals, intervals[1:]):
        assert end == start
    # They cover every index exactly once.
    covered = [i for lo, hi in intervals for i in range(lo, hi)]
    assert covered == list(range(total))
    # Balanced sizes: they differ by at most 1.
    sizes = [hi - lo for lo, hi in intervals]
    assert max(sizes) - min(sizes) <= 1


def test_split_range_honours_a_non_zero_start():
    assert split_range(100, 110, 2) == [(100, 105), (105, 110)]


@pytest.mark.parametrize("workers", [0, -1])
def test_split_range_rejects_invalid_worker_count(workers):
    with pytest.raises(ValueError):
        split_range(0, 10, workers)


# ---------------------------------------------------------------------------
# Sequential search
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("candidate", [0, 1, 137, 255])
def test_sequential_recovers_the_key(candidate):
    keyspace = KeySpace(unknown_bits=8, base_key56=BASE)
    secret, ciphertext, _ = make_challenge(keyspace, PLAINTEXT, candidate=candidate)

    result = brute_force_des(
        PLAINTEXT, ciphertext, 0, keyspace.size, keyspace=keyspace
    )

    assert result.found
    assert result.candidate == candidate
    assert result.key == secret
    assert verify_key(result.key, [(PLAINTEXT, ciphertext)])


def test_search_stops_as_soon_as_it_finds_the_key():
    """It must not keep testing candidates after the hit."""
    keyspace = KeySpace(unknown_bits=10, base_key56=BASE)
    _, ciphertext, candidate = make_challenge(keyspace, PLAINTEXT, candidate=300)

    result = brute_force_des(PLAINTEXT, ciphertext, 0, keyspace.size, keyspace=keyspace)

    assert result.tested == candidate + 1
    assert result.tested < keyspace.size


def test_reports_failure_when_the_key_is_outside_the_interval():
    keyspace = KeySpace(unknown_bits=8, base_key56=BASE)
    _, ciphertext, _ = make_challenge(keyspace, PLAINTEXT, candidate=200)

    result = brute_force_des(PLAINTEXT, ciphertext, 0, 100, keyspace=keyspace)

    assert not result.found
    assert result.key is None
    assert result.candidate is None
    assert result.tested == 100


def test_throughput_and_timing_are_measured():
    keyspace = KeySpace(unknown_bits=8, base_key56=BASE)
    _, ciphertext, _ = make_challenge(keyspace, PLAINTEXT, candidate=255)

    result = brute_force_des(PLAINTEXT, ciphertext, 0, keyspace.size, keyspace=keyspace)

    assert result.elapsed > 0
    assert result.throughput > 0
    assert result.tested == pytest.approx(result.throughput * result.elapsed, rel=1e-6)


def test_the_search_is_not_hard_coded():
    """
    The key is discovered by testing candidates, not by reading it from
    anywhere: with a ciphertext that matches no key of the space, the
    search must exhaust the interval and find nothing.
    """
    keyspace = KeySpace(unknown_bits=9, base_key56=BASE)
    unreachable = des_encrypt_block(bytes.fromhex("0011223344556677"), PLAINTEXT)

    result = brute_force_des(PLAINTEXT, unreachable, 0, keyspace.size, keyspace=keyspace)

    assert not result.found
    assert result.tested == keyspace.size


def test_interval_boundaries_are_half_open():
    """[start, end): the candidate `end` is not tested."""
    keyspace = KeySpace(unknown_bits=8, base_key56=BASE)
    _, ciphertext, _ = make_challenge(keyspace, PLAINTEXT, candidate=50)

    assert not brute_force_des(PLAINTEXT, ciphertext, 0, 50, keyspace=keyspace).found
    assert brute_force_des(PLAINTEXT, ciphertext, 0, 51, keyspace=keyspace).found
    assert brute_force_des(PLAINTEXT, ciphertext, 50, 51, keyspace=keyspace).found


@pytest.mark.parametrize("start,end", [(0, 1000), (-1, 10), (10, 5)])
def test_rejects_invalid_intervals(start, end):
    keyspace = KeySpace(unknown_bits=8, base_key56=BASE)
    with pytest.raises(ValueError):
        brute_force_des(PLAINTEXT, bytes(8), start, end, keyspace=keyspace)


@pytest.mark.parametrize("block", [bytes(7), bytes(9)])
def test_rejects_blocks_of_wrong_length(block):
    with pytest.raises(ValueError):
        brute_force_des(block, bytes(8), 0, 1)
    with pytest.raises(ValueError):
        brute_force_des(bytes(8), block, 0, 1)


def test_default_keyspace_is_the_full_56_bit_space():
    """Without `keyspace`, the candidate integer is directly the effective key."""
    keyspace = KeySpace(unknown_bits=56)
    secret, ciphertext, _ = make_challenge(keyspace, PLAINTEXT, candidate=77)

    result = brute_force_des(PLAINTEXT, ciphertext, 0, 200)

    assert result.found
    assert result.candidate == 77
    assert result.key == secret


# ---------------------------------------------------------------------------
# Parallel search
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("workers", [1, 2, 4])
def test_parallel_recovers_the_key(workers):
    keyspace = KeySpace(unknown_bits=10, base_key56=BASE)
    secret, ciphertext, candidate = make_challenge(keyspace, PLAINTEXT, candidate=700)

    result = parallel_brute_force(PLAINTEXT, ciphertext, keyspace, workers=workers)

    assert result.found
    assert result.candidate == candidate
    assert result.key == secret
    assert result.workers == workers
    assert len(result.per_worker) == workers
    assert sum(r.found for r in result.per_worker) == 1


def test_parallel_and_sequential_agree():
    keyspace = KeySpace(unknown_bits=10, base_key56=BASE)
    _, ciphertext, _ = make_challenge(keyspace, PLAINTEXT, candidate=613)

    sequential = brute_force_des(PLAINTEXT, ciphertext, 0, keyspace.size, keyspace=keyspace)
    parallel = parallel_brute_force(PLAINTEXT, ciphertext, keyspace, workers=4)

    assert sequential.candidate == parallel.candidate
    assert sequential.key == parallel.key


def test_parallel_stops_early_after_a_hit():
    """
    With the key near the start of the space and several workers, the total
    number of candidates tested must stay well below the size of the space.
    """
    keyspace = KeySpace(unknown_bits=11, base_key56=BASE)
    _, ciphertext, _ = make_challenge(keyspace, PLAINTEXT, candidate=5)

    result = parallel_brute_force(PLAINTEXT, ciphertext, keyspace, workers=4)

    assert result.found
    assert result.tested < keyspace.size


def test_parallel_reports_failure_when_the_key_is_absent():
    keyspace = KeySpace(unknown_bits=9, base_key56=BASE)
    unreachable = des_encrypt_block(bytes.fromhex("0011223344556677"), PLAINTEXT)

    result = parallel_brute_force(PLAINTEXT, unreachable, keyspace, workers=2)

    assert not result.found
    assert result.key is None
    assert result.tested == keyspace.size  # the whole space was exhausted


def test_parallel_workers_cover_disjoint_intervals():
    keyspace = KeySpace(unknown_bits=9, base_key56=BASE)
    unreachable = des_encrypt_block(bytes.fromhex("0011223344556677"), PLAINTEXT)

    result = parallel_brute_force(PLAINTEXT, unreachable, keyspace, workers=4)

    intervals = [(r.start, r.end) for r in result.per_worker]
    assert intervals == split_range(0, keyspace.size, 4)
    assert sum(r.tested for r in result.per_worker) == keyspace.size


def test_parallel_metrics_are_computed():
    keyspace = KeySpace(unknown_bits=9, base_key56=BASE)
    _, ciphertext, _ = make_challenge(keyspace, PLAINTEXT, candidate=keyspace.size - 1)

    result = parallel_brute_force(PLAINTEXT, ciphertext, keyspace, workers=2)

    assert result.elapsed > 0
    assert result.throughput > 0
    # S_p = T_1 / T_p and E_p = S_p / p
    assert result.speedup(2 * result.elapsed) == pytest.approx(2.0)
    assert result.efficiency(2 * result.elapsed) == pytest.approx(1.0)
