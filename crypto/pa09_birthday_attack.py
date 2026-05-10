"""
PA#9 — Birthday Attack (Collision Finding).

Two algorithms:
    1. Naive birthday (hash-table based): O(2^(n/2)) time, O(2^(n/2)) space.
    2. Floyd's cycle detection: O(2^(n/2)) time, O(1) space.

Dependencies:
    - crypto.pa08_dlp_hash (DLPHash, for attacking truncated output)
    - crypto.utils
"""

from crypto.pa08_dlp_hash import DLPHash
from crypto.utils import random_bytes, bytes_to_int, int_to_bytes
import math


def naive_birthday_attack(hash_fn: callable, output_bits: int,
                          max_attempts: int = None) -> dict:
    """
    Naive birthday attack using a hash table / dictionary.

    Algorithm:
        1. seen = {}  (maps hash_output → input)
        2. counter = 0
        3. Loop:
           a. x = random input (random bytes, or counter as bytes)
           b. h = hash_fn(x), truncated/interpreted as output_bits bits.
           c. counter += 1
           d. If h in seen AND seen[h] != x:
              return collision (x, seen[h], h)
           e. seen[h] = x
           f. If counter > max_attempts: return failure.
    """
    if max_attempts is None:
        max_attempts = int(10 * (2 ** (output_bits / 2)))

    expected = 1.25 * (2 ** (output_bits / 2))

    n_bytes = (output_bits + 7) // 8

    seen = {}
    counter = 0
    # Use a larger input size so different inputs can hash to the same value
    input_size = max(n_bytes * 2, 4)

    while counter < max_attempts:
        x = random_bytes(input_size)
        h = hash_fn(x)
        counter += 1

        if h in seen and seen[h] != x:
            ratio = counter / (2 ** (output_bits / 2))
            return {
                'collision_found': True,
                'input_1': x,
                'input_2': seen[h],
                'hash_value': h,
                'evaluations': counter,
                'expected_evaluations': expected,
                'ratio': ratio,
            }
        seen[h] = x

    return {
        'collision_found': False,
        'input_1': None,
        'input_2': None,
        'hash_value': None,
        'evaluations': counter,
        'expected_evaluations': expected,
        'ratio': counter / (2 ** (output_bits / 2)),
    }


def floyds_cycle_attack(hash_fn: callable, output_bits: int,
                        max_attempts: int = None) -> dict:
    """
    Floyd's cycle-finding birthday attack (space-efficient).

    Treat the hash as a function f: {0,1}^n → {0,1}^n.
    The sequence x0, f(x0), f(f(x0)), ... must eventually cycle,
    implying a collision.
    """
    if max_attempts is None:
        max_attempts = int(10 * (2 ** (output_bits / 2)))

    expected = 1.25 * (2 ** (output_bits / 2))

    n_bytes = (output_bits + 7) // 8

    def f(x_bytes: bytes) -> bytes:
        """The iterated function: hash and truncate to n bits."""
        full_hash = hash_fn(x_bytes)
        truncated = bytearray(full_hash[:n_bytes])
        if output_bits % 8 != 0:
            mask = (0xFF << (8 - (output_bits % 8))) & 0xFF
            truncated[-1] &= mask
        return bytes(truncated)

    # Starting point
    x0 = random_bytes(n_bytes)

    evaluations = 0

    # Phase 1: Floyd's tortoise and hare
    tortoise = f(x0)
    hare = f(f(x0))
    evaluations += 3

    while tortoise != hare:
        if evaluations > max_attempts:
            return {
                'collision_found': False,
                'input_1': None,
                'input_2': None,
                'hash_value': None,
                'evaluations': evaluations,
                'expected_evaluations': expected,
                'ratio': evaluations / (2 ** (output_bits / 2)),
            }
        tortoise = f(tortoise)
        hare = f(f(hare))
        evaluations += 3

    # Phase 2: Find the actual collision pair
    # Reset tortoise to x0, advance both at same speed to find cycle entry
    tortoise = x0
    while True:
        prev_tortoise = tortoise
        prev_hare = hare
        tortoise = f(tortoise)
        hare = f(hare)
        evaluations += 2

        if prev_tortoise != prev_hare and f(prev_tortoise) == f(prev_hare):
            # Found: prev_tortoise and prev_hare are different but hash to same value
            collision_hash = f(prev_tortoise)
            ratio = evaluations / (2 ** (output_bits / 2))
            return {
                'collision_found': True,
                'input_1': prev_tortoise,
                'input_2': prev_hare,
                'hash_value': collision_hash,
                'evaluations': evaluations,
                'expected_evaluations': expected,
                'ratio': ratio,
            }

        if tortoise == hare:
            # Cycle detected but no collision found yet — use naive fallback
            break

        if evaluations > max_attempts:
            break

    # Fallback: if Floyd's didn't cleanly extract, use naive approach
    return naive_birthday_attack(hash_fn, output_bits, max_attempts)


def attack_toy_hash(output_bits: int = 16) -> dict:
    """
    Attack a deliberately weak toy hash (XOR-based) with the birthday attack.
    """
    n_bytes = (output_bits + 7) // 8
    mask = (1 << output_bits) - 1

    def toy_hash(x: bytes) -> bytes:
        h = 0
        for i, b in enumerate(x):
            h = ((h * 31 + b + i) ^ (h >> 3)) & mask
        return h.to_bytes(n_bytes, 'big')

    result = naive_birthday_attack(toy_hash, output_bits=output_bits)
    return {
        'output_bits': output_bits,
        'collision': result,
        'evaluations': result['evaluations'],
    }


def attack_truncated_dlp_hash(output_bits: int = 16, dlp_bits: int = 64) -> dict:
    """
    Attack the PA#8 DLP hash with truncated output.

    1. Create DLPHash(bits=dlp_bits).
    2. Define hash_fn(x) = hasher.hash_truncated(x, output_bits).
    3. Run naive_birthday_attack.
    4. Report results.
    """
    hasher = DLPHash(bits=dlp_bits)

    def hash_fn(x: bytes) -> bytes:
        return hasher.hash_truncated(x, output_bits)

    result = naive_birthday_attack(hash_fn, output_bits=output_bits)

    return {
        'output_bits': output_bits,
        'evaluations': result['evaluations'],
        'expected': result['expected_evaluations'],
        'ratio': result['ratio'],
        'input_1_hex': result['input_1'].hex() if result['input_1'] else None,
        'input_2_hex': result['input_2'].hex() if result['input_2'] else None,
        'shared_hash_hex': result['hash_value'].hex() if result['hash_value'] else None,
    }


def empirical_birthday_curve(hash_fn: callable, output_bits: int,
                              num_trials: int = 100) -> dict:
    """
    Run `num_trials` independent birthday attack trials.
    For each trial, record the number of evaluations until first collision.
    """
    eval_counts = []
    expected = 1.25 * (2 ** (output_bits / 2))

    for _ in range(num_trials):
        result = naive_birthday_attack(hash_fn, output_bits=output_bits)
        eval_counts.append(result['evaluations'])

    mean_evals = sum(eval_counts) / len(eval_counts)
    variance = sum((x - mean_evals) ** 2 for x in eval_counts) / len(eval_counts)
    std_evals = variance ** 0.5

    return {
        'output_bits': output_bits,
        'num_trials': num_trials,
        'eval_counts': eval_counts,
        'mean_evals': mean_evals,
        'std_evals': std_evals,
        'expected_evals': expected,
        'mean_ratio': mean_evals / (2 ** (output_bits / 2)),
    }


def md5_sha1_context() -> dict:
    """
    Compute 2^(n/2) for MD5 (n=128) and SHA-1 (n=160).
    Express in terms of modern CPU speed.

    Assume: 10^9 hashes/second.
    """
    hashes_per_sec = 1e9
    result = {}
    for name, n in [('md5', 128), ('sha1', 160), ('sha256', 256)]:
        bound = 2 ** (n // 2)
        seconds = bound / hashes_per_sec
        years = seconds / (365.25 * 24 * 3600)
        status_map = {
            'md5': 'broken (2005)',
            'sha1': 'deprecated (2017)',
            'sha256': 'currently secure'
        }
        result[name] = {
            'output_bits': n,
            'birthday_bound': bound,
            'seconds': seconds,
            'years': years,
            'status': status_map[name]
        }
    return result
