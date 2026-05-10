"""
crypto/pa13_miller_rabin.py — Miller-Rabin Primality Testing (PA#13).

Allowed imports: os, math, random (SystemRandom only).
NO crypto libraries.
"""

from crypto.utils import random_int, random_bits


def miller_rabin_test(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.

    Args:
        n: The integer to test (must be > 2).
        k: Number of rounds (default 40, giving error probability <= 4^(-40)).

    Returns:
        True if n is probably prime, False if n is definitely composite.

    Algorithm:
        1. Handle edge cases: n < 2 -> False, n == 2 or n == 3 -> True, n even -> False.
        2. Write n - 1 = 2^s * d where d is odd.
        3. For each round i in range(k):
           a. Pick random a in [2, n - 2].
           b. Compute x = pow(a, d, n).
           c. If x == 1 or x == n - 1: continue to next round.
           d. For r in range(s - 1):
              - x = pow(x, 2, n)
              - If x == n - 1: break
           e. If x != n - 1: return False (composite).
        4. Return True (probably prime).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 = 2^s * d with d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random_int(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def gen_prime(bits: int, k: int = 40) -> int:
    """
    Generate a random probable prime of exactly `bits` bits.

    Algorithm:
        1. Loop:
           a. Generate a random `bits`-bit odd integer n (set top bit and bottom bit to 1).
           b. If miller_rabin_test(n, k): return n.

    Args:
        bits: Bit length of the prime.
        k: Miller-Rabin rounds.

    Returns:
        A probable prime integer of exactly `bits` bits.
    """
    while True:
        # Set top bit to ensure exactly `bits` bits; set bottom bit to ensure odd
        n = random_bits(bits) | 1
        if miller_rabin_test(n, k):
            return n


def gen_safe_prime(bits: int, k: int = 40) -> tuple[int, int]:
    """
    Generate a safe prime p = 2q + 1 where q is also prime.

    Args:
        bits: Bit length of p.
        k: Miller-Rabin rounds.

    Returns:
        Tuple (p, q) where p = 2q + 1, both p and q are probable primes.

    Algorithm:
        1. Loop:
           a. Generate a prime q of (bits - 1) bits.
           b. Compute p = 2*q + 1.
           c. If miller_rabin_test(p, k): return (p, q).
    """
    while True:
        q = gen_prime(bits - 1, k)
        p = 2 * q + 1
        if miller_rabin_test(p, k):
            return (p, q)


def is_prime(n: int) -> bool:
    """Convenience wrapper: returns miller_rabin_test(n, 40)."""
    return miller_rabin_test(n, 40)
