"""
crypto/utils.py — Shared utilities for all PAs.

Allowed imports: os, math, struct, random (only SystemRandom for secure randomness).
NO crypto libraries.
"""

import os
import math
import struct
from random import SystemRandom

_sysrand = SystemRandom()


def random_bytes(n: int) -> bytes:
    """Return n cryptographically random bytes using os.urandom."""
    return os.urandom(n)


def random_int(low: int, high: int) -> int:
    """Return a cryptographically random integer in [low, high] inclusive."""
    return _sysrand.randint(low, high)


def random_bits(n: int) -> int:
    """Return a random n-bit integer (i.e., an integer in [2^(n-1), 2^n - 1])."""
    # Top bit is always 1 to ensure exactly n bits
    return _sysrand.getrandbits(n) | (1 << (n - 1))


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(b, 'big')


def int_to_bytes(n: int, length: int = None) -> bytes:
    """Convert integer to bytes (big-endian). Auto-compute length if not given."""
    if length is None:
        length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, 'big')


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    assert len(a) == len(b), f"Length mismatch: {len(a)} vs {len(b)}"
    return bytes(x ^ y for x, y in zip(a, b))


def mod_inverse(a: int, n: int) -> int:
    """
    Compute modular inverse a^(-1) mod n using extended Euclidean algorithm.
    Raises ValueError if gcd(a, n) != 1.
    """
    g, x, _ = extended_gcd(a % n, n)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a}, {n}) = {g}")
    return x % n


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def gcd(a: int, b: int) -> int:
    """Compute GCD using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a
