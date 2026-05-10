"""
Tests for PA#13 — Miller-Rabin Primality Testing.
"""
import pytest
from crypto.pa13_miller_rabin import miller_rabin_test, gen_prime, gen_safe_prime, is_prime


def test_known_primes():
    """Test that known primes all return True."""
    primes = [2, 3, 5, 7, 11, 13, 97, 101, 7919, 104729]
    for p in primes:
        assert miller_rabin_test(p) is True, f"Expected {p} to be prime"


def test_known_composites():
    """Test that known composites all return False."""
    composites = [4, 6, 8, 9, 15, 21, 100, 1000]
    for c in composites:
        assert miller_rabin_test(c) is False, f"Expected {c} to be composite"


def test_carmichael_561():
    """Test that 561 (smallest Carmichael number) is correctly identified as COMPOSITE."""
    # 561 = 3 * 11 * 17 — Fermat test would pass but Miller-Rabin should catch it
    assert miller_rabin_test(561, 10) is False, "561 is composite (Carmichael number)"


def test_carmichael_others():
    """Test that more Carmichael numbers are identified as composite."""
    carmichaels = [1105, 1729]
    for c in carmichaels:
        assert miller_rabin_test(c) is False, f"Expected {c} to be composite (Carmichael)"


def test_gen_prime_512():
    """Generate a 512-bit prime, verify bit length and Miller-Rabin with 100 rounds."""
    p = gen_prime(512)
    assert p.bit_length() == 512, f"Expected 512-bit prime, got {p.bit_length()} bits"
    assert miller_rabin_test(p, 100) is True, "Generated prime failed Miller-Rabin (100 rounds)"


def test_gen_prime_1024():
    """Generate a 1024-bit prime, verify bit length and Miller-Rabin with 100 rounds."""
    p = gen_prime(1024)
    assert p.bit_length() == 1024, f"Expected 1024-bit prime, got {p.bit_length()} bits"
    assert miller_rabin_test(p, 100) is True, "Generated prime failed Miller-Rabin (100 rounds)"


def test_gen_safe_prime():
    """Generate a 256-bit safe prime. Verify p = 2q + 1 and both pass Miller-Rabin."""
    p, q = gen_safe_prime(256)
    assert p == 2 * q + 1, "Safe prime condition p = 2q + 1 violated"
    assert miller_rabin_test(p) is True, "Safe prime p failed Miller-Rabin"
    assert miller_rabin_test(q) is True, "Sophie Germain prime q failed Miller-Rabin"
    assert p.bit_length() == 256, f"Expected 256-bit safe prime, got {p.bit_length()} bits"


def test_prime_generation_count():
    """Generate 10 primes of 512 bits, observe candidate count vs theoretical expectation."""
    import math
    total_candidates = 0
    num_primes = 10
    bits = 512
    theoretical = bits * math.log(2)  # ≈ 355

    # Monkey-patch to count calls
    original_test = miller_rabin_test

    call_counts = []
    for _ in range(num_primes):
        count = 0
        from crypto import utils as u
        while True:
            n = u.random_bits(bits) | 1
            count += 1
            if original_test(n):
                call_counts.append(count)
                break

    avg_candidates = sum(call_counts) / len(call_counts)
    print(f"\nAverage candidates tested: {avg_candidates:.1f}")
    print(f"Theoretical O(bits * ln(2)) ≈ {theoretical:.1f}")
    # Just verify we generated the right number
    assert len(call_counts) == num_primes


def test_edge_cases():
    """Test n=0, n=1, n=2, n=3, n=-5 are handled correctly."""
    assert miller_rabin_test(0) is False
    assert miller_rabin_test(1) is False
    assert miller_rabin_test(2) is True
    assert miller_rabin_test(3) is True
    assert miller_rabin_test(-5) is False


def test_is_prime_wrapper():
    """Verify is_prime is a correct convenience wrapper."""
    assert is_prime(7) is True
    assert is_prime(9) is False
    assert is_prime(97) is True
