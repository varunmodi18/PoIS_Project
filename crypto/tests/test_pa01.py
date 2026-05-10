"""
Tests for PA#1 — OWF + PRG.
"""
import pytest
from crypto.pa01_owf_prg import DLP_OWF, PRG, PRG_as_OWF, StatisticalTests, goldreich_levin_bit
from crypto.utils import random_int

# Use small bits for speed in tests
BITS = 64


@pytest.fixture(scope="module")
def owf():
    """Shared DLP_OWF instance for test module."""
    return DLP_OWF(bits=BITS)


@pytest.fixture(scope="module")
def prg(owf):
    """Shared PRG instance for test module."""
    return PRG(owf)


def test_dlp_owf_evaluate(owf):
    """Evaluate f(x) for 10 random x. Verify range and determinism."""
    p = owf.get_params()['p']
    q = owf.get_params()['q']
    for _ in range(10):
        x = random_int(1, q - 1)
        y = owf.evaluate(x)
        assert 1 <= y <= p - 1, f"f({x}) = {y} out of range [1, p-1]"
        # Determinism
        assert owf.evaluate(x) == y, "f is not deterministic"


def test_dlp_owf_hardness(owf):
    """Call verify_hardness(1000). Assert inversions_found == 0."""
    result = owf.verify_hardness(1000)
    assert result['inversions_found'] == 0, (
        f"Found {result['inversions_found']} inversions (expected 0 for 64-bit params)"
    )


def test_prg_deterministic(owf):
    """PRG with same seed produces same output."""
    prg1 = PRG(owf, r=12345)
    prg2 = PRG(owf, r=12345)
    seed = 999
    out1 = prg1.generate(seed, 50)
    out2 = prg2.generate(seed, 50)
    assert out1 == out2, "PRG is not deterministic for same seed and r"


def test_prg_output_length(prg):
    """Generate 100, 200, 500 bits. Verify lengths."""
    q = prg.owf.get_params()['q']
    seed = random_int(1, q - 1)
    for length in [100, 200, 500]:
        bits = prg.generate(seed, length)
        assert len(bits) == length, f"Expected {length} bits, got {len(bits)}"


def test_prg_different_seeds(prg):
    """Two different seeds produce different outputs."""
    q = prg.owf.get_params()['q']
    s1 = random_int(1, q - 1)
    s2 = random_int(1, q - 1)
    while s2 == s1:
        s2 = random_int(1, q - 1)
    out1 = prg.generate(s1, 100)
    out2 = prg.generate(s2, 100)
    assert out1 != out2, "Different seeds produced same output"


def test_prg_statistical_frequency(prg):
    """Generate 10000 bits. Run frequency_monobit test. Assert pass."""
    q = prg.owf.get_params()['q']
    seed = random_int(1, q - 1)
    bits = prg.generate(seed, 10000)
    passed, p_value = StatisticalTests.frequency_monobit(bits)
    assert passed, f"Frequency monobit test failed (p_value={p_value:.4f})"


def test_prg_statistical_runs(prg):
    """Generate 10000 bits. Run runs_test. Assert pass."""
    q = prg.owf.get_params()['q']
    seed = random_int(1, q - 1)
    bits = prg.generate(seed, 10000)
    passed, p_value = StatisticalTests.runs_test(bits)
    assert passed, f"Runs test failed (p_value={p_value:.4f})"


def test_prg_statistical_serial(prg):
    """Generate 10000 bits. Run serial_test. Assert pass."""
    q = prg.owf.get_params()['q']
    seed = random_int(1, q - 1)
    bits = prg.generate(seed, 10000)
    passed, p_value = StatisticalTests.serial_test(bits)
    assert passed, f"Serial test failed (p_value={p_value:.4f})"


def test_prg_as_owf(owf):
    """Create PRG_as_OWF. Call verify_hardness(100). Assert no inversions."""
    prg = PRG(owf)
    prg_owf = PRG_as_OWF(prg)
    result = prg_owf.verify_hardness(100)
    assert result['inversions_found'] == 0, (
        f"Found {result['inversions_found']} inversions in PRG_as_OWF"
    )


def test_prg_next_bits_stateful(prg):
    """Call next_bits(50) twice on same PRG. Verify outputs differ (state advances)."""
    q = prg.owf.get_params()['q']
    seed = random_int(1, q - 1)
    prg.seed(seed)
    out1 = prg.next_bits(50)
    out2 = prg.next_bits(50)
    assert out1 != out2, "PRG state did not advance: consecutive next_bits gave same output"


def test_goldreich_levin_bit():
    """Verify GL bit is 0 or 1. Verify determinism."""
    for _ in range(20):
        x = random_int(0, 2**64 - 1)
        r = random_int(0, 2**64 - 1)
        b = goldreich_levin_bit(x, r, 64)
        assert b in (0, 1), f"GL bit is not 0 or 1: {b}"
        # Determinism
        assert goldreich_levin_bit(x, r, 64) == b, "GL bit is not deterministic"
