"""
Tests for PA#20 — All 2-Party Secure Computation.
"""
import time


class TestCircuitPlaintext:
    """Test circuits in plaintext mode first (no OT, fast)."""

    def test_comparison_circuit_plaintext(self):
        from crypto.pa20_mpc import build_comparison_circuit, int_to_bits
        circuit = build_comparison_circuit(4)
        # 7 > 5 → 1
        assert circuit.evaluate_plaintext(int_to_bits(7, 4), int_to_bits(5, 4)) == [1]
        # 3 > 9 → 0
        assert circuit.evaluate_plaintext(int_to_bits(3, 4), int_to_bits(9, 4)) == [0]
        # 6 > 6 → 0 (equal, not greater)
        assert circuit.evaluate_plaintext(int_to_bits(6, 4), int_to_bits(6, 4)) == [0]
        # 15 > 0 → 1
        assert circuit.evaluate_plaintext(int_to_bits(15, 4), int_to_bits(0, 4)) == [1]
        # 0 > 15 → 0
        assert circuit.evaluate_plaintext(int_to_bits(0, 4), int_to_bits(15, 4)) == [0]

    def test_comparison_exhaustive_3bit(self):
        """Test all 64 pairs of 3-bit integers."""
        from crypto.pa20_mpc import build_comparison_circuit, int_to_bits
        circuit = build_comparison_circuit(3)
        for x in range(8):
            for y in range(8):
                result = circuit.evaluate_plaintext(int_to_bits(x, 3), int_to_bits(y, 3))
                assert result == [1 if x > y else 0], f"Failed: {x} > {y}"

    def test_equality_circuit_plaintext(self):
        from crypto.pa20_mpc import build_equality_circuit, int_to_bits
        circuit = build_equality_circuit(4)
        assert circuit.evaluate_plaintext(int_to_bits(5, 4), int_to_bits(5, 4)) == [1]
        assert circuit.evaluate_plaintext(int_to_bits(5, 4), int_to_bits(6, 4)) == [0]
        assert circuit.evaluate_plaintext(int_to_bits(0, 4), int_to_bits(0, 4)) == [1]

    def test_equality_exhaustive_3bit(self):
        from crypto.pa20_mpc import build_equality_circuit, int_to_bits
        circuit = build_equality_circuit(3)
        for x in range(8):
            for y in range(8):
                result = circuit.evaluate_plaintext(int_to_bits(x, 3), int_to_bits(y, 3))
                assert result == [1 if x == y else 0], f"Failed: {x} == {y}"

    def test_addition_circuit_plaintext(self):
        from crypto.pa20_mpc import build_addition_circuit, int_to_bits, bits_to_int
        circuit = build_addition_circuit(4)
        assert bits_to_int(circuit.evaluate_plaintext(int_to_bits(3, 4), int_to_bits(5, 4))) == 8
        assert bits_to_int(circuit.evaluate_plaintext(int_to_bits(15, 4), int_to_bits(1, 4))) == 0  # overflow
        assert bits_to_int(circuit.evaluate_plaintext(int_to_bits(7, 4), int_to_bits(7, 4))) == 14

    def test_addition_exhaustive_3bit(self):
        from crypto.pa20_mpc import build_addition_circuit, int_to_bits, bits_to_int
        circuit = build_addition_circuit(3)
        for x in range(8):
            for y in range(8):
                result = bits_to_int(circuit.evaluate_plaintext(int_to_bits(x, 3), int_to_bits(y, 3)))
                assert result == (x + y) % 8, f"Failed: {x} + {y}"


class TestSecureEvaluation:
    """Test circuits with secure (OT-based) evaluation."""

    def test_millionaires_basic(self):
        from crypto.pa20_mpc import millionaires_problem
        result = millionaires_problem(7, 5, n_bits=4)
        assert result['alice_richer'] and result['correct']

    def test_millionaires_bob_richer(self):
        from crypto.pa20_mpc import millionaires_problem
        result = millionaires_problem(3, 12, n_bits=4)
        assert result['bob_richer'] and result['correct']

    def test_millionaires_equal(self):
        from crypto.pa20_mpc import millionaires_problem
        result = millionaires_problem(7, 7, n_bits=4)
        assert result['equal'] and result['correct']

    def test_equality_equal(self):
        from crypto.pa20_mpc import secure_equality_test
        result = secure_equality_test(5, 5, n_bits=4)
        assert result['equal'] and result['correct']

    def test_equality_not_equal(self):
        from crypto.pa20_mpc import secure_equality_test
        result = secure_equality_test(5, 9, n_bits=4)
        assert not result['equal'] and result['correct']

    def test_addition_basic(self):
        from crypto.pa20_mpc import secure_addition
        result = secure_addition(3, 5, n_bits=4)
        assert result['sum'] == 8 and result['correct']

    def test_addition_overflow(self):
        from crypto.pa20_mpc import secure_addition
        result = secure_addition(15, 1, n_bits=4)
        assert result['sum'] == 0 and result['correct']  # 15+1=16 mod 16 = 0

    def test_addition_various(self):
        from crypto.pa20_mpc import secure_addition
        for x, y in [(0, 0), (1, 1), (7, 8), (10, 5)]:
            result = secure_addition(x, y, n_bits=4)
            assert result['correct'], f"Failed: {x} + {y}"


class TestHelpers:
    def test_int_to_bits(self):
        from crypto.pa20_mpc import int_to_bits
        assert int_to_bits(5, 4) == [0, 1, 0, 1]
        assert int_to_bits(15, 4) == [1, 1, 1, 1]
        assert int_to_bits(0, 4) == [0, 0, 0, 0]

    def test_bits_to_int(self):
        from crypto.pa20_mpc import bits_to_int
        assert bits_to_int([0, 1, 0, 1]) == 5
        assert bits_to_int([1, 1, 1, 1]) == 15
        assert bits_to_int([0, 0, 0, 0]) == 0

    def test_roundtrip(self):
        from crypto.pa20_mpc import int_to_bits, bits_to_int
        for v in range(16):
            assert bits_to_int(int_to_bits(v, 4)) == v


class TestPerformance:
    def test_performance_report(self):
        from crypto.pa20_mpc import performance_report
        report = performance_report(n_bits=4)
        assert report['comparison']['and_gates'] > 0
        assert report['equality']['and_gates'] > 0
        assert report['addition']['and_gates'] > 0
        for name in ['comparison', 'equality', 'addition']:
            assert report[name]['time'] < 300, \
                f"{name} took {report[name]['time']:.1f}s (limit: 300s)"
