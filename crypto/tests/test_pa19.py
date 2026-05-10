"""
Tests for PA#19 — Secure AND, XOR, NOT Gates.
"""


class TestSecureAND:
    def test_truth_table(self):
        """Verify AND gate produces correct truth table."""
        from crypto.pa19_secure_gates import secure_and, SecureGateParams
        params = SecureGateParams(bits=64)
        truth_table = {
            (0, 0): 0, (0, 1): 0, (1, 0): 0, (1, 1): 1
        }
        for (a, b), expected in truth_table.items():
            result = secure_and(a, b, params)
            assert result['result'] == expected, \
                f"AND({a},{b}) = {result['result']}, expected {expected}"
            assert result['correct']

    def test_and_50_random_trials(self):
        """Run 50 random AND gate computations."""
        from crypto.pa19_secure_gates import secure_and, SecureGateParams
        from crypto.utils import random_int
        params = SecureGateParams(bits=64)
        for _ in range(50):
            a = random_int(0, 1)
            b = random_int(0, 1)
            result = secure_and(a, b, params)
            assert result['correct']

    def test_and_all_combos_repeated(self):
        """Each (a,b) combo 10 times to check consistency."""
        from crypto.pa19_secure_gates import secure_and, SecureGateParams
        params = SecureGateParams(bits=64)
        for a in [0, 1]:
            for b in [0, 1]:
                for _ in range(10):
                    result = secure_and(a, b, params)
                    assert result['result'] == (a & b)


class TestSecureXOR:
    def test_truth_table(self):
        from crypto.pa19_secure_gates import secure_xor
        truth_table = {(0, 0): 0, (0, 1): 1, (1, 0): 1, (1, 1): 0}
        for (a, b), expected in truth_table.items():
            result = secure_xor(a, b)
            assert result['result'] == expected
            assert result['correct']

    def test_xor_shares_reconstruct(self):
        """alice_share ⊕ bob_share must equal a ⊕ b."""
        from crypto.pa19_secure_gates import secure_xor
        for a in [0, 1]:
            for b in [0, 1]:
                result = secure_xor(a, b)
                assert (result['alice_share'] ^ result['bob_share']) == (a ^ b)

    def test_xor_50_trials(self):
        from crypto.pa19_secure_gates import secure_xor
        from crypto.utils import random_int
        for _ in range(50):
            a, b = random_int(0, 1), random_int(0, 1)
            assert secure_xor(a, b)['correct']


class TestSecureNOT:
    def test_not(self):
        from crypto.pa19_secure_gates import secure_not
        assert secure_not(0)['result'] == 1
        assert secure_not(1)['result'] == 0


class TestSimplifiedInterfaces:
    def test_and_simple(self):
        from crypto.pa19_secure_gates import secure_and_simple, SecureGateParams
        params = SecureGateParams(bits=64)
        assert secure_and_simple(1, 1, params) == 1
        assert secure_and_simple(1, 0, params) == 0

    def test_xor_simple(self):
        from crypto.pa19_secure_gates import secure_xor_simple
        assert secure_xor_simple(1, 1) == 0
        assert secure_xor_simple(1, 0) == 1

    def test_not_simple(self):
        from crypto.pa19_secure_gates import secure_not_simple
        assert secure_not_simple(0) == 1
        assert secure_not_simple(1) == 0


class TestPrivacy:
    def test_privacy_analysis(self):
        from crypto.pa19_secure_gates import privacy_analysis_and, SecureGateParams
        params = SecureGateParams(bits=64)
        result = privacy_analysis_and(params)
        assert result['alice_learns_nothing']
        assert result['bob_learns_only_output']
        assert len(result['truth_table']) == 4
