"""
Tests for PA#9 — Birthday Attack.
"""
import math


class TestNaiveBirthdayAttack:
    def test_finds_collision_8bit(self):
        """8-bit output: collision should be found in ~20 evaluations."""
        from crypto.pa09_birthday_attack import naive_birthday_attack
        def tiny_hash(x: bytes) -> bytes:
            result = 0
            for b in x:
                result ^= b
            return bytes([result])
        result = naive_birthday_attack(tiny_hash, output_bits=8)
        assert result['collision_found']
        assert result['input_1'] != result['input_2']
        assert tiny_hash(result['input_1'])[:1] == tiny_hash(result['input_2'])[:1]
        assert result['evaluations'] < 200

    def test_finds_collision_12bit(self):
        """12-bit output: collision in ~80 evaluations."""
        from crypto.pa09_birthday_attack import naive_birthday_attack
        counter = [0]
        def hash_12bit(x: bytes) -> bytes:
            h = 0
            for i, b in enumerate(x):
                h = (h * 31 + b + i) & 0xFFF
            return bytes([(h >> 4) & 0xFF, (h & 0x0F) << 4])
        result = naive_birthday_attack(hash_12bit, output_bits=12)
        assert result['collision_found']
        assert result['evaluations'] < 1000

    def test_finds_collision_16bit(self):
        """16-bit output: collision in ~256 evaluations."""
        from crypto.pa09_birthday_attack import naive_birthday_attack
        def hash_16bit(x: bytes) -> bytes:
            h = 0
            for i, b in enumerate(x):
                h = ((h * 37 + b + i * 7) ^ (h >> 3)) & 0xFFFF
            return h.to_bytes(2, 'big')
        result = naive_birthday_attack(hash_16bit, output_bits=16)
        assert result['collision_found']
        assert result['evaluations'] < 5000

    def test_ratio_near_expected(self):
        """Ratio of evaluations to 2^(n/2) should be reasonable (0.5 to 5.0)."""
        from crypto.pa09_birthday_attack import naive_birthday_attack
        def simple_hash(x: bytes) -> bytes:
            h = 0
            for i, b in enumerate(x):
                h = ((h * 31 + b) ^ (h >> 5)) & 0xFFFF
            return h.to_bytes(2, 'big')
        result = naive_birthday_attack(simple_hash, output_bits=16)
        assert result['collision_found']
        assert 0.1 < result['ratio'] < 10.0, f"Ratio {result['ratio']} outside expected range"


class TestFloydsCycleAttack:
    def test_finds_collision_8bit(self):
        """Floyd's should find a collision on 8-bit output."""
        from crypto.pa09_birthday_attack import floyds_cycle_attack
        def tiny_hash(x: bytes) -> bytes:
            h = 0
            for b in x:
                h = (h * 31 + b) & 0xFF
            if h == 0:
                h = 1
            return bytes([h])
        result = floyds_cycle_attack(tiny_hash, output_bits=8)
        assert result['collision_found']
        assert result['input_1'] != result['input_2']

    def test_finds_collision_16bit(self):
        """Floyd's on 16-bit output."""
        from crypto.pa09_birthday_attack import floyds_cycle_attack
        def hash_16bit(x: bytes) -> bytes:
            h = 0
            for i, b in enumerate(x):
                h = ((h * 37 + b + i * 7) ^ (h >> 3)) & 0xFFFF
            if h == 0:
                h = 1
            return h.to_bytes(2, 'big')
        result = floyds_cycle_attack(hash_16bit, output_bits=16)
        assert result['collision_found']


class TestAttackDLPHash:
    def test_attack_truncated_dlp_16bit(self):
        """Birthday attack on DLP hash truncated to 16 bits."""
        from crypto.pa09_birthday_attack import attack_truncated_dlp_hash
        result = attack_truncated_dlp_hash(output_bits=16, dlp_bits=64)
        assert result['evaluations'] > 0
        assert result['ratio'] > 0
        assert result['input_1_hex'] != result['input_2_hex']
        assert result['shared_hash_hex'] is not None
        assert result['ratio'] < 10.0, f"Ratio {result['ratio']} too high"

    def test_attack_truncated_dlp_12bit(self):
        """12-bit truncated DLP hash attack."""
        from crypto.pa09_birthday_attack import attack_truncated_dlp_hash
        result = attack_truncated_dlp_hash(output_bits=12, dlp_bits=64)
        assert result['evaluations'] > 0
        assert result['ratio'] < 10.0


class TestEmpiricalCurve:
    def test_birthday_curve_8bit(self):
        """Run 50 trials on 8-bit hash, confirm mean near 2^4 = 16."""
        from crypto.pa09_birthday_attack import empirical_birthday_curve
        def hash_8bit(x: bytes) -> bytes:
            h = 0
            for b in x:
                h = (h * 31 + b) & 0xFF
            return bytes([h])
        result = empirical_birthday_curve(hash_8bit, output_bits=8, num_trials=50)
        assert result['num_trials'] == 50
        assert len(result['eval_counts']) == 50
        assert result['mean_evals'] < 100, f"Mean {result['mean_evals']} too high"
        assert result['mean_evals'] > 2, f"Mean {result['mean_evals']} suspiciously low"

    def test_birthday_curve_scaling(self):
        """
        Confirm that doubling output bits roughly doubles evaluations.
        """
        from crypto.pa09_birthday_attack import empirical_birthday_curve
        def parametric_hash(n_bits):
            mask = (1 << n_bits) - 1
            n_bytes = (n_bits + 7) // 8
            def h(x: bytes) -> bytes:
                val = 0
                for b in x:
                    val = ((val * 31 + b) ^ (val >> 3)) & mask
                return val.to_bytes(n_bytes, 'big')
            return h
        r8 = empirical_birthday_curve(parametric_hash(8), 8, num_trials=30)
        r10 = empirical_birthday_curve(parametric_hash(10), 10, num_trials=30)
        ratio = r10['mean_evals'] / max(r8['mean_evals'], 1)
        assert 1.0 < ratio < 6.0, f"Scaling ratio {ratio} outside expected range"


class TestMD5SHA1Context:
    def test_context_values(self):
        from crypto.pa09_birthday_attack import md5_sha1_context
        ctx = md5_sha1_context()
        assert ctx['md5']['output_bits'] == 128
        assert ctx['sha1']['output_bits'] == 160
        assert ctx['sha256']['output_bits'] == 256
        assert ctx['md5']['birthday_bound'] == 2**64
        assert ctx['sha256']['years'] > ctx['md5']['years'] * 1e10
