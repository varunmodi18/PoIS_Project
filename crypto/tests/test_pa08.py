"""
Tests for PA#8 — DLP-Based Collision-Resistant Hash Function.
"""
import time


class TestDLPHashParams:
    """Group parameter generation tests."""

    def test_params_construction(self):
        """DLPHashParams should construct without error."""
        from crypto.pa08_dlp_hash import DLPHashParams
        params = DLPHashParams(bits=64)
        assert hasattr(params, 'p')
        assert hasattr(params, 'q')
        assert hasattr(params, 'g')
        assert hasattr(params, 'h_hat')

    def test_safe_prime(self):
        """p must be a safe prime: p = 2q + 1, both prime."""
        from crypto.pa08_dlp_hash import DLPHashParams
        from crypto.pa13_miller_rabin import is_prime
        params = DLPHashParams(bits=64)
        assert params.p == 2 * params.q + 1
        assert is_prime(params.p)
        assert is_prime(params.q)

    def test_generator_order(self):
        """g must have order q in Z*_p."""
        from crypto.pa08_dlp_hash import DLPHashParams
        params = DLPHashParams(bits=64)
        assert pow(params.g, params.q, params.p) == 1, "g^q mod p must be 1"
        assert params.g != 1, "g must not be 1"

    def test_h_hat_in_subgroup(self):
        """h_hat must be in the order-q subgroup."""
        from crypto.pa08_dlp_hash import DLPHashParams
        params = DLPHashParams(bits=64)
        assert pow(params.h_hat, params.q, params.p) == 1, "h_hat must have order q"
        assert params.h_hat != 1, "h_hat must not be 1"

    def test_alpha_not_stored(self):
        """The secret α must NOT be stored anywhere in the object."""
        from crypto.pa08_dlp_hash import DLPHashParams
        params = DLPHashParams(bits=64)
        assert not hasattr(params, 'alpha'), "α must be discarded, not stored"
        assert not hasattr(params, '_alpha'), "α must not be stored as _alpha either"
        for attr_name in dir(params):
            if 'alpha' in attr_name.lower():
                assert False, f"Found suspicious attribute: {attr_name}"

    def test_params_bit_length(self):
        """p should have the requested bit length."""
        from crypto.pa08_dlp_hash import DLPHashParams
        params = DLPHashParams(bits=64)
        assert params.p.bit_length() == 64

    def test_different_params_each_time(self):
        """Two constructions should produce different parameters."""
        from crypto.pa08_dlp_hash import DLPHashParams
        p1 = DLPHashParams(bits=32)
        p2 = DLPHashParams(bits=32)
        assert p1.p != p2.p or p1.h_hat != p2.h_hat


class TestDLPCompression:
    """Compression function tests."""

    def test_compress_ints_deterministic(self):
        """Same inputs → same output."""
        from crypto.pa08_dlp_hash import DLPHashParams, DLPCompression
        params = DLPHashParams(bits=64)
        comp = DLPCompression(params)
        result1 = comp.compress_ints(42, 99)
        result2 = comp.compress_ints(42, 99)
        assert result1 == result2

    def test_compress_ints_different_inputs(self):
        """Different inputs should produce different outputs (with high probability)."""
        from crypto.pa08_dlp_hash import DLPHashParams, DLPCompression
        from crypto.utils import random_int
        params = DLPHashParams(bits=64)
        comp = DLPCompression(params)
        outputs = set()
        for _ in range(50):
            x = random_int(0, params.q - 1)
            y = random_int(0, params.q - 1)
            outputs.add(comp.compress_ints(x, y))
        assert len(outputs) >= 45, f"Only {len(outputs)} distinct outputs from 50 random inputs"

    def test_compress_ints_range(self):
        """Output must be in [1, p-1]."""
        from crypto.pa08_dlp_hash import DLPHashParams, DLPCompression
        from crypto.utils import random_int
        params = DLPHashParams(bits=64)
        comp = DLPCompression(params)
        for _ in range(50):
            x = random_int(0, params.q - 1)
            y = random_int(0, params.q - 1)
            result = comp.compress_ints(x, y)
            assert 1 <= result < params.p

    def test_compress_ints_formula(self):
        """Verify h(x,y) = g^x · ĥ^y mod p manually."""
        from crypto.pa08_dlp_hash import DLPHashParams, DLPCompression
        params = DLPHashParams(bits=64)
        comp = DLPCompression(params)
        x, y = 7, 13
        expected = (pow(params.g, x, params.p) * pow(params.h_hat, y, params.p)) % params.p
        assert comp.compress_ints(x, y) == expected

    def test_compress_bytes_interface(self):
        """Byte-level compress must match int-level compress."""
        from crypto.pa08_dlp_hash import DLPHashParams, DLPCompression
        from crypto.utils import int_to_bytes, bytes_to_int
        params = DLPHashParams(bits=64)
        comp = DLPCompression(params)
        x, y = 42, 99
        cv_bytes = int_to_bytes(x, comp.output_size)
        block_bytes = int_to_bytes(y, comp.block_size)
        result_bytes = comp.compress(cv_bytes, block_bytes)
        result_int = bytes_to_int(result_bytes)
        expected_int = comp.compress_ints(x % params.q, y % params.q)
        assert result_int == expected_int

    def test_compress_bytes_output_length(self):
        """Output bytes must have correct length."""
        from crypto.pa08_dlp_hash import DLPHashParams, DLPCompression
        params = DLPHashParams(bits=64)
        comp = DLPCompression(params)
        cv = b'\x00' * comp.output_size
        block = b'\x01' * comp.block_size
        result = comp.compress(cv, block)
        assert len(result) == comp.output_size


class TestDLPHash:
    """Full hash function tests."""

    def test_hash_deterministic(self):
        """Same message → same hash."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        h1 = hasher.hash(b'Hello World')
        h2 = hasher.hash(b'Hello World')
        assert h1 == h2

    def test_hash_different_messages(self):
        """Different messages → different hashes."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        hashes = set()
        for i in range(20):
            h = hasher.hash(f'message_{i}'.encode())
            hashes.add(h)
        assert len(hashes) == 20, f"Only {len(hashes)} distinct hashes for 20 messages"

    def test_hash_empty_message(self):
        """Empty message should hash without error."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        h = hasher.hash(b'')
        assert isinstance(h, bytes)
        assert len(h) == hasher.get_output_size()

    def test_hash_various_lengths(self):
        """Hash messages of various lengths, all producing valid output."""
        from crypto.pa08_dlp_hash import DLPHash
        from crypto.utils import random_bytes
        hasher = DLPHash(bits=64)
        expected_len = hasher.get_output_size()
        for length in [0, 1, 5, 8, 16, 32, 64, 100, 255, 1000]:
            msg = random_bytes(length) if length > 0 else b''
            h = hasher.hash(msg)
            assert len(h) == expected_len, f"Hash of {length}-byte msg has wrong length"

    def test_hash_hex(self):
        """hash_hex must return a hex string matching hash."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        msg = b'test'
        assert hasher.hash_hex(msg) == hasher.hash(msg).hex()

    def test_hash_with_trace_structure(self):
        """Trace must have correct structure."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        trace = hasher.hash_with_trace(b'Hello World trace test')
        assert 'blocks' in trace
        assert 'chaining_values' in trace
        assert 'digest' in trace
        assert len(trace['chaining_values']) == len(trace['blocks']) + 1

    def test_hash_with_trace_matches_hash(self):
        """Trace digest must equal hash output."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        msg = b'consistency'
        assert hasher.hash_with_trace(msg)['digest'] == hasher.hash_hex(msg)

    def test_hash_truncated(self):
        """Truncated hash should have correct bit length."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        msg = b'truncate me'
        for n_bits in [8, 12, 16, 20]:
            trunc = hasher.hash_truncated(msg, n_bits)
            expected_bytes = (n_bits + 7) // 8
            assert len(trunc) == expected_bytes

    def test_hash_truncated_deterministic(self):
        """Truncated hash must be deterministic."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        msg = b'deterministic truncation'
        assert hasher.hash_truncated(msg, 16) == hasher.hash_truncated(msg, 16)

    def test_interface_for_pa10(self):
        """PA#10 needs get_block_size(), get_output_size(), hash()."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        bs = hasher.get_block_size()
        os_ = hasher.get_output_size()
        assert isinstance(bs, int) and bs > 0
        assert isinstance(os_, int) and os_ > 0
        h = hasher.hash(b'PA10 interface test')
        assert len(h) == os_


class TestCollisionResistance:
    def test_no_random_collisions(self):
        """Brute-force random search should find no collisions for 64-bit params."""
        from crypto.pa08_dlp_hash import collision_resistance_demo
        result = collision_resistance_demo(bits=32)
        assert result['collisions_found'] == 0

    def test_distinct_digests(self):
        from crypto.pa08_dlp_hash import integration_test_different_messages
        result = integration_test_different_messages(bits=64, num_messages=20)
        assert result['all_distinct']


class TestPA08Performance:
    def test_hash_speed(self):
        """Hashing a 1KB message should take < 10 seconds (DLP is slow in Python)."""
        from crypto.pa08_dlp_hash import DLPHash
        hasher = DLPHash(bits=64)
        msg = b'A' * 1024
        start = time.time()
        hasher.hash(msg)
        elapsed = time.time() - start
        assert elapsed < 10, f"1KB hash took {elapsed:.1f}s (limit: 10s)"
