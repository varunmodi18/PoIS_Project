"""
Tests for PA#5 — MACs.
"""
import pytest


class TestPRFMAC:
    def test_prf_mac_correctness(self):
        from crypto.pa05_mac import prf_mac, prf_mac_verify
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = random_bytes(16)
        tag = prf_mac(key, msg)
        assert isinstance(tag, bytes) and len(tag) == 16
        assert prf_mac_verify(key, msg, tag)

    def test_prf_mac_rejects_wrong_tag(self):
        from crypto.pa05_mac import prf_mac, prf_mac_verify
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = random_bytes(16)
        tag = prf_mac(key, msg)
        wrong_tag = random_bytes(16)
        assert not prf_mac_verify(key, msg, wrong_tag)

    def test_prf_mac_rejects_wrong_message(self):
        from crypto.pa05_mac import prf_mac, prf_mac_verify
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg1 = random_bytes(16)
        msg2 = random_bytes(16)
        tag = prf_mac(key, msg1)
        assert not prf_mac_verify(key, msg2, tag)

    def test_prf_mac_wrong_length(self):
        from crypto.pa05_mac import prf_mac
        from crypto.utils import random_bytes
        with pytest.raises(ValueError):
            prf_mac(random_bytes(16), b'short')

    def test_prf_mac_deterministic(self):
        from crypto.pa05_mac import prf_mac
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = random_bytes(16)
        assert prf_mac(key, msg) == prf_mac(key, msg)


class TestCBCMAC:
    def test_cbc_mac_single_block(self):
        from crypto.pa05_mac import cbc_mac, cbc_mac_verify
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = random_bytes(16)
        tag = cbc_mac(key, msg)
        assert len(tag) == 16
        assert cbc_mac_verify(key, msg, tag)

    def test_cbc_mac_multi_block(self):
        from crypto.pa05_mac import cbc_mac, cbc_mac_verify
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'A longer message that spans several blocks for testing CBC-MAC'
        tag = cbc_mac(key, msg)
        assert cbc_mac_verify(key, msg, tag)

    def test_cbc_mac_tamper_detection(self):
        from crypto.pa05_mac import cbc_mac, cbc_mac_verify
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'Original message content here'
        tag = cbc_mac(key, msg)
        tampered = b'Tampered message content here'
        assert not cbc_mac_verify(key, tampered, tag)

    def test_cbc_mac_different_keys(self):
        from crypto.pa05_mac import cbc_mac
        from crypto.utils import random_bytes
        key1 = random_bytes(16)
        key2 = random_bytes(16)
        msg = b'Same message'
        assert cbc_mac(key1, msg) != cbc_mac(key2, msg)

    def test_cbc_mac_empty_message(self):
        from crypto.pa05_mac import cbc_mac, cbc_mac_verify
        from crypto.utils import random_bytes
        key = random_bytes(16)
        tag = cbc_mac(key, b'')
        assert cbc_mac_verify(key, b'', tag)

    def test_cbc_mac_various_lengths(self):
        from crypto.pa05_mac import cbc_mac, cbc_mac_verify
        from crypto.utils import random_bytes
        key = random_bytes(16)
        for length in [1, 15, 16, 17, 31, 32, 48, 100, 255]:
            msg = random_bytes(length)
            tag = cbc_mac(key, msg)
            assert cbc_mac_verify(key, msg, tag), f"Failed for length {length}"


class TestConstantTimeCompare:
    def test_equal_strings(self):
        from crypto.pa05_mac import _constant_time_compare
        assert _constant_time_compare(b'hello', b'hello')

    def test_unequal_strings(self):
        from crypto.pa05_mac import _constant_time_compare
        assert not _constant_time_compare(b'hello', b'world')

    def test_different_lengths(self):
        from crypto.pa05_mac import _constant_time_compare
        assert not _constant_time_compare(b'hi', b'hello')

    def test_empty(self):
        from crypto.pa05_mac import _constant_time_compare
        assert _constant_time_compare(b'', b'')


class TestHMACStub:
    def test_hmac_not_implemented(self):
        from crypto.pa05_mac import hmac_stub
        with pytest.raises(NotImplementedError):
            hmac_stub(b'key', b'message')


class TestEUFCMA:
    def test_prf_mac_unforgeable(self):
        from crypto.pa05_mac import prf_mac, prf_mac_verify, euf_cma_game
        result = euf_cma_game(
            mac_fn=lambda k, m: prf_mac(k, m.ljust(16, b'\x00')[:16]),
            verify_fn=lambda k, m, t: prf_mac_verify(k, m.ljust(16, b'\x00')[:16], t),
            num_queries=50
        )
        assert result['forgeries_succeeded'] == 0
        assert result['secure']

    def test_cbc_mac_unforgeable(self):
        from crypto.pa05_mac import cbc_mac, cbc_mac_verify, euf_cma_game
        result = euf_cma_game(
            mac_fn=cbc_mac,
            verify_fn=cbc_mac_verify,
            num_queries=50
        )
        assert result['forgeries_succeeded'] == 0
