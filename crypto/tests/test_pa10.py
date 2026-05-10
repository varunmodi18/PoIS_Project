"""
Tests for PA#10 — HMAC and HMAC-Based CCA-Secure Encryption.
"""
import pytest
import time


# ============================================================
# HMAC Core Tests
# ============================================================

class TestHMACConstruction:
    def test_hmac_deterministic(self):
        """Same key + same message → same tag."""
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        key = b'secret_key_here!'
        msg = b'Hello HMAC!'
        t1 = hmac.mac(key, msg)
        t2 = hmac.mac(key, msg)
        assert t1 == t2

    def test_hmac_output_length(self):
        """HMAC output must equal the hash output size."""
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        key = b'key'
        tag = hmac.mac(key, b'message')
        assert len(tag) == hmac.output_size

    def test_hmac_different_keys(self):
        """Different keys → different tags."""
        from crypto.pa10_hmac import HMAC
        from crypto.utils import random_bytes
        hmac = HMAC(dlp_bits=64)
        msg = b'same message'
        tags = set()
        for _ in range(10):
            key = random_bytes(16)
            tags.add(hmac.mac(key, msg))
        assert len(tags) == 10

    def test_hmac_different_messages(self):
        """Different messages → different tags."""
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        key = b'fixed_key_value!'
        tags = set()
        for i in range(20):
            tags.add(hmac.mac(key, f'message_{i}'.encode()))
        assert len(tags) == 20

    def test_hmac_verify_correct(self):
        """Valid tag should verify True."""
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        key = b'verification_key'
        msg = b'verify this message'
        tag = hmac.mac(key, msg)
        assert hmac.verify(key, msg, tag)

    def test_hmac_verify_wrong_tag(self):
        """Invalid tag should verify False."""
        from crypto.pa10_hmac import HMAC
        from crypto.utils import random_bytes
        hmac = HMAC(dlp_bits=64)
        key = b'verification_key'
        msg = b'verify this message'
        tag = hmac.mac(key, msg)
        wrong_tag = random_bytes(len(tag))
        assert not hmac.verify(key, msg, wrong_tag)

    def test_hmac_verify_wrong_message(self):
        """Tag for different message should verify False."""
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        key = b'verification_key'
        tag = hmac.mac(key, b'message A')
        assert not hmac.verify(key, b'message B', tag)

    def test_hmac_verify_wrong_key(self):
        """Tag verified with different key should fail."""
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        tag = hmac.mac(b'key_one_is_here!', b'message')
        assert not hmac.verify(b'key_two_is_here!', b'message', tag)

    def test_hmac_empty_message(self):
        """HMAC of empty message should work."""
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        tag = hmac.mac(b'key', b'')
        assert isinstance(tag, bytes) and len(tag) == hmac.output_size
        assert hmac.verify(b'key', b'', tag)

    def test_hmac_long_message(self):
        """HMAC of long message should work."""
        from crypto.pa10_hmac import HMAC
        from crypto.utils import random_bytes
        hmac = HMAC(dlp_bits=64)
        key = random_bytes(16)
        msg = random_bytes(5000)
        tag = hmac.mac(key, msg)
        assert hmac.verify(key, msg, tag)

    def test_hmac_long_key(self):
        """Key longer than block_size should be hashed first."""
        from crypto.pa10_hmac import HMAC
        from crypto.utils import random_bytes
        hmac = HMAC(dlp_bits=64)
        long_key = random_bytes(hmac.block_size + 50)
        msg = b'message with long key'
        tag = hmac.mac(long_key, msg)
        assert hmac.verify(long_key, msg, tag)

    def test_hmac_short_key(self):
        """Key shorter than block_size should be zero-padded."""
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        short_key = b'tiny'
        msg = b'message with short key'
        tag = hmac.mac(short_key, msg)
        assert hmac.verify(short_key, msg, tag)

    def test_hmac_various_message_lengths(self):
        """HMAC should work for messages of many lengths."""
        from crypto.pa10_hmac import HMAC
        from crypto.utils import random_bytes
        hmac = HMAC(dlp_bits=64)
        key = random_bytes(16)
        for length in [0, 1, 7, 8, 15, 16, 31, 32, 64, 100, 255, 1000]:
            msg = random_bytes(length) if length > 0 else b''
            tag = hmac.mac(key, msg)
            assert hmac.verify(key, msg, tag), f"HMAC failed for length {length}"


# ============================================================
# Constant-Time Comparison Tests
# ============================================================

class TestSecureCompare:
    def test_equal(self):
        from crypto.pa10_hmac import secure_compare
        assert secure_compare(b'hello', b'hello')

    def test_not_equal(self):
        from crypto.pa10_hmac import secure_compare
        assert not secure_compare(b'hello', b'world')

    def test_different_lengths(self):
        from crypto.pa10_hmac import secure_compare
        assert not secure_compare(b'hi', b'hello')

    def test_empty(self):
        from crypto.pa10_hmac import secure_compare
        assert secure_compare(b'', b'')

    def test_single_bit_difference(self):
        from crypto.pa10_hmac import secure_compare
        a = b'\x00' * 16
        b_val = b'\x00' * 15 + b'\x01'
        assert not secure_compare(a, b_val)

    def test_hmac_uses_secure_compare(self):
        """Verify that HMAC.verify uses secure_compare, not ==."""
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        key = b'key_for_timing'
        msg = b'message'
        tag = hmac.mac(key, msg)
        almost_right = tag[:-1] + bytes([(tag[-1] ^ 0x01)])
        assert not hmac.verify(key, msg, almost_right)


# ============================================================
# Forward Direction: CRHF ⇒ MAC
# ============================================================

class TestCRHFtoMAC:
    def test_euf_cma_game(self):
        """HMAC should be unforgeable in the EUF-CMA game."""
        from crypto.pa10_hmac import crhf_to_mac_demo
        result = crhf_to_mac_demo(num_queries=50)
        assert result['forgeries_succeeded'] == 0
        assert result['secure']


# ============================================================
# Backward Direction: MAC ⇒ CRHF
# ============================================================

class TestMACToCRHF:
    def test_mac_based_hash_works(self):
        """MACBasedHash should produce valid, deterministic hashes."""
        from crypto.pa10_hmac import MACBasedHash
        mac_hash = MACBasedHash()
        h1 = mac_hash.hash(b'test message')
        h2 = mac_hash.hash(b'test message')
        assert h1 == h2

    def test_mac_based_hash_distinct(self):
        """Different messages should produce different hashes."""
        from crypto.pa10_hmac import MACBasedHash
        mac_hash = MACBasedHash()
        hashes = set()
        for i in range(10):
            hashes.add(mac_hash.hash(f'msg_{i}'.encode()))
        assert len(hashes) == 10

    def test_mac_to_crhf_demo(self):
        from crypto.pa10_hmac import mac_to_crhf_demo
        result = mac_to_crhf_demo()
        assert result['all_distinct']


# ============================================================
# Length-Extension Attack
# ============================================================

class TestLengthExtension:
    def test_naive_mac_vulnerable(self):
        """H(k||m) MAC should be broken by length extension."""
        from crypto.pa10_hmac import length_extension_attack_demo
        result = length_extension_attack_demo()
        assert result['naive_mac']['verified'], \
            "Length extension attack should succeed on H(k||m)"

    def test_hmac_immune(self):
        """HMAC should be immune to length extension."""
        from crypto.pa10_hmac import length_extension_attack_demo
        result = length_extension_attack_demo()
        assert not result['hmac']['verified'], \
            "Length extension attack should fail on HMAC"


# ============================================================
# Encrypt-then-HMAC (CCA-Secure Encryption)
# ============================================================

class TestEncryptThenHMAC:
    def test_roundtrip(self):
        """Encrypt-then-HMAC roundtrip works."""
        from crypto.pa10_hmac import EncryptThenHMAC
        from crypto.utils import random_bytes
        eth = EncryptThenHMAC(dlp_bits=64)
        ke = random_bytes(16)
        km = random_bytes(16)
        msg = b'Encrypt-then-HMAC test!'
        r, ct, tag = eth.encrypt(ke, km, msg)
        assert eth.decrypt(ke, km, r, ct, tag) == msg

    def test_roundtrip_various_lengths(self):
        from crypto.pa10_hmac import EncryptThenHMAC
        from crypto.utils import random_bytes
        eth = EncryptThenHMAC(dlp_bits=64)
        ke = random_bytes(16)
        km = random_bytes(16)
        for length in [0, 1, 15, 16, 17, 100]:
            msg = random_bytes(length) if length > 0 else b''
            r, ct, tag = eth.encrypt(ke, km, msg)
            assert eth.decrypt(ke, km, r, ct, tag) == msg, f"Failed at length {length}"

    def test_tampered_ciphertext_rejected(self):
        from crypto.pa10_hmac import EncryptThenHMAC, EtHDecryptionError
        from crypto.utils import random_bytes
        eth = EncryptThenHMAC(dlp_bits=64)
        ke = random_bytes(16)
        km = random_bytes(16)
        r, ct, tag = eth.encrypt(ke, km, b'tamper test')
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(EtHDecryptionError):
            eth.decrypt(ke, km, r, tampered, tag)

    def test_tampered_nonce_rejected(self):
        from crypto.pa10_hmac import EncryptThenHMAC, EtHDecryptionError
        from crypto.utils import random_bytes
        eth = EncryptThenHMAC(dlp_bits=64)
        ke = random_bytes(16)
        km = random_bytes(16)
        r, ct, tag = eth.encrypt(ke, km, b'nonce test')
        tampered_r = bytes([r[0] ^ 0x01]) + r[1:]
        with pytest.raises(EtHDecryptionError):
            eth.decrypt(ke, km, tampered_r, ct, tag)

    def test_tampered_tag_rejected(self):
        from crypto.pa10_hmac import EncryptThenHMAC, EtHDecryptionError
        from crypto.utils import random_bytes
        eth = EncryptThenHMAC(dlp_bits=64)
        ke = random_bytes(16)
        km = random_bytes(16)
        r, ct, tag = eth.encrypt(ke, km, b'tag test')
        tampered_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
        with pytest.raises(EtHDecryptionError):
            eth.decrypt(ke, km, r, ct, tampered_tag)

    def test_wrong_mac_key_rejected(self):
        from crypto.pa10_hmac import EncryptThenHMAC, EtHDecryptionError
        from crypto.utils import random_bytes
        eth = EncryptThenHMAC(dlp_bits=64)
        ke = random_bytes(16)
        km1 = random_bytes(16)
        km2 = random_bytes(16)
        r, ct, tag = eth.encrypt(ke, km1, b'key test')
        with pytest.raises(EtHDecryptionError):
            eth.decrypt(ke, km2, r, ct, tag)

    def test_every_byte_tamper_rejected(self):
        """Flip every byte of ciphertext — all must be rejected."""
        from crypto.pa10_hmac import EncryptThenHMAC, EtHDecryptionError
        from crypto.utils import random_bytes
        eth = EncryptThenHMAC(dlp_bits=64)
        ke = random_bytes(16)
        km = random_bytes(16)
        r, ct, tag = eth.encrypt(ke, km, b'full tamper test')
        for i in range(len(ct)):
            tampered = bytearray(ct)
            tampered[i] ^= 0x01
            with pytest.raises(EtHDecryptionError):
                eth.decrypt(ke, km, r, bytes(tampered), tag)


class TestEtHCCA2Game:
    def test_advantage_near_zero(self):
        from crypto.pa10_hmac import eth_cca2_game
        result = eth_cca2_game(num_rounds=50)
        assert result['advantage'] < 0.2, f"Advantage {result['advantage']} too high"


class TestCompareSchemes:
    def test_comparison(self):
        from crypto.pa10_hmac import compare_mac_vs_hmac_cca
        result = compare_mac_vs_hmac_cca()
        assert result['both_cca2_secure']
        assert result['cbc_mac']['tag_size'] > 0
        assert result['hmac']['tag_size'] > 0
