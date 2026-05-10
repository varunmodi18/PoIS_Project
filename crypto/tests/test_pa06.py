"""
Tests for PA#6 — CCA-Secure Encryption.
"""
import pytest


class TestCCAEncryption:
    def test_roundtrip(self):
        from crypto.pa06_cca_enc import cca_encrypt, cca_decrypt
        from crypto.utils import random_bytes
        ke = random_bytes(16)
        km = random_bytes(16)
        msg = b'CCA-secure message!'
        r, ct, tag = cca_encrypt(ke, km, msg)
        assert cca_decrypt(ke, km, r, ct, tag) == msg

    def test_roundtrip_various_lengths(self):
        from crypto.pa06_cca_enc import cca_encrypt, cca_decrypt
        from crypto.utils import random_bytes
        ke = random_bytes(16)
        km = random_bytes(16)
        for length in [0, 1, 15, 16, 17, 31, 32, 100]:
            msg = random_bytes(length) if length > 0 else b''
            r, ct, tag = cca_encrypt(ke, km, msg)
            assert cca_decrypt(ke, km, r, ct, tag) == msg

    def test_tampered_ciphertext_rejected(self):
        from crypto.pa06_cca_enc import cca_encrypt, cca_decrypt, CCADecryptionError
        from crypto.utils import random_bytes
        ke = random_bytes(16)
        km = random_bytes(16)
        msg = b'Do not tamper with me!'
        r, ct, tag = cca_encrypt(ke, km, msg)
        tampered_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(CCADecryptionError):
            cca_decrypt(ke, km, r, tampered_ct, tag)

    def test_tampered_nonce_rejected(self):
        from crypto.pa06_cca_enc import cca_encrypt, cca_decrypt, CCADecryptionError
        from crypto.utils import random_bytes
        ke = random_bytes(16)
        km = random_bytes(16)
        r, ct, tag = cca_encrypt(ke, km, b'test')
        tampered_r = bytes([r[0] ^ 0x01]) + r[1:]
        with pytest.raises(CCADecryptionError):
            cca_decrypt(ke, km, tampered_r, ct, tag)

    def test_tampered_tag_rejected(self):
        from crypto.pa06_cca_enc import cca_encrypt, cca_decrypt, CCADecryptionError
        from crypto.utils import random_bytes
        ke = random_bytes(16)
        km = random_bytes(16)
        r, ct, tag = cca_encrypt(ke, km, b'test')
        tampered_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
        with pytest.raises(CCADecryptionError):
            cca_decrypt(ke, km, r, ct, tampered_tag)

    def test_wrong_keys_rejected(self):
        from crypto.pa06_cca_enc import cca_encrypt, cca_decrypt, CCADecryptionError
        from crypto.utils import random_bytes
        ke1, km1 = random_bytes(16), random_bytes(16)
        ke2, km2 = random_bytes(16), random_bytes(16)
        r, ct, tag = cca_encrypt(ke1, km1, b'secret')
        with pytest.raises(CCADecryptionError):
            cca_decrypt(ke1, km2, r, ct, tag)

    def test_independent_keys(self):
        from crypto.pa06_cca_enc import cca_encrypt, cca_decrypt
        from crypto.utils import random_bytes
        ke = random_bytes(16)
        km = random_bytes(16)
        assert ke != km
        r, ct, tag = cca_encrypt(ke, km, b'test')
        assert cca_decrypt(ke, km, r, ct, tag) == b'test'


class TestCCA2Game:
    def test_advantage_near_zero(self):
        from crypto.pa06_cca_enc import cca2_game_simulation
        result = cca2_game_simulation(num_rounds=100)
        assert result['advantage'] < 0.15, f"CCA2 advantage {result['advantage']} too high"
        if result['oracle_total_queries'] > 0:
            rejection_rate = result['oracle_rejections'] / result['oracle_total_queries']
            assert rejection_rate > 0.9, f"Rejection rate {rejection_rate} too low"


class TestMalleability:
    def test_cpa_malleable(self):
        from crypto.pa06_cca_enc import malleability_attack_cpa_only
        result = malleability_attack_cpa_only()
        assert result['bit_was_flipped'], "CPA scheme should be malleable"

    def test_cca_not_malleable(self):
        from crypto.pa06_cca_enc import malleability_blocked_cca
        result = malleability_blocked_cca()
        assert result['attack_blocked'], "CCA scheme should block malleability"
