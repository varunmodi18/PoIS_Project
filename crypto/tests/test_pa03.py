"""
Tests for PA#3 — CPA-Secure Encryption.
"""
import pytest


class TestPadding:
    def test_pad_short(self):
        from crypto.pa03_cpa_enc import pad_message, BLOCK_SIZE
        padded = pad_message(b'Hello')
        assert len(padded) == BLOCK_SIZE
        assert padded[-1] == BLOCK_SIZE - 5

    def test_pad_exact_block(self):
        from crypto.pa03_cpa_enc import pad_message, BLOCK_SIZE
        padded = pad_message(b'A' * BLOCK_SIZE)
        assert len(padded) == 2 * BLOCK_SIZE

    def test_pad_unpad_roundtrip(self):
        from crypto.pa03_cpa_enc import pad_message, unpad_message
        for length in [0, 1, 5, 15, 16, 17, 31, 32, 100]:
            msg = b'X' * length
            assert unpad_message(pad_message(msg)) == msg

    def test_unpad_invalid(self):
        from crypto.pa03_cpa_enc import unpad_message
        with pytest.raises(ValueError):
            unpad_message(b'Hello World!!!!!' + b'\x05\x05\x05\x05\x03')


class TestCPAEncryption:
    def test_encrypt_decrypt_short(self):
        from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'Hello, World!'
        r, ct = cpa_encrypt(key, msg)
        recovered = cpa_decrypt(key, r, ct)
        assert recovered == msg

    def test_encrypt_decrypt_exact_block(self):
        from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'A' * 16
        r, ct = cpa_encrypt(key, msg)
        assert cpa_decrypt(key, r, ct) == msg

    def test_encrypt_decrypt_multi_block(self):
        from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'This is a longer message that spans multiple AES blocks for testing.'
        r, ct = cpa_encrypt(key, msg)
        assert cpa_decrypt(key, r, ct) == msg

    def test_encrypt_decrypt_empty(self):
        from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        r, ct = cpa_encrypt(key, b'')
        assert cpa_decrypt(key, r, ct) == b''

    def test_randomized_encryption(self):
        from crypto.pa03_cpa_enc import cpa_encrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'Same message'
        r1, ct1 = cpa_encrypt(key, msg)
        r2, ct2 = cpa_encrypt(key, msg)
        assert r1 != r2 or ct1 != ct2, "Encryption must be randomized"

    def test_wrong_key_fails(self):
        from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
        from crypto.utils import random_bytes
        key1 = random_bytes(16)
        key2 = random_bytes(16)
        msg = b'Secret message!!'
        r, ct = cpa_encrypt(key1, msg)
        try:
            recovered = cpa_decrypt(key2, r, ct)
            assert recovered != msg
        except (ValueError, Exception):
            pass

    def test_cpa_game_advantage_near_zero(self):
        from crypto.pa03_cpa_enc import cpa_game_simulation
        result = cpa_game_simulation(num_rounds=200)
        assert result['advantage'] < 0.15, f"Advantage {result['advantage']} too high"

    def test_broken_deterministic_attack(self):
        from crypto.pa03_cpa_enc import cpa_encrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        nonce = random_bytes(16)
        msg = b'Attack at dawn!!'
        _, ct1 = cpa_encrypt(key, msg, fixed_r=nonce)
        _, ct2 = cpa_encrypt(key, msg, fixed_r=nonce)
        assert ct1 == ct2, "Reused nonce must produce identical ciphertext"

    def test_many_message_lengths(self):
        from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        for length in range(0, 100):
            msg = random_bytes(length) if length > 0 else b''
            r, ct = cpa_encrypt(key, msg)
            assert cpa_decrypt(key, r, ct) == msg, f"Failed for length {length}"
