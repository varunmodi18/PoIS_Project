"""
Tests for PA#4 — Modes of Operation.
"""
import pytest


class TestCBC:
    def test_cbc_roundtrip_short(self):
        from crypto.pa04_modes import cbc_encrypt, cbc_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'Hello CBC!'
        iv, ct = cbc_encrypt(key, msg)
        assert cbc_decrypt(key, iv, ct) == msg

    def test_cbc_roundtrip_exact_block(self):
        from crypto.pa04_modes import cbc_encrypt, cbc_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'A' * 16
        iv, ct = cbc_encrypt(key, msg)
        assert cbc_decrypt(key, iv, ct) == msg

    def test_cbc_roundtrip_multi_block(self):
        from crypto.pa04_modes import cbc_encrypt, cbc_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'Multi-block test message that is longer than 16 bytes!'
        iv, ct = cbc_encrypt(key, msg)
        assert cbc_decrypt(key, iv, ct) == msg

    def test_cbc_random_iv(self):
        from crypto.pa04_modes import cbc_encrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'Same message'
        iv1, _ = cbc_encrypt(key, msg)
        iv2, _ = cbc_encrypt(key, msg)
        assert iv1 != iv2


class TestOFB:
    def test_ofb_roundtrip(self):
        from crypto.pa04_modes import ofb_encrypt, ofb_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'OFB mode test message!'
        iv, ct = ofb_encrypt(key, msg)
        assert ofb_decrypt(key, iv, ct) == msg

    def test_ofb_enc_dec_identical(self):
        from crypto.pa04_modes import ofb_encrypt, ofb_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        iv = random_bytes(16)
        msg = b'A' * 32
        _, ct = ofb_encrypt(key, msg, iv=iv)
        recovered = ofb_decrypt(key, iv, ct)
        assert recovered == msg

    def test_ofb_multi_block(self):
        from crypto.pa04_modes import ofb_encrypt, ofb_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = random_bytes(100)
        iv, ct = ofb_encrypt(key, msg)
        assert ofb_decrypt(key, iv, ct) == msg


class TestCTR:
    def test_ctr_roundtrip(self):
        from crypto.pa04_modes import ctr_encrypt, ctr_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'CTR mode rocks!'
        nonce, ct = ctr_encrypt(key, msg)
        assert ctr_decrypt(key, nonce, ct) == msg

    def test_ctr_roundtrip_multi(self):
        from crypto.pa04_modes import ctr_encrypt, ctr_decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        for length in [0, 1, 15, 16, 17, 31, 32, 48, 100, 255]:
            msg = random_bytes(length) if length > 0 else b''
            nonce, ct = ctr_encrypt(key, msg)
            assert ctr_decrypt(key, nonce, ct) == msg, f"CTR failed at length {length}"


class TestUnifiedAPI:
    def test_all_modes_roundtrip(self):
        from crypto.pa04_modes import encrypt, decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        msg = b'Test message for all modes'
        for mode in ['CBC', 'OFB', 'CTR']:
            iv, ct = encrypt(mode, key, msg)
            recovered = decrypt(mode, key, iv, ct)
            assert recovered == msg, f"Mode {mode} failed roundtrip"

    def test_invalid_mode(self):
        from crypto.pa04_modes import encrypt
        from crypto.utils import random_bytes
        with pytest.raises(ValueError):
            encrypt('XYZ', random_bytes(16), b'test')


class TestModeCorrectness:
    def test_all_modes_many_lengths(self):
        from crypto.pa04_modes import encrypt, decrypt
        from crypto.utils import random_bytes
        key = random_bytes(16)
        for mode in ['CBC', 'OFB', 'CTR']:
            for length in range(0, 101, 7):
                msg = random_bytes(length) if length > 0 else b''
                iv, ct = encrypt(mode, key, msg)
                assert decrypt(mode, key, iv, ct) == msg, \
                    f"{mode} failed at length {length}"


class TestAttacks:
    def test_cbc_iv_reuse(self):
        from crypto.pa04_modes import cbc_iv_reuse_attack
        result = cbc_iv_reuse_attack()
        assert result['blocks_match'], "CBC IV reuse should produce matching first blocks"

    def test_ofb_keystream_reuse(self):
        from crypto.pa04_modes import ofb_keystream_reuse_attack
        result = ofb_keystream_reuse_attack()
        assert result['match'], "c1⊕c2 should equal m1⊕m2"

    def test_error_propagation(self):
        from crypto.pa04_modes import bit_flip_error_propagation
        result = bit_flip_error_propagation()
        # CBC: flipping bit in block 2 corrupts blocks 2 and 3 (indices 1 and 2)
        assert 1 in result['cbc']['corrupted_blocks']
        assert len(result['cbc']['corrupted_blocks']) == 2
        # OFB: only the flipped block
        assert len(result['ofb']['corrupted_blocks']) == 1
        # CTR: only the flipped block
        assert len(result['ctr']['corrupted_blocks']) == 1
