"""Tests for PA#12 — RSA."""
import pytest


class TestRSAKeyGen:
    def test_key_generation(self):
        from crypto.pa12_rsa import RSAKeyPair
        kp = RSAKeyPair(bits=512)
        assert kp.n == kp.p * kp.q
        assert kp.e == 65537

    def test_key_correctness(self):
        """e*d ≡ 1 mod φ(N)."""
        from crypto.pa12_rsa import RSAKeyPair
        kp = RSAKeyPair(bits=512)
        phi_n = (kp.p - 1) * (kp.q - 1)
        assert (kp.e * kp.d) % phi_n == 1

    def test_crt_components(self):
        from crypto.pa12_rsa import RSAKeyPair
        kp = RSAKeyPair(bits=512)
        assert kp.dp == kp.d % (kp.p - 1)
        assert kp.dq == kp.d % (kp.q - 1)
        assert (kp.q_inv * kp.q) % kp.p == 1

    def test_key_size(self):
        from crypto.pa12_rsa import RSAKeyPair
        for bits in [256, 512, 1024]:
            kp = RSAKeyPair(bits=bits)
            assert kp.n.bit_length() >= bits - 2
            assert kp.n.bit_length() <= bits + 1

    def test_p_q_different(self):
        from crypto.pa12_rsa import RSAKeyPair
        kp = RSAKeyPair(bits=512)
        assert kp.p != kp.q


class TestTextbookRSA:
    def test_encrypt_decrypt_small(self):
        from crypto.pa12_rsa import RSAKeyPair, rsa_encrypt_raw, rsa_decrypt_raw
        kp = RSAKeyPair(bits=512)
        m = 42
        c = rsa_encrypt_raw(kp.public_key(), m)
        m_recovered = rsa_decrypt_raw(kp.private_key(), c)
        assert m_recovered == m

    def test_encrypt_decrypt_random(self):
        from crypto.pa12_rsa import RSAKeyPair, rsa_encrypt_raw, rsa_decrypt_raw
        from crypto.utils import random_int
        kp = RSAKeyPair(bits=512)
        for _ in range(20):
            m = random_int(0, kp.n - 1)
            c = rsa_encrypt_raw(kp.public_key(), m)
            assert rsa_decrypt_raw(kp.private_key(), c) == m

    def test_deterministic(self):
        from crypto.pa12_rsa import RSAKeyPair, rsa_encrypt_raw
        kp = RSAKeyPair(bits=512)
        m = 12345
        c1 = rsa_encrypt_raw(kp.public_key(), m)
        c2 = rsa_encrypt_raw(kp.public_key(), m)
        assert c1 == c2, "Textbook RSA must be deterministic"

    def test_message_out_of_range(self):
        from crypto.pa12_rsa import RSAKeyPair, rsa_encrypt_raw
        kp = RSAKeyPair(bits=512)
        with pytest.raises(AssertionError):
            rsa_encrypt_raw(kp.public_key(), kp.n)


class TestPKCS15:
    def test_pad_unpad_roundtrip(self):
        from crypto.pa12_rsa import pkcs15_pad, pkcs15_unpad
        msg = b'Hello RSA!'
        em = pkcs15_pad(msg, 64)
        assert len(em) == 64
        assert em[0] == 0x00 and em[1] == 0x02
        recovered = pkcs15_unpad(em)
        assert recovered == msg

    def test_pad_randomness(self):
        from crypto.pa12_rsa import pkcs15_pad
        msg = b'test'
        em1 = pkcs15_pad(msg, 64)
        em2 = pkcs15_pad(msg, 64)
        assert em1 != em2

    def test_pad_ps_nonzero(self):
        from crypto.pa12_rsa import pkcs15_pad
        msg = b'x'
        em = pkcs15_pad(msg, 64)
        sep_idx = em.index(b'\x00', 2)
        ps = em[2:sep_idx]
        assert all(b != 0 for b in ps), "PS bytes must be nonzero"

    def test_pad_ps_minimum_length(self):
        from crypto.pa12_rsa import pkcs15_pad
        msg = b'A' * 53
        em = pkcs15_pad(msg, 64)
        sep_idx = em.index(b'\x00', 2)
        assert sep_idx >= 10

    def test_pad_message_too_long(self):
        from crypto.pa12_rsa import pkcs15_pad
        with pytest.raises(ValueError):
            pkcs15_pad(b'A' * 54, 64)

    def test_unpad_malformed(self):
        from crypto.pa12_rsa import pkcs15_unpad
        with pytest.raises(ValueError):
            pkcs15_unpad(b'\x00\x01' + b'\xff' * 60 + b'\x00' + b'msg')
        with pytest.raises(ValueError):
            pkcs15_unpad(b'\x01\x02' + b'\xff' * 60 + b'\x00' + b'msg')

    def test_encrypt_decrypt_pkcs(self):
        from crypto.pa12_rsa import RSAKeyPair, pkcs15_encrypt, pkcs15_decrypt
        kp = RSAKeyPair(bits=512)
        msg = b'PKCS#1 v1.5 test'
        c = pkcs15_encrypt(kp.public_key(), msg, kp.byte_size)
        recovered = pkcs15_decrypt(kp.private_key(), c, kp.byte_size)
        assert recovered == msg

    def test_pkcs_randomized(self):
        from crypto.pa12_rsa import RSAKeyPair, pkcs15_encrypt
        kp = RSAKeyPair(bits=512)
        msg = b'same'
        c1 = pkcs15_encrypt(kp.public_key(), msg, kp.byte_size)
        c2 = pkcs15_encrypt(kp.public_key(), msg, kp.byte_size)
        assert c1 != c2

    def test_pkcs_various_lengths(self):
        from crypto.pa12_rsa import RSAKeyPair, pkcs15_encrypt, pkcs15_decrypt
        kp = RSAKeyPair(bits=1024)
        max_msg_len = kp.byte_size - 11
        for length in [0, 1, 10, 50, max_msg_len]:
            msg = b'X' * length if length > 0 else b''
            c = pkcs15_encrypt(kp.public_key(), msg, kp.byte_size)
            assert pkcs15_decrypt(kp.private_key(), c, kp.byte_size) == msg


class TestDeterminismAttack:
    def test_attack(self):
        from crypto.pa12_rsa import determinism_attack_demo
        result = determinism_attack_demo()
        assert result['textbook']['identical'], "Textbook RSA must produce identical ciphertexts"
        assert not result['pkcs15']['identical'], "PKCS#1 v1.5 must produce different ciphertexts"
