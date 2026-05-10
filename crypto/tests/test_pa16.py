"""Tests for PA#16 — ElGamal PKC."""


class TestElGamalKeyGen:
    def test_key_generation(self):
        from crypto.pa16_elgamal import ElGamalKeyPair
        kp = ElGamalKeyPair(bits=64)
        pk = kp.public_key()
        assert 'p' in pk and 'g' in pk and 'q' in pk and 'h' in pk

    def test_h_equals_g_to_x(self):
        from crypto.pa16_elgamal import ElGamalKeyPair
        kp = ElGamalKeyPair(bits=64)
        assert kp.h == pow(kp.params.g, kp.x, kp.params.p)

    def test_h_in_subgroup(self):
        from crypto.pa16_elgamal import ElGamalKeyPair
        kp = ElGamalKeyPair(bits=64)
        assert pow(kp.h, kp.params.q, kp.params.p) == 1


class TestElGamalEncDec:
    def test_roundtrip(self):
        from crypto.pa16_elgamal import ElGamalKeyPair, elgamal_encrypt, elgamal_decrypt
        from crypto.utils import random_int
        kp = ElGamalKeyPair(bits=64)
        pk = kp.public_key()
        for _ in range(20):
            m = random_int(1, pk['p'] - 1)
            c1, c2 = elgamal_encrypt(pk, m)
            recovered = elgamal_decrypt(kp.private_key(), c1, c2, pk['p'])
            assert recovered == m

    def test_randomized(self):
        from crypto.pa16_elgamal import ElGamalKeyPair, elgamal_encrypt
        kp = ElGamalKeyPair(bits=64)
        pk = kp.public_key()
        m = 42
        c1_a, c2_a = elgamal_encrypt(pk, m)
        c1_b, c2_b = elgamal_encrypt(pk, m)
        assert (c1_a, c2_a) != (c1_b, c2_b)

    def test_bytes_roundtrip(self):
        from crypto.pa16_elgamal import ElGamalKeyPair, elgamal_encrypt_bytes, elgamal_decrypt_bytes
        kp = ElGamalKeyPair(bits=64)
        pk = kp.public_key()
        msg = b'Hi!'
        c1, c2 = elgamal_encrypt_bytes(pk, msg)
        recovered = elgamal_decrypt_bytes(kp.private_key(), c1, c2, pk['p'], len(msg))
        assert recovered == msg


class TestMalleability:
    def test_malleability(self):
        from crypto.pa16_elgamal import malleability_attack_demo
        result = malleability_attack_demo(bits=64)
        assert result['attack_succeeded'], "ElGamal must be malleable"

    def test_cpa_game(self):
        from crypto.pa16_elgamal import cpa_game_demo
        result = cpa_game_demo(bits=64, num_rounds=100)
        assert result['advantage'] < 0.15
