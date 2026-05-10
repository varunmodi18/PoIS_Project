"""Tests for PA#14 — CRT + Håstad Broadcast Attack."""
import time


class TestCRT:
    def test_simple_crt(self):
        from crypto.pa14_crt import crt
        assert crt([2, 3, 2], [3, 5, 7]) == 23

    def test_crt_two_moduli(self):
        from crypto.pa14_crt import crt
        assert crt([1, 2], [3, 5]) == 7

    def test_crt_large(self):
        from crypto.pa14_crt import crt
        from crypto.pa13_miller_rabin import gen_prime
        n1, n2, n3 = gen_prime(64), gen_prime(64), gen_prime(64)
        x_original = 123456789
        a1 = x_original % n1
        a2 = x_original % n2
        a3 = x_original % n3
        x_recovered = crt([a1, a2, a3], [n1, n2, n3])
        assert x_recovered == x_original

    def test_crt_uniqueness(self):
        from crypto.pa14_crt import crt
        x = crt([2, 3], [5, 7])
        assert 0 <= x < 35
        assert x % 5 == 2
        assert x % 7 == 3


class TestCRTDecryption:
    def test_crt_matches_standard(self):
        from crypto.pa12_rsa import RSAKeyPair, rsa_encrypt_raw, rsa_decrypt_raw
        from crypto.pa14_crt import rsa_decrypt_crt
        from crypto.utils import random_int
        kp = RSAKeyPair(bits=512)
        for _ in range(20):
            m = random_int(0, kp.n - 1)
            c = rsa_encrypt_raw(kp.public_key(), m)
            m_std = rsa_decrypt_raw(kp.private_key(), c)
            m_crt = rsa_decrypt_crt(kp.private_key(), c)
            assert m_std == m_crt == m

    def test_crt_speedup(self):
        from crypto.pa14_crt import crt_rsa_performance_comparison
        result = crt_rsa_performance_comparison(bits=1024, num_trials=50)
        assert result['results_match']
        assert result['speedup'] > 1.5, f"CRT speedup {result['speedup']}x is too low"


class TestIntegerNthRoot:
    def test_cube_root(self):
        from crypto.pa14_crt import integer_nth_root
        assert integer_nth_root(27, 3) == 3
        assert integer_nth_root(64, 3) == 4
        assert integer_nth_root(125, 3) == 5

    def test_cube_root_large(self):
        from crypto.pa14_crt import integer_nth_root
        m = 123456789
        assert integer_nth_root(m ** 3, 3) == m

    def test_non_perfect(self):
        from crypto.pa14_crt import integer_nth_root
        assert integer_nth_root(28, 3) == 3

    def test_square_root(self):
        from crypto.pa14_crt import integer_nth_root
        assert integer_nth_root(144, 2) == 12
        assert integer_nth_root(145, 2) == 12

    def test_zero(self):
        from crypto.pa14_crt import integer_nth_root
        assert integer_nth_root(0, 3) == 0


class TestHastadAttack:
    def test_hastad_e3(self):
        from crypto.pa14_crt import hastad_demo
        result = hastad_demo(e=3, bits=512)
        assert result['attack_succeeded'], "Håstad attack with e=3 must succeed"
        assert result['recovered_message'] == result['message']

    def test_hastad_fails_with_padding(self):
        from crypto.pa14_crt import hastad_fails_with_padding_demo
        result = hastad_fails_with_padding_demo(e=3, bits=512)
        assert not result['attack_succeeded'], "Padding must defeat Håstad"
