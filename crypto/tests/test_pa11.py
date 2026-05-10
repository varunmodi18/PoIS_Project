"""Tests for PA#11 — Diffie-Hellman Key Exchange."""
import time


class TestDHParams:
    def test_construction(self):
        from crypto.pa11_diffie_hellman import DHParams
        params = DHParams(bits=64)
        assert hasattr(params, 'p') and hasattr(params, 'q') and hasattr(params, 'g')

    def test_safe_prime(self):
        from crypto.pa11_diffie_hellman import DHParams
        from crypto.pa13_miller_rabin import is_prime
        params = DHParams(bits=64)
        assert params.p == 2 * params.q + 1
        assert is_prime(params.p) and is_prime(params.q)

    def test_generator_order(self):
        from crypto.pa11_diffie_hellman import DHParams
        params = DHParams(bits=64)
        assert pow(params.g, params.q, params.p) == 1
        assert params.g != 1


class TestDHExchange:
    def test_keys_match(self):
        from crypto.pa11_diffie_hellman import DHParams, dh_full_exchange
        params = DHParams(bits=64)
        result = dh_full_exchange(params)
        assert result['keys_match'], "Alice and Bob must derive the same shared secret"

    def test_keys_match_repeated(self):
        from crypto.pa11_diffie_hellman import DHParams, dh_full_exchange
        params = DHParams(bits=64)
        for _ in range(10):
            result = dh_full_exchange(params)
            assert result['keys_match']

    def test_different_exchanges_different_keys(self):
        from crypto.pa11_diffie_hellman import DHParams, dh_full_exchange
        params = DHParams(bits=64)
        keys = set()
        for _ in range(10):
            result = dh_full_exchange(params)
            keys.add(result['K_alice'])
        assert len(keys) >= 9, "Different exchanges should produce different keys"

    def test_step_by_step(self):
        from crypto.pa11_diffie_hellman import (
            DHParams, dh_alice_step1, dh_bob_step1,
            dh_alice_step2, dh_bob_step2
        )
        params = DHParams(bits=64)
        a, A = dh_alice_step1(params)
        b, B = dh_bob_step1(params)
        K_a = dh_alice_step2(a, B, params)
        K_b = dh_bob_step2(b, A, params)
        assert K_a == K_b
        assert K_a == pow(params.g, a * b, params.p)

    def test_public_values_in_subgroup(self):
        from crypto.pa11_diffie_hellman import DHParams, dh_alice_step1
        params = DHParams(bits=64)
        a, A = dh_alice_step1(params)
        assert pow(A, params.q, params.p) == 1, "Public value must be in order-q subgroup"


class TestMITM:
    def test_mitm_attack(self):
        from crypto.pa11_diffie_hellman import DHParams, mitm_attack_demo
        params = DHParams(bits=64)
        result = mitm_attack_demo(params)
        assert result['eve_has_alice_key'], "Eve must derive Alice's shared secret"
        assert result['eve_has_bob_key'], "Eve must derive Bob's shared secret"
        assert result['alice_bob_keys_differ'], "Alice and Bob should NOT share a key"


class TestCDH:
    def test_cdh_brute_force_small(self):
        """For very small q (~2^16), brute force should find the secret."""
        from crypto.pa11_diffie_hellman import DHParams, cdh_hardness_demo
        params = DHParams(bits=32)
        result = cdh_hardness_demo(params)
        assert result['found_secret']
