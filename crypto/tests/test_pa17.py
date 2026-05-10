"""Tests for PA#17 — CCA-Secure PKC."""
import pytest


class TestCCASecurePKC:
    def test_roundtrip(self):
        from crypto.pa17_cca_pkc import CCASecurePKC
        from crypto.utils import random_int
        scheme = CCASecurePKC(elgamal_bits=64, rsa_bits=512)
        p = scheme.elgamal.params.p
        for _ in range(10):
            m = random_int(1, p - 1)
            c1, c2, sigma = scheme.encrypt(m)
            assert scheme.decrypt(c1, c2, sigma) == m

    def test_bytes_roundtrip(self):
        from crypto.pa17_cca_pkc import CCASecurePKC
        scheme = CCASecurePKC(elgamal_bits=64, rsa_bits=512)
        msg = b'CCA-PKC!'
        c1, c2, sigma = scheme.encrypt_bytes(msg)
        assert scheme.decrypt_bytes(c1, c2, sigma, len(msg)) == msg

    def test_tampered_c1_rejected(self):
        from crypto.pa17_cca_pkc import CCASecurePKC, CCADecryptionError
        from crypto.utils import random_int
        scheme = CCASecurePKC(elgamal_bits=64, rsa_bits=512)
        m = random_int(1, scheme.elgamal.params.p - 1)
        c1, c2, sigma = scheme.encrypt(m)
        with pytest.raises(CCADecryptionError):
            scheme.decrypt(c1 + 1, c2, sigma)

    def test_tampered_c2_rejected(self):
        from crypto.pa17_cca_pkc import CCASecurePKC, CCADecryptionError
        from crypto.utils import random_int
        scheme = CCASecurePKC(elgamal_bits=64, rsa_bits=512)
        m = random_int(1, scheme.elgamal.params.p - 1)
        c1, c2, sigma = scheme.encrypt(m)
        with pytest.raises(CCADecryptionError):
            scheme.decrypt(c1, c2 * 2 % scheme.elgamal.params.p, sigma)

    def test_tampered_sigma_rejected(self):
        from crypto.pa17_cca_pkc import CCASecurePKC, CCADecryptionError
        from crypto.utils import random_int
        scheme = CCASecurePKC(elgamal_bits=64, rsa_bits=512)
        m = random_int(1, scheme.elgamal.params.p - 1)
        c1, c2, sigma = scheme.encrypt(m)
        with pytest.raises(CCADecryptionError):
            scheme.decrypt(c1, c2, sigma + 1)

    def test_verify_before_decrypt(self):
        from crypto.pa17_cca_pkc import CCASecurePKC, CCADecryptionError
        scheme = CCASecurePKC(elgamal_bits=64, rsa_bits=512)
        m = 42
        c1, c2, sigma = scheme.encrypt(m)
        with pytest.raises(CCADecryptionError):
            scheme.decrypt(c1, c2 * 3 % scheme.elgamal.params.p, sigma)


class TestCCA2Game:
    def test_advantage(self):
        from crypto.pa17_cca_pkc import cca2_game_demo
        result = cca2_game_demo(num_rounds=50)
        assert result['advantage'] <= 0.25


class TestMalleabilityComparison:
    def test_comparison(self):
        from crypto.pa17_cca_pkc import malleability_comparison_demo
        result = malleability_comparison_demo()
        assert result['plain_elgamal']['malleable']
        assert result['cca_secure']['blocked']


class TestLineage:
    def test_full_lineage(self):
        from crypto.pa17_cca_pkc import full_lineage_trace
        result = full_lineage_trace()
        assert result['all_own_code']
        assert 'PA#13 (Miller-Rabin)' in result['chain']
