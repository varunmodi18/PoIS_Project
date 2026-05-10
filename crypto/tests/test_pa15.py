"""Tests for PA#15 — Digital Signatures."""


class TestRSASignatures:
    def test_sign_verify(self):
        from crypto.pa15_signatures import RSASignatureScheme
        scheme = RSASignatureScheme(rsa_bits=512)
        msg = b'Hello, sign me!'
        sigma = scheme.sign(msg)
        assert scheme.verify(msg, sigma)

    def test_wrong_message_fails(self):
        from crypto.pa15_signatures import RSASignatureScheme
        scheme = RSASignatureScheme(rsa_bits=512)
        sigma = scheme.sign(b'original')
        assert not scheme.verify(b'tampered', sigma)

    def test_wrong_signature_fails(self):
        from crypto.pa15_signatures import RSASignatureScheme
        from crypto.utils import random_int
        scheme = RSASignatureScheme(rsa_bits=512)
        msg = b'test'
        sigma = scheme.sign(msg)
        fake_sigma = random_int(1, scheme.kp.n - 1)
        assert not scheme.verify(msg, fake_sigma)

    def test_deterministic(self):
        from crypto.pa15_signatures import RSASignatureScheme
        scheme = RSASignatureScheme(rsa_bits=512)
        msg = b'deterministic'
        assert scheme.sign(msg) == scheme.sign(msg)

    def test_different_messages_different_sigs(self):
        from crypto.pa15_signatures import RSASignatureScheme
        scheme = RSASignatureScheme(rsa_bits=512)
        sigs = set()
        for i in range(10):
            sigs.add(scheme.sign(f'msg_{i}'.encode()))
        assert len(sigs) == 10

    def test_various_message_lengths(self):
        from crypto.pa15_signatures import RSASignatureScheme
        from crypto.utils import random_bytes
        scheme = RSASignatureScheme(rsa_bits=512)
        for length in [0, 1, 10, 100, 1000]:
            msg = random_bytes(length) if length > 0 else b''
            sigma = scheme.sign(msg)
            assert scheme.verify(msg, sigma), f"Failed for length {length}"


class TestEUFCMA:
    def test_unforgeable(self):
        from crypto.pa15_signatures import RSASignatureScheme, euf_cma_game
        scheme = RSASignatureScheme(rsa_bits=512)
        result = euf_cma_game(scheme, num_queries=50)
        assert result['forgeries_succeeded'] == 0


class TestMultiplicativeForgery:
    def test_raw_rsa_forgery(self):
        from crypto.pa15_signatures import multiplicative_forgery_demo
        result = multiplicative_forgery_demo()
        assert result['raw']['forgery_valid'], "Raw RSA must be forgeable"
        assert not result['hash_then_sign']['forgery_valid'], "Hash-then-sign must resist forgery"
