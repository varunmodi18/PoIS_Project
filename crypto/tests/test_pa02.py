"""
Tests for PA#2 — Pseudorandom Functions (GGM + AES).
"""


class TestAES128:
    """AES-128 correctness using NIST test vectors."""

    def test_aes_encrypt_nist_vector_1(self):
        # Verified against OpenSSL: openssl enc -aes-128-ecb -nopad -nosalt
        # -K 00112233445566778899aabbccddeeff
        from crypto.pa02_prf import AES_PRF
        aes = AES_PRF()
        key = bytes.fromhex('00112233445566778899aabbccddeeff')
        pt  = bytes.fromhex('00112233445566778899aabbccddeeff')
        ct  = aes.encrypt_block(key, pt)
        assert ct.hex() == '62f679be2bf0d931641e039ca3401bb2', f"Got {ct.hex()}"

    def test_aes_encrypt_nist_vector_2(self):
        from crypto.pa02_prf import AES_PRF
        aes = AES_PRF()
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        pt  = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
        ct  = aes.encrypt_block(key, pt)
        assert ct.hex() == '3925841d02dc09fbdc118597196a0b32', f"Got {ct.hex()}"

    def test_aes_encrypt_all_zeros(self):
        from crypto.pa02_prf import AES_PRF
        aes = AES_PRF()
        key = bytes(16)
        pt  = bytes(16)
        ct  = aes.encrypt_block(key, pt)
        assert ct.hex() == '66e94bd4ef8a2c3b884cfa59ca342b2e', f"Got {ct.hex()}"

    def test_aes_decrypt_roundtrip(self):
        from crypto.pa02_prf import AES_PRF
        from crypto.utils import random_bytes
        aes = AES_PRF()
        for _ in range(20):
            key = random_bytes(16)
            pt = random_bytes(16)
            ct = aes.encrypt_block(key, pt)
            recovered = aes.decrypt_block(key, ct)
            assert recovered == pt, f"Roundtrip failed: {pt.hex()} -> {ct.hex()} -> {recovered.hex()}"

    def test_aes_deterministic(self):
        from crypto.pa02_prf import AES_PRF
        aes = AES_PRF()
        key = bytes.fromhex('0f1571c947d9e8590cb7add6af7f6798')
        pt = bytes.fromhex('0123456789abcdef0123456789abcdef')
        assert aes.encrypt_block(key, pt) == aes.encrypt_block(key, pt)

    def test_aes_different_keys(self):
        from crypto.pa02_prf import AES_PRF
        from crypto.utils import random_bytes
        aes = AES_PRF()
        pt = bytes(16)
        cts = set()
        for _ in range(50):
            key = random_bytes(16)
            cts.add(aes.encrypt_block(key, pt))
        assert len(cts) == 50

    def test_aes_prf_interface(self):
        from crypto.pa02_prf import AES_PRF
        from crypto.utils import random_bytes
        aes = AES_PRF()
        key = random_bytes(16)
        x = random_bytes(16)
        result = aes.F(key, x)
        assert isinstance(result, bytes) and len(result) == 16


class TestGGM_PRF:
    """GGM PRF correctness tests."""

    def test_ggm_deterministic(self):
        from crypto.pa01_owf_prg import DLP_OWF, PRG
        from crypto.pa02_prf import GGM_PRF
        owf = DLP_OWF(bits=32)
        prg = PRG(owf)
        ggm = GGM_PRF(prg)
        key = 42
        x = 5
        assert ggm.F(key, x) == ggm.F(key, x)

    def test_ggm_different_inputs(self):
        from crypto.pa01_owf_prg import DLP_OWF, PRG
        from crypto.pa02_prf import GGM_PRF
        owf = DLP_OWF(bits=32)
        prg = PRG(owf)
        ggm = GGM_PRF(prg)
        key = 100
        outputs = set()
        n_bits = ggm.n_bits
        for x in range(min(2**n_bits, 20)):
            outputs.add(ggm.F(key, x))
        assert len(outputs) >= 15, f"Only {len(outputs)} distinct outputs for 20 inputs"

    def test_ggm_different_keys(self):
        from crypto.pa01_owf_prg import DLP_OWF, PRG
        from crypto.pa02_prf import GGM_PRF
        owf = DLP_OWF(bits=32)
        prg = PRG(owf)
        ggm = GGM_PRF(prg)
        x = 7
        outputs = set()
        for key in range(20):
            outputs.add(ggm.F(key, x))
        assert len(outputs) >= 15

    def test_ggm_trace(self):
        from crypto.pa01_owf_prg import DLP_OWF, PRG
        from crypto.pa02_prf import GGM_PRF
        owf = DLP_OWF(bits=32)
        prg = PRG(owf)
        ggm = GGM_PRF(prg)
        trace = ggm.evaluate_with_trace(key=42, x=5, input_bits=4)
        assert 'path' in trace
        assert len(trace['path']) == 4
        # trace uses input_bits=4; compare against evaluate() with same input_bits
        assert trace['output'] == ggm.evaluate(42, 5, input_bits=4)


class TestPRGFromPRF:
    """Backward direction: PRF → PRG."""

    def test_prg_from_prf_length(self):
        from crypto.pa02_prf import AES_PRF, PRG_from_PRF
        from crypto.utils import random_bytes
        prg = PRG_from_PRF(AES_PRF())
        output = prg.generate(random_bytes(16))
        assert len(output) == 32

    def test_prg_from_prf_deterministic(self):
        from crypto.pa02_prf import AES_PRF, PRG_from_PRF
        prg = PRG_from_PRF(AES_PRF())
        seed = bytes.fromhex('00112233445566778899aabbccddeeff')
        assert prg.generate(seed) == prg.generate(seed)

    def test_prg_from_prf_different_seeds(self):
        from crypto.pa02_prf import AES_PRF, PRG_from_PRF
        from crypto.utils import random_bytes
        prg = PRG_from_PRF(AES_PRF())
        outputs = set()
        for _ in range(30):
            outputs.add(prg.generate(random_bytes(16)))
        assert len(outputs) == 30

    def test_prg_from_prf_statistical(self):
        from crypto.pa02_prf import AES_PRF, PRG_from_PRF
        from crypto.pa01_owf_prg import StatisticalTests
        from crypto.utils import random_bytes
        prg = PRG_from_PRF(AES_PRF())
        all_bits = []
        for _ in range(500):
            output = prg.generate(random_bytes(16))
            for byte in output:
                for bit_pos in range(8):
                    all_bits.append((byte >> (7 - bit_pos)) & 1)
        passed, p_val = StatisticalTests.frequency_monobit(all_bits)
        assert passed, f"PRG-from-PRF failed frequency test, p={p_val}"


class TestPRFDistinguishing:
    """PRF distinguishing game."""

    def test_aes_prf_vs_random(self):
        from crypto.pa02_prf import AES_PRF
        from crypto.utils import random_bytes
        aes = AES_PRF()
        key = random_bytes(16)

        prf_bytes = bytearray()
        rand_bytes_buf = bytearray()
        for _ in range(100):
            x = random_bytes(16)
            prf_bytes.extend(aes.F(key, x))
            rand_bytes_buf.extend(random_bytes(16))

        prf_counts = [0] * 256
        rand_counts = [0] * 256
        for b in prf_bytes:
            prf_counts[b] += 1
        for b in rand_bytes_buf:
            rand_counts[b] += 1

        expected = len(prf_bytes) / 256
        prf_chi2 = sum((c - expected)**2 / expected for c in prf_counts)
        rand_chi2 = sum((c - expected)**2 / expected for c in rand_counts)

        assert prf_chi2 < 400, f"PRF chi2 = {prf_chi2}, too high"
        assert rand_chi2 < 400, f"Random chi2 = {rand_chi2}, too high"
