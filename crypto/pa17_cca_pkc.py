"""
PA#17 — CCA-Secure Public-Key Cryptosystem via Signcryption.

Construction (Encrypt-then-Sign):
    Encrypt: CE = ElGamal_Enc(pk_enc, m)
    Sign:    σ = RSA_Sign(sk_sign, CE)
    Output:  (CE, σ)

Decrypt (Verify-then-Decrypt):
    1. Verify RSA_Verify(vk_sign, CE, σ). If fails → ⊥.
    2. m = ElGamal_Dec(sk_enc, CE).

Dependencies:
    - crypto.pa16_elgamal (ElGamalKeyPair, elgamal_encrypt, elgamal_decrypt)
    - crypto.pa15_signatures (RSASignatureScheme)
    - crypto.utils
"""

from crypto.pa16_elgamal import (
    ElGamalKeyPair, elgamal_encrypt, elgamal_decrypt
)
from crypto.pa15_signatures import RSASignatureScheme
from crypto.pa08_dlp_hash import DLPHash
from crypto.utils import int_to_bytes, bytes_to_int


class CCADecryptionError(Exception):
    """Raised when signature verification fails."""
    pass


class CCASecurePKC:
    """
    CCA-Secure Public-Key Cryptosystem via Encrypt-then-Sign.
    """

    def __init__(self, elgamal_kp: ElGamalKeyPair = None,
                 sig_scheme: RSASignatureScheme = None,
                 elgamal_bits: int = 64, rsa_bits: int = 512):
        self.elgamal = elgamal_kp or ElGamalKeyPair(bits=elgamal_bits)
        self.signer = sig_scheme or RSASignatureScheme(rsa_bits=rsa_bits)
        # Byte length for serializing group elements
        self._elem_bytes = (self.elgamal.params.p.bit_length() + 7) // 8

    def _serialize_ct(self, c1: int, c2: int) -> bytes:
        """Serialize (c1, c2) to bytes for signing."""
        return int_to_bytes(c1, self._elem_bytes) + int_to_bytes(c2, self._elem_bytes)

    def encrypt(self, m: int) -> tuple:
        """
        Encrypt-then-Sign.

        Returns (c1, c2, sigma).
        """
        c1, c2 = elgamal_encrypt(self.elgamal.public_key(), m)
        ce_bytes = self._serialize_ct(c1, c2)
        sigma = self.signer.sign(ce_bytes)
        return (c1, c2, sigma)

    def decrypt(self, c1: int, c2: int, sigma: int) -> int:
        """
        Verify-then-Decrypt.

        Raises CCADecryptionError if signature is invalid.
        """
        ce_bytes = self._serialize_ct(c1, c2)
        if not self.signer.verify(ce_bytes, sigma):
            raise CCADecryptionError("Signature invalid — decryption aborted (⊥)")
        return elgamal_decrypt(self.elgamal.private_key(), c1, c2, self.elgamal.params.p)

    def encrypt_bytes(self, message: bytes) -> tuple:
        """Encrypt byte string."""
        m_int = bytes_to_int(message)
        assert 0 < m_int < self.elgamal.params.p
        return self.encrypt(m_int)

    def decrypt_bytes(self, c1: int, c2: int, sigma: int,
                      msg_length: int = None) -> bytes:
        """Decrypt to byte string."""
        m_int = self.decrypt(c1, c2, sigma)
        if msg_length is None:
            msg_length = max(1, (m_int.bit_length() + 7) // 8)
        return m_int.to_bytes(msg_length, 'big')


def cca2_game_demo(num_rounds: int = 50) -> dict:
    """
    IND-CCA2 game for the signcryption scheme.
    """
    import os
    from crypto.utils import random_int

    scheme = CCASecurePKC(elgamal_bits=64, rsa_bits=512)
    p = scheme.elgamal.params.p

    wins = 0
    oracle_rejections = 0
    oracle_total = 0

    for _ in range(num_rounds):
        m0 = random_int(1, p - 1)
        m1 = random_int(1, p - 1)
        b = os.urandom(1)[0] & 1
        m_b = m0 if b == 0 else m1

        c1_star, c2_star, sigma_star = scheme.encrypt(m_b)

        # Adversary tries tampered decryption queries
        for _ in range(5):
            tampered_c2 = (c2_star * 2) % p
            oracle_total += 1
            try:
                scheme.decrypt(c1_star, tampered_c2, sigma_star)
            except CCADecryptionError:
                oracle_rejections += 1

        # Adversary guesses randomly
        b_prime = os.urandom(1)[0] & 1
        if b_prime == b:
            wins += 1

    return {
        'rounds': num_rounds,
        'wins': wins,
        'advantage': abs(wins / num_rounds - 0.5),
        'oracle_rejections': oracle_rejections,
        'oracle_total': oracle_total,
    }


def malleability_comparison_demo() -> dict:
    """
    Compare plain ElGamal (malleable) vs PA#17 (not malleable).
    """
    from crypto.utils import random_int
    from crypto.pa16_elgamal import elgamal_encrypt, elgamal_decrypt, ElGamalKeyPair

    # Plain ElGamal: malleable
    kp = ElGamalKeyPair(bits=64)
    pk = kp.public_key()
    p = pk['p']
    m = random_int(2, p // 2)
    c1, c2 = elgamal_encrypt(pk, m)
    modified_c2 = (c2 * 2) % p
    decrypted = elgamal_decrypt(kp.private_key(), c1, modified_c2, p)
    plain_malleable = (decrypted == (2 * m) % p)

    # PA#17: not malleable (signature blocks it)
    scheme = CCASecurePKC(elgamal_bits=64, rsa_bits=512)
    p17 = scheme.elgamal.params.p
    m17 = random_int(1, p17 - 1)
    c1_17, c2_17, sigma_17 = scheme.encrypt(m17)
    blocked = False
    error_msg = ''
    try:
        scheme.decrypt(c1_17, (c2_17 * 2) % p17, sigma_17)
    except CCADecryptionError as e:
        blocked = True
        error_msg = str(e)

    return {
        'plain_elgamal': {
            'malleable': plain_malleable,
            'recovered_2m': plain_malleable,
        },
        'cca_secure': {
            'blocked': blocked,
            'error': error_msg,
        },
    }


def full_lineage_trace() -> dict:
    """
    Trace the full dependency chain for one encrypt/decrypt operation.
    """
    return {
        'chain': ['PA#17 (CCA-PKC)', 'PA#16 (ElGamal)', 'PA#11 (DH)',
                  'PA#13 (Miller-Rabin)', 'PA#15 (Signatures)', 'PA#12 (RSA)',
                  'PA#13 (Miller-Rabin)', 'PA#8 (DLP Hash)', 'PA#7 (Merkle-Damgård)',
                  'PA#13 (Miller-Rabin)'],
        'all_own_code': True,
    }
