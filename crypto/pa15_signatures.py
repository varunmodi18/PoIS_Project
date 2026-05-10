"""
PA#15 — Digital Signatures (RSA-based, hash-then-sign).

Sign: σ = H(m)^d mod N.
Verify: σ^e mod N == H(m).

Dependencies:
    - crypto.pa12_rsa (RSAKeyPair)
    - crypto.pa08_dlp_hash (DLPHash — for hashing messages before signing)
    - crypto.utils
"""

from crypto.pa12_rsa import RSAKeyPair
from crypto.pa08_dlp_hash import DLPHash
from crypto.utils import bytes_to_int, int_to_bytes


class RSASignatureScheme:
    """
    RSA Digital Signature with hash-then-sign.

    Sign(sk, m):
        1. h = H(m) using DLP hash from PA#8.
        2. h_int = bytes_to_int(h) mod N.
        3. σ = h_int^d mod N.

    Verify(vk, m, σ):
        1. h = H(m).
        2. h_int = bytes_to_int(h) mod N.
        3. Check: σ^e mod N == h_int.
    """

    def __init__(self, rsa_keypair: RSAKeyPair = None,
                 hasher: DLPHash = None, rsa_bits: int = 512):
        self.kp = rsa_keypair or RSAKeyPair(bits=rsa_bits)
        self.hasher = hasher or DLPHash(bits=64)

    def sign(self, message: bytes) -> int:
        """Sign a message."""
        h = self.hasher.hash(message)
        h_int = bytes_to_int(h) % self.kp.n
        return pow(h_int, self.kp.d, self.kp.n)

    def verify(self, message: bytes, sigma: int) -> bool:
        """Verify a signature."""
        h = self.hasher.hash(message)
        h_int = bytes_to_int(h) % self.kp.n
        check = pow(sigma, self.kp.e, self.kp.n)
        return check == h_int

    def public_key(self) -> tuple:
        return self.kp.public_key()


class RawRSASignature:
    """
    RAW RSA signature (NO hashing — INSECURE).

    Vulnerable to multiplicative forgery:
        σ(m1) · σ(m2) mod N = (m1·m2)^d mod N = σ(m1·m2).
    """

    def __init__(self, rsa_keypair: RSAKeyPair = None, rsa_bits: int = 512):
        self.kp = rsa_keypair or RSAKeyPair(bits=rsa_bits)

    def sign(self, m: int) -> int:
        """Sign integer m: σ = m^d mod N."""
        return pow(m, self.kp.d, self.kp.n)

    def verify(self, m: int, sigma: int) -> bool:
        """Verify: σ^e mod N == m."""
        return pow(sigma, self.kp.e, self.kp.n) == m


def euf_cma_game(scheme: RSASignatureScheme, num_queries: int = 50) -> dict:
    """
    EUF-CMA game for the hash-then-sign scheme.
    """
    from crypto.utils import random_bytes

    # Adversary collects oracle queries
    queried_msgs = set()
    for i in range(num_queries):
        msg = f'query_{i}'.encode()
        scheme.sign(msg)
        queried_msgs.add(msg)

    # Adversary tries to forge for new messages
    forgery_attempts = 10
    forgeries_succeeded = 0
    for i in range(forgery_attempts):
        new_msg = f'forge_attempt_{i}'.encode()
        # Random sigma guess
        fake_sigma = bytes_to_int(random_bytes(scheme.kp.byte_size)) % scheme.kp.n
        if scheme.verify(new_msg, fake_sigma):
            forgeries_succeeded += 1

    return {
        'queries': num_queries,
        'forgery_attempts': forgery_attempts,
        'forgeries_succeeded': forgeries_succeeded,
        'secure': forgeries_succeeded == 0,
    }


def multiplicative_forgery_demo() -> dict:
    """
    Demonstrate multiplicative forgery on RAW RSA signatures.

    σ(m1) · σ(m2) mod N is a valid signature on m1 · m2 mod N.
    This attack FAILS on hash-then-sign.
    """
    from crypto.utils import random_int

    kp = RSAKeyPair(bits=512)
    raw_scheme = RawRSASignature(rsa_keypair=kp)
    hash_scheme = RSASignatureScheme(rsa_keypair=kp)

    # Raw RSA forgery
    m1 = random_int(2, kp.n - 1)
    m2 = random_int(2, kp.n - 1)
    sigma1 = raw_scheme.sign(m1)
    sigma2 = raw_scheme.sign(m2)

    forged_message = (m1 * m2) % kp.n
    forged_sigma = (sigma1 * sigma2) % kp.n
    raw_forgery_valid = raw_scheme.verify(forged_message, forged_sigma)

    # Hash-then-sign: the same trick fails
    # σ_hash(m1) · σ_hash(m2) mod N = (H(m1) · H(m2))^d mod N
    # But H(m1·m2) ≠ H(m1)·H(m2), so verification fails
    hsig1 = hash_scheme.sign(m1.to_bytes((m1.bit_length() + 7) // 8, 'big'))
    hsig2 = hash_scheme.sign(m2.to_bytes((m2.bit_length() + 7) // 8, 'big'))
    h_forged_sigma = (hsig1 * hsig2) % kp.n
    h_forged_msg = (m1 * m2).to_bytes(((m1 * m2).bit_length() + 7) // 8, 'big')
    hash_forgery_valid = hash_scheme.verify(h_forged_msg, h_forged_sigma)

    return {
        'raw': {
            'm1': m1, 'm2': m2,
            'sigma1': sigma1, 'sigma2': sigma2,
            'forged_message': forged_message,
            'forged_sigma': forged_sigma,
            'forgery_valid': raw_forgery_valid,
        },
        'hash_then_sign': {
            'forgery_valid': hash_forgery_valid,
        },
    }
