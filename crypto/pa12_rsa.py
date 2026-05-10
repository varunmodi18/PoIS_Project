"""
PA#12 — Textbook RSA and PKCS#1 v1.5 Padded RSA.

Key generation:
    1. Pick primes p, q using PA#13. N = p*q.
    2. φ(N) = (p-1)(q-1).
    3. e = 65537 (standard). d = e^(-1) mod φ(N).
    4. Public key: (N, e). Private key: (N, d, p, q, dp, dq, q_inv).

Dependencies:
    - crypto.pa13_miller_rabin (gen_prime)
    - crypto.utils (mod_inverse, random_bytes, random_int, bytes_to_int, int_to_bytes)
"""

from crypto.pa13_miller_rabin import gen_prime
from crypto.utils import mod_inverse, random_bytes, random_int, bytes_to_int, int_to_bytes


class RSAKeyPair:
    """RSA key pair container."""

    def __init__(self, bits: int = 1024):
        self.e = 65537
        while True:
            self.p = gen_prime(bits // 2)
            self.q = gen_prime(bits // 2)
            while self.q == self.p:
                self.q = gen_prime(bits // 2)
            self.n = self.p * self.q
            phi_n = (self.p - 1) * (self.q - 1)
            from crypto.utils import gcd
            if gcd(self.e, phi_n) == 1:
                break
        self.d = mod_inverse(self.e, phi_n)
        self.dp = self.d % (self.p - 1)
        self.dq = self.d % (self.q - 1)
        self.q_inv = mod_inverse(self.q, self.p)
        self.key_size = self.n.bit_length()
        self.byte_size = (self.key_size + 7) // 8

    def public_key(self) -> tuple:
        """Return (N, e)."""
        return (self.n, self.e)

    def private_key(self) -> dict:
        """Return full private key including CRT components."""
        return {
            'n': self.n, 'd': self.d,
            'p': self.p, 'q': self.q,
            'dp': self.dp, 'dq': self.dq, 'q_inv': self.q_inv
        }


# ============================================================
# Textbook RSA (INSECURE — deterministic)
# ============================================================

def rsa_encrypt_raw(pk: tuple, m: int) -> int:
    """Textbook RSA encryption: C = M^e mod N."""
    n, e = pk
    assert 0 <= m < n, f"Message {m} out of range [0, {n})"
    return pow(m, e, n)


def rsa_decrypt_raw(sk: dict, c: int) -> int:
    """Textbook RSA decryption: M = C^d mod N."""
    return pow(c, sk['d'], sk['n'])


# ============================================================
# PKCS#1 v1.5 Padded RSA
# ============================================================

def pkcs15_pad(message: bytes, key_byte_size: int) -> bytes:
    """
    PKCS#1 v1.5 encryption padding.

    EM = 0x00 || 0x02 || PS || 0x00 || message
    PS is at least 8 non-zero random bytes.
    """
    ps_len = key_byte_size - len(message) - 3
    if ps_len < 8:
        raise ValueError(f"Message too long for key size: need ps_len >= 8, got {ps_len}")

    # Generate ps_len non-zero random bytes
    ps = bytearray()
    while len(ps) < ps_len:
        b = random_bytes(1)[0]
        if b != 0:
            ps.append(b)

    em = b'\x00\x02' + bytes(ps) + b'\x00' + message
    assert len(em) == key_byte_size
    return em


def pkcs15_unpad(em: bytes) -> bytes:
    """Remove PKCS#1 v1.5 encryption padding."""
    if len(em) < 11 or em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("Invalid PKCS#1 v1.5 padding: bad header bytes")

    # Find separator 0x00 after the PS (starting from index 2)
    try:
        sep_idx = em.index(b'\x00', 2)
    except ValueError:
        raise ValueError("Invalid PKCS#1 v1.5 padding: no separator found")

    if sep_idx < 10:  # At least 8 PS bytes between positions 2 and sep_idx
        raise ValueError("Invalid PKCS#1 v1.5 padding: PS too short")

    return em[sep_idx + 1:]


def pkcs15_encrypt(pk: tuple, message: bytes, key_byte_size: int) -> int:
    """PKCS#1 v1.5 RSA encryption."""
    em = pkcs15_pad(message, key_byte_size)
    m_int = bytes_to_int(em)
    return rsa_encrypt_raw(pk, m_int)


def pkcs15_decrypt(sk: dict, ciphertext: int, key_byte_size: int) -> bytes:
    """PKCS#1 v1.5 RSA decryption."""
    m_int = rsa_decrypt_raw(sk, ciphertext)
    em = int_to_bytes(m_int, key_byte_size)
    return pkcs15_unpad(em)


# ============================================================
# Attack Demonstrations
# ============================================================

def determinism_attack_demo() -> dict:
    """
    Textbook RSA determinism attack.
    """
    kp = RSAKeyPair(bits=512)
    msg = b'Hello'
    m_int = bytes_to_int(msg)

    # Textbook RSA: same message → same ciphertext
    c1 = rsa_encrypt_raw(kp.public_key(), m_int)
    c2 = rsa_encrypt_raw(kp.public_key(), m_int)

    # PKCS#1 v1.5: same message → different ciphertexts
    pkcs_c1 = pkcs15_encrypt(kp.public_key(), msg, kp.byte_size)
    pkcs_c2 = pkcs15_encrypt(kp.public_key(), msg, kp.byte_size)

    return {
        'textbook': {
            'message': msg.hex(),
            'c1': c1, 'c2': c2,
            'identical': c1 == c2,
        },
        'pkcs15': {
            'message': msg.hex(),
            'c1': pkcs_c1, 'c2': pkcs_c2,
            'identical': pkcs_c1 == pkcs_c2,
        },
    }


def bleichenbacher_simplified_demo(bits: int = 256) -> dict:
    """
    Simplified Bleichenbacher padding oracle attack concept demonstration.
    """
    kp = RSAKeyPair(bits=bits)
    msg = b'secret'
    c = pkcs15_encrypt(kp.public_key(), msg, kp.byte_size)

    # Padding oracle: returns True if decrypted ciphertext has valid PKCS#1 padding
    def padding_oracle(ciphertext: int) -> bool:
        try:
            pkcs15_decrypt(kp.private_key(), ciphertext, kp.byte_size)
            return True
        except ValueError:
            return False

    # Demonstrate: multiplying ciphertext by s^e mod N gives ciphertext for s*m
    oracle_queries = 0
    intervals_narrowed = 0

    # Try a few multiplications
    for s in range(2, 10):
        s_e = rsa_encrypt_raw(kp.public_key(), s)  # s^e mod N
        n, e = kp.public_key()
        c_prime = (c * s_e) % n
        oracle_queries += 1
        is_valid = padding_oracle(c_prime)
        if is_valid:
            intervals_narrowed += 1

    return {
        'oracle_queries': oracle_queries,
        'intervals_narrowed': intervals_narrowed,
        'partial_recovery': intervals_narrowed > 0,
        'explanation': (
            "Bleichenbacher's attack uses the padding oracle to narrow the interval "
            "containing m. Multiplying c by s^e mod N gives a ciphertext for s*m mod N. "
            "By checking padding validity, the attacker learns whether s*m falls in [2B, 3B). "
            "After ~2^20 queries, m is recovered. PKCS#1 v1.5 should use OAEP instead."
        ),
    }
