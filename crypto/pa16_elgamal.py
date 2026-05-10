"""
PA#16 — ElGamal Public-Key Cryptosystem.

Key gen: x ← Z_q (private), h = g^x (public).
Encrypt(m): r ← Z_q, C = (g^r, m · h^r) = (c1, c2).
Decrypt(c1, c2): m = c2 · c1^(-x) = c2 / c1^x.

Security: CPA-secure under DDH. NOT CCA-secure (malleable).

Dependencies:
    - crypto.pa11_diffie_hellman (DHParams — reuse group parameters)
    - crypto.utils
"""

from crypto.pa11_diffie_hellman import DHParams
from crypto.utils import random_int, mod_inverse


class ElGamalKeyPair:
    """ElGamal key pair."""

    def __init__(self, params: DHParams = None, bits: int = 64):
        self.params = params or DHParams(bits=bits)
        self.x = random_int(1, self.params.q - 1)
        self.h = pow(self.params.g, self.x, self.params.p)

    def public_key(self) -> dict:
        return {
            'p': self.params.p, 'g': self.params.g,
            'q': self.params.q, 'h': self.h
        }

    def private_key(self) -> int:
        return self.x


def elgamal_encrypt(pk: dict, m: int, r: int = None) -> tuple:
    """
    ElGamal encryption.

    Returns (c1, c2) where c1 = g^r mod p, c2 = m · h^r mod p.
    """
    p, g, q, h = pk['p'], pk['g'], pk['q'], pk['h']
    if r is None:
        r = random_int(1, q - 1)
    c1 = pow(g, r, p)
    c2 = (m * pow(h, r, p)) % p
    return c1, c2


def elgamal_decrypt(sk: int, c1: int, c2: int, p: int) -> int:
    """
    ElGamal decryption.

    m = c2 · c1^(-x) mod p.
    """
    s = pow(c1, sk, p)
    s_inv = mod_inverse(s, p)
    return (c2 * s_inv) % p


# ============================================================
# Byte-level wrappers
# ============================================================

def elgamal_encrypt_bytes(pk: dict, message: bytes) -> tuple:
    """Encrypt a byte string."""
    m_int = int.from_bytes(message, 'big')
    assert 0 < m_int < pk['p'], "Message too large for this group"
    return elgamal_encrypt(pk, m_int)


def elgamal_decrypt_bytes(sk: int, c1: int, c2: int, p: int,
                          msg_length: int = None) -> bytes:
    """Decrypt to byte string."""
    m_int = elgamal_decrypt(sk, c1, c2, p)
    if msg_length is None:
        msg_length = (m_int.bit_length() + 7) // 8
    return m_int.to_bytes(max(1, msg_length), 'big')


# ============================================================
# Attack Demonstrations
# ============================================================

def malleability_attack_demo(bits: int = 64) -> dict:
    """
    ElGamal malleability attack.

    (c1, 2*c2 mod p) decrypts to 2*m mod p.
    """
    kp = ElGamalKeyPair(bits=bits)
    pk = kp.public_key()
    p = pk['p']

    m = random_int(2, p // 2)   # ensure 2*m doesn't wrap
    c1, c2 = elgamal_encrypt(pk, m)

    # Modify c2 by multiplying by 2
    modified_c2 = (2 * c2) % p
    decrypted_modified = elgamal_decrypt(kp.private_key(), c1, modified_c2, p)
    expected_2m = (2 * m) % p

    return {
        'original_m': m,
        'c1': c1, 'c2': c2,
        'modified_c2': modified_c2,
        'decrypted_modified': decrypted_modified,
        'expected_2m': expected_2m,
        'attack_succeeded': decrypted_modified == expected_2m,
    }


def cpa_game_demo(bits: int = 64, num_rounds: int = 100) -> dict:
    """
    IND-CPA game for ElGamal (adversary guesses randomly).
    """
    import os
    kp = ElGamalKeyPair(bits=bits)
    pk = kp.public_key()
    p = pk['p']

    wins = 0
    for _ in range(num_rounds):
        m0 = random_int(1, p - 1)
        m1 = random_int(1, p - 1)
        b = os.urandom(1)[0] & 1
        m_b = m0 if b == 0 else m1
        # Challenge ciphertext
        c1, c2 = elgamal_encrypt(pk, m_b)
        # Adversary guesses randomly
        b_prime = os.urandom(1)[0] & 1
        if b_prime == b:
            wins += 1

    return {
        'rounds': num_rounds,
        'wins': wins,
        'advantage': abs(wins / num_rounds - 0.5),
    }
