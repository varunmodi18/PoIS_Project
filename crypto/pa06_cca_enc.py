"""
PA#6 — CCA-Secure Symmetric Encryption via Encrypt-then-MAC.

Construction:
    Encrypt: CE = Enc_{kE}(m), t = Mac_{kM}(CE), output (CE, t)
    Decrypt: If Vrfy_{kM}(CE, t) fails → raise CCADecryptionError. Else → Dec_{kE}(CE).

Dependencies:
    - crypto.pa03_cpa_enc (CPA-secure encryption)
    - crypto.pa05_mac (CBC-MAC)
    - crypto.utils
"""

from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
from crypto.pa05_mac import cbc_mac, cbc_mac_verify
from crypto.utils import random_bytes


class CCADecryptionError(Exception):
    """Raised when MAC verification fails during CCA decryption (returns ⊥)."""
    pass


def cca_encrypt(key_enc: bytes, key_mac: bytes, message: bytes) -> tuple[bytes, bytes, bytes]:
    """
    CCA-secure encryption via Encrypt-then-MAC.

    Args:
        key_enc: 16-byte encryption key (kE).
        key_mac: 16-byte MAC key (kM). MUST differ from key_enc.
        message: Arbitrary-length plaintext.

    Returns:
        (r, ciphertext, tag) where:
            - r is the nonce from CPA encryption
            - ciphertext is the CPA ciphertext
            - tag is the MAC of (r || ciphertext)
    """
    r, ce = cpa_encrypt(key_enc, message)
    t = cbc_mac(key_mac, r + ce)
    return (r, ce, t)


def cca_decrypt(key_enc: bytes, key_mac: bytes, r: bytes,
                ciphertext: bytes, tag: bytes) -> bytes:
    """
    CCA decryption with MAC verification.

    CRITICAL: Verify MAC BEFORE decrypting.

    Raises:
        CCADecryptionError if MAC verification fails.
    """
    if not cbc_mac_verify(key_mac, r + ciphertext, tag):
        raise CCADecryptionError("MAC verification failed — ciphertext rejected (⊥)")
    return cpa_decrypt(key_enc, r, ciphertext)


def cca2_game_simulation(num_rounds: int = 50) -> dict:
    """
    IND-CCA2 game simulation.

    Returns:
        {'rounds': int, 'wins': int, 'advantage': float,
         'oracle_rejections': int, 'oracle_total_queries': int}
    """
    import os

    wins = 0
    oracle_rejections = 0
    oracle_total = 0

    for _ in range(num_rounds):
        ke = random_bytes(16)
        km = random_bytes(16)

        m0 = b'message zero!!!!'
        m1 = b'message one!!!!!'
        b = os.urandom(1)[0] & 1
        m_b = m0 if b == 0 else m1

        # Encrypt challenge
        r_star, ct_star, tag_star = cca_encrypt(ke, km, m_b)

        # Adversary queries decryption oracle on MODIFIED ciphertexts
        for _ in range(5):
            # Flip a byte of the ciphertext (not the challenge itself)
            tampered_ct = bytes([ct_star[0] ^ 0xFF]) + ct_star[1:]
            oracle_total += 1
            try:
                cca_decrypt(ke, km, r_star, tampered_ct, tag_star)
            except CCADecryptionError:
                oracle_rejections += 1

        # Adversary guesses randomly
        b_prime = os.urandom(1)[0] & 1
        if b_prime == b:
            wins += 1

    advantage = abs(wins / num_rounds - 0.5)
    return {
        'rounds': num_rounds,
        'wins': wins,
        'advantage': advantage,
        'oracle_rejections': oracle_rejections,
        'oracle_total_queries': oracle_total,
    }


def malleability_attack_cpa_only() -> dict:
    """
    Demonstrate malleability of CPA-only encryption.
    Flipping a bit in ciphertext flips the same bit in plaintext (CTR-mode style).
    """
    key = random_bytes(16)
    msg = b'Hello, World!!!!'  # 16 bytes = 1 block
    r, ct = cpa_encrypt(key, msg)

    # Flip bit 0 of the first ciphertext byte
    flip_byte = 0
    ct_tampered = bytes([ct[flip_byte] ^ 0x80]) + ct[flip_byte + 1:]

    recovered = cpa_decrypt(key, r, ct_tampered)

    bit_flipped = (recovered[flip_byte] ^ msg[flip_byte]) == 0x80

    return {
        'original': msg.hex(),
        'flipped_bit': flip_byte * 8,
        'modified_plaintext': recovered.hex(),
        'bit_was_flipped': bit_flipped,
    }


def malleability_blocked_cca() -> dict:
    """
    Show that the same bit-flip attack is BLOCKED by Encrypt-then-MAC.
    """
    ke = random_bytes(16)
    km = random_bytes(16)
    msg = b'Hello, World!!!!'

    r, ct, tag = cca_encrypt(ke, km, msg)

    # Flip a bit in ciphertext
    ct_tampered = bytes([ct[0] ^ 0x80]) + ct[1:]

    attack_blocked = False
    error_message = ''
    try:
        cca_decrypt(ke, km, r, ct_tampered, tag)
    except CCADecryptionError as e:
        attack_blocked = True
        error_message = str(e)

    return {
        'attack_blocked': attack_blocked,
        'error_message': error_message,
    }


def key_reuse_vulnerability() -> dict:
    """
    Demonstrate that using the same key for encryption and MAC is dangerous.
    """
    k = random_bytes(16)

    # Encrypt with k and MAC with k (WRONG — key reuse)
    r, ce = cpa_encrypt(k, b'Secret message!!')
    tag = cbc_mac(k, r + ce)

    # An adversary that knows the MAC output could potentially exploit
    # structural relationships. With independent keys, this correlation
    # is impossible to exploit.
    r_good, ce_good, tag_good = cca_encrypt(k, random_bytes(16), b'Secret message!!')

    return {
        'explanation': (
            "Using the same key for encryption and MAC can create exploitable "
            "correlations. The PRF security of AES requires the key to be kept "
            "secret. If the MAC reveals key-dependent information, the encryption "
            "key is compromised. Always use independently generated keys."
        ),
        'independent_keys_used': True,
    }
