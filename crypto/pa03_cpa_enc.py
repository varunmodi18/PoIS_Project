"""
PA#3 — CPA-Secure Symmetric Encryption.

Construction: C = <r, F_k(r) ⊕ m> (counter mode with random nonce)
For multi-block: C = <r, F_k(r)⊕m1 || F_k(r+1)⊕m2 || ...>

Dependencies:
    - crypto.pa02_prf (AES_PRF)
    - crypto.utils
"""

from crypto.pa02_prf import AES_PRF
from crypto.utils import random_bytes, xor_bytes, int_to_bytes, bytes_to_int

BLOCK_SIZE = 16  # AES block size in bytes


def pad_message(message: bytes) -> bytes:
    """
    PKCS#7 padding: pad message to multiple of BLOCK_SIZE.
    Always adds at least 1 byte of padding.
    """
    pad_len = BLOCK_SIZE - (len(message) % BLOCK_SIZE)
    # pad_len is in [1, BLOCK_SIZE] — never 0 because PKCS#7 always pads
    return message + bytes([pad_len] * pad_len)


def unpad_message(padded: bytes) -> bytes:
    """
    Remove PKCS#7 padding.
    Raises ValueError if padding is invalid.
    """
    if not padded:
        raise ValueError("Empty input to unpad")
    pad_len = padded[-1]
    if pad_len == 0 or pad_len > BLOCK_SIZE:
        raise ValueError(f"Invalid padding byte: {pad_len}")
    if len(padded) < pad_len:
        raise ValueError("Padded message too short for indicated pad length")
    for byte in padded[-pad_len:]:
        if byte != pad_len:
            raise ValueError("Invalid PKCS#7 padding: inconsistent padding bytes")
    return padded[:-pad_len]


def cpa_encrypt(key: bytes, message: bytes, prf: AES_PRF = None,
                fixed_r: bytes = None) -> tuple[bytes, bytes]:
    """
    CPA-secure encryption: C = <r, F_k(r)⊕m1 || F_k(r+1)⊕m2 || ...>

    Args:
        key: 16-byte PRF key.
        message: Arbitrary-length plaintext.
        prf: AES_PRF instance. If None, create one.
        fixed_r: FOR TESTING ONLY. Forces a specific nonce r.

    Returns:
        (r, ciphertext) where r is the 16-byte nonce.
    """
    prf = prf or AES_PRF()
    padded = pad_message(message)
    r = fixed_r if fixed_r is not None else random_bytes(16)

    blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    r_int = bytes_to_int(r)

    ciphertext_blocks = []
    for i, mi in enumerate(blocks):
        counter = r_int + i
        counter_bytes = int_to_bytes(counter, 16)
        ci = xor_bytes(prf.F(key, counter_bytes), mi)
        ciphertext_blocks.append(ci)

    return (r, b''.join(ciphertext_blocks))


def cpa_decrypt(key: bytes, r: bytes, ciphertext: bytes,
                prf: AES_PRF = None) -> bytes:
    """
    CPA decryption.

    Args:
        key: 16-byte PRF key.
        r: 16-byte nonce (from encryption).
        ciphertext: Encrypted message (multiple of BLOCK_SIZE).
        prf: AES_PRF instance.

    Returns:
        Original plaintext (unpadded).
    """
    prf = prf or AES_PRF()
    blocks = [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    r_int = bytes_to_int(r)

    plaintext_blocks = []
    for i, ci in enumerate(blocks):
        counter = r_int + i
        counter_bytes = int_to_bytes(counter, 16)
        mi = xor_bytes(prf.F(key, counter_bytes), ci)
        plaintext_blocks.append(mi)

    padded = b''.join(plaintext_blocks)
    return unpad_message(padded)


def cpa_game_simulation(num_rounds: int = 50) -> dict:
    """
    IND-CPA game simulation.
    Adversary advantage should be ≈ 0 for a CPA-secure scheme.
    """
    import os
    wins = 0
    for _ in range(num_rounds):
        # Challenger picks random key
        key = random_bytes(16)
        # Adversary picks two equal-length messages
        m0 = b'message zero!!!!'
        m1 = b'message one!!!!!'
        # Challenger picks random bit b
        b = os.urandom(1)[0] & 1
        m_b = m0 if b == 0 else m1
        # Challenger encrypts m_b
        _r, _ct = cpa_encrypt(key, m_b)
        # Adversary guesses randomly (can't do better)
        b_prime = os.urandom(1)[0] & 1
        if b_prime == b:
            wins += 1

    advantage = abs(wins / num_rounds - 0.5)
    return {'rounds': num_rounds, 'wins': wins, 'advantage': advantage}


def broken_deterministic_demo() -> dict:
    """
    Demonstrate the broken deterministic variant (reusing r).
    """
    key = random_bytes(16)
    r = random_bytes(16)
    m1 = b'Attack at dawn!!'
    m2 = b'Attack at dawn!!'
    m3 = b'Attack at dusk!!'

    _, c1 = cpa_encrypt(key, m1, fixed_r=r)
    _, c2 = cpa_encrypt(key, m2, fixed_r=r)
    _, c3 = cpa_encrypt(key, m3, fixed_r=r)

    xor_c1_c3 = xor_bytes(c1, c3)
    xor_m1_m3 = xor_bytes(m1, m3)

    return {
        'c1': c1.hex(),
        'c2': c2.hex(),
        'c3': c3.hex(),
        'c1_equals_c2': c1 == c2,
        'xor_c1_c3': xor_c1_c3.hex(),
        'xor_m1_m3': xor_m1_m3.hex(),
        'xor_match': xor_c1_c3 == xor_m1_m3,
    }
