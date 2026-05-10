"""
PA#5 — Message Authentication Codes.

Three constructions:
    1. PRF-MAC (fixed-length): Mac_k(m) = F_k(m) for single-block messages.
    2. CBC-MAC (variable-length): Chain PRF evaluations.
    3. HMAC (stub): Placeholder for PA#10.

Dependencies:
    - crypto.pa02_prf (AES_PRF)
    - crypto.utils
"""

import struct
from crypto.pa02_prf import AES_PRF
from crypto.utils import random_bytes, xor_bytes, bytes_to_int, int_to_bytes

BLOCK_SIZE = 16


def prf_mac(key: bytes, message: bytes, prf: AES_PRF = None) -> bytes:
    """
    PRF-MAC for fixed-length (single-block) messages.
    Mac_k(m) = F_k(m)

    Args:
        key: 16-byte key.
        message: Exactly 16 bytes.
        prf: AES_PRF instance.

    Returns:
        16-byte MAC tag.

    Raises:
        ValueError if len(message) != 16.
    """
    if len(message) != BLOCK_SIZE:
        raise ValueError(f"PRF-MAC requires exactly {BLOCK_SIZE}-byte message, got {len(message)}")
    prf = prf or AES_PRF()
    return prf.F(key, message)


def prf_mac_verify(key: bytes, message: bytes, tag: bytes,
                   prf: AES_PRF = None) -> bool:
    """
    Verify a PRF-MAC tag using constant-time comparison.
    """
    if len(message) != BLOCK_SIZE:
        return False
    expected = prf_mac(key, message, prf)
    return _constant_time_compare(expected, tag)


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    Prevents timing side-channels.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def cbc_mac(key: bytes, message: bytes, prf: AES_PRF = None) -> bytes:
    """
    CBC-MAC for variable-length messages.

    Prepends the message length as the first block (security for variable-length).

    Algorithm:
        1. Prepend 16-byte length block: struct.pack('>Q', len(message)) + 8 zero bytes.
        2. Append message, zero-pad to multiple of BLOCK_SIZE.
        3. t = 0^16
        4. For each block Mi: t = F_k(t XOR Mi)
        5. Return t.

    Args:
        key: 16-byte key.
        message: Arbitrary-length message.
        prf: AES_PRF instance.

    Returns:
        16-byte MAC tag.
    """
    prf = prf or AES_PRF()

    # Prepend length block: 8-byte big-endian length + 8 zero bytes
    length_block = struct.pack('>Q', len(message)) + b'\x00' * 8

    # Zero-pad message to multiple of BLOCK_SIZE
    padded_msg = message
    if len(padded_msg) % BLOCK_SIZE != 0:
        pad = BLOCK_SIZE - (len(padded_msg) % BLOCK_SIZE)
        padded_msg = padded_msg + b'\x00' * pad

    full_message = length_block + padded_msg

    # CBC-MAC chaining
    t = b'\x00' * BLOCK_SIZE
    for i in range(0, len(full_message), BLOCK_SIZE):
        block = full_message[i:i + BLOCK_SIZE]
        t = prf.F(key, xor_bytes(t, block))

    return t


def cbc_mac_verify(key: bytes, message: bytes, tag: bytes,
                   prf: AES_PRF = None) -> bool:
    """Verify CBC-MAC tag using constant-time comparison."""
    expected = cbc_mac(key, message, prf)
    return _constant_time_compare(expected, tag)


def hmac_stub(key: bytes, message: bytes) -> bytes:
    """
    HMAC placeholder. Will be implemented in PA#10.
    """
    raise NotImplementedError(
        "HMAC is not yet implemented. See PA#10 (Phase 3). "
        "This stub exists so the MAC interface is complete."
    )


# ============================================================
# Security demonstrations
# ============================================================

def euf_cma_game(mac_fn: callable, verify_fn: callable,
                 num_queries: int = 50) -> dict:
    """
    EUF-CMA game: adversary tries to forge a MAC without knowing the key.

    Returns:
        {'queries': num_queries, 'forgery_attempts': 20,
         'forgeries_succeeded': int, 'secure': bool}
    """
    import os
    from crypto.utils import random_int

    key = random_bytes(16)
    seen_messages = []

    # Adversary queries the MAC oracle
    for _ in range(num_queries):
        length = random_int(1, 64)
        mi = random_bytes(length)
        ti = mac_fn(key, mi)
        seen_messages.append((mi, ti))

    seen_set = set(m for m, _ in seen_messages)

    # Adversary attempts forgeries on new messages
    forgeries = 0
    forgery_attempts = 20
    for _ in range(forgery_attempts):
        # Pick a new message not in seen_set
        m_star = random_bytes(random_int(1, 64))
        while m_star in seen_set:
            m_star = random_bytes(random_int(1, 64))
        # Try random tag
        t_star = random_bytes(16)
        if verify_fn(key, m_star, t_star):
            forgeries += 1

    return {
        'queries': num_queries,
        'forgery_attempts': forgery_attempts,
        'forgeries_succeeded': forgeries,
        'secure': forgeries == 0,
    }


def mac_as_prf_demo() -> dict:
    """
    Backward direction: MAC → PRF.
    Show that MAC on random inputs produces uniform-looking outputs.
    """
    from crypto.pa01_owf_prg import StatisticalTests

    key = random_bytes(16)
    all_bits = []
    for _ in range(100):
        x = random_bytes(BLOCK_SIZE)
        tag = prf_mac(key, x)
        for byte in tag:
            for bit_pos in range(8):
                all_bits.append((byte >> (7 - bit_pos)) & 1)

    passed, p_value = StatisticalTests.frequency_monobit(all_bits)
    return {'prf_test_passed': passed, 'p_value': p_value}


def length_extension_attack_demo() -> dict:
    """
    Demonstrate length-extension vulnerability of naive H(k||m) MAC.
    Uses the toy MD hash from PA#7.
    """
    from crypto.pa07_merkle_damgard import create_toy_hash

    md = create_toy_hash(block_size=8, output_size=4)
    key = b'\x42\x13\xAB\xCD'  # 4-byte key
    message = b'hello'

    # "MAC" = H(k || m)
    tag = md.hash(key + message)

    # Length extension: compute H(k || m || padding || m')
    # We know the state after hashing k||m is `tag`.
    # Continue hashing from that state.
    padded = md._pad(key + message)
    extension = b'evil'

    # Build the extended message: original + padding (without key) + extension
    # The attack: we extend from the known tag state
    extended_message = message + padded[len(key + message):] + extension

    # Attack: hash starting from `tag` state (simulating continued MD chain)
    def extended_compress(cv: bytes, block: bytes) -> bytes:
        from crypto.pa07_merkle_damgard import xor_compress
        return xor_compress(cv, block)

    from crypto.pa07_merkle_damgard import MerkleDamgard
    ext_md = MerkleDamgard(
        compress_fn=extended_compress,
        block_size=8,
        output_size=4
    )
    ext_md.iv = tag  # Start from known tag state
    forged_tag = ext_md.hash(extension)

    # Verify: H(k || m || padding || extension) should equal forged_tag
    real_tag = md.hash(key + message + padded[len(key + message):] + extension)

    return {
        'original_message': message.hex(),
        'original_tag': tag.hex(),
        'extended_message': extended_message.hex(),
        'extended_tag': forged_tag.hex(),
        'attack_succeeded': forged_tag == real_tag,
    }
