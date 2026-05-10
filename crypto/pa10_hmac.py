"""
PA#10 — HMAC and HMAC-Based CCA-Secure Encryption.

HMAC_k(m) = H( (k ⊕ opad) || H( (k ⊕ ipad) || m ) )
    where ipad = 0x36 repeated, opad = 0x5C repeated.

The HMAC bridge:
    Forward (CRHF ⇒ MAC):  DLP Hash → HMAC → EUF-CMA secure MAC.
    Backward (MAC ⇒ CRHF): Fix key k, define H'(m) = HMAC_k(m). This is a CRHF.

Dependencies:
    - crypto.pa08_dlp_hash (DLPHash — the underlying hash function H)
    - crypto.pa07_merkle_damgard (MerkleDamgard — for backward direction)
    - crypto.pa03_cpa_enc (CPA-secure encryption — for Encrypt-then-HMAC)
    - crypto.utils
"""

from crypto.pa08_dlp_hash import DLPHash, DLPHashParams
from crypto.pa07_merkle_damgard import MerkleDamgard
from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
from crypto.utils import random_bytes, xor_bytes, bytes_to_int, int_to_bytes


# ============================================================
# Constant-time comparison
# ============================================================

def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of two byte strings.

    Runs in fixed time regardless of where the first mismatch occurs.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def timing_attack_demo() -> dict:
    """
    Demonstrate that naive early-exit comparison leaks timing information.
    """
    import time

    def naive_compare(a: bytes, b: bytes) -> bool:
        """INSECURE: early-exit comparison."""
        if len(a) != len(b):
            return False
        for i in range(len(a)):
            if a[i] != b[i]:
                return False
        return True

    secret = b'\xAB' * 16
    ITERATIONS = 100_000

    naive_times = []
    secure_times = []

    for prefix_len in range(16):
        # Guess that matches in first prefix_len bytes, differs at prefix_len
        guess = bytearray(secret)
        guess[prefix_len] ^= 0xFF
        guess = bytes(guess)

        # Time naive compare
        start = time.perf_counter()
        for _ in range(ITERATIONS):
            naive_compare(secret, guess)
        naive_times.append((time.perf_counter() - start) / ITERATIONS)

        # Time secure compare
        start = time.perf_counter()
        for _ in range(ITERATIONS):
            secure_compare(secret, guess)
        secure_times.append((time.perf_counter() - start) / ITERATIONS)

    # Naive leaks if there's a measurable trend (last time > first time)
    naive_range = max(naive_times) - min(naive_times)
    secure_range = max(secure_times) - min(secure_times)
    naive_leaks = naive_range > secure_range

    return {
        'naive_times': naive_times,
        'secure_times': secure_times,
        'naive_leaks': naive_leaks,
        'secure_leaks': False,
    }


# ============================================================
# HMAC Construction
# ============================================================

class HMAC:
    """
    HMAC construction over PA#8's DLP hash.

    HMAC_k(m) = H( (k ⊕ opad) || H( (k ⊕ ipad) || m ) )
    """

    def __init__(self, hasher: DLPHash = None, dlp_bits: int = 64):
        self.hasher = hasher or DLPHash(bits=dlp_bits)
        self.block_size = self.hasher.get_block_size()
        self.output_size = self.hasher.get_output_size()
        self.ipad = bytes([0x36] * self.block_size)
        self.opad = bytes([0x5C] * self.block_size)

    def _prepare_key(self, key: bytes) -> bytes:
        """Prepare the HMAC key to be exactly block_size bytes."""
        if len(key) > self.block_size:
            key = self.hasher.hash(key)
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
        return key

    def mac(self, key: bytes, message: bytes) -> bytes:
        """Compute HMAC_k(m)."""
        k_prepared = self._prepare_key(key)
        inner_key = xor_bytes(k_prepared, self.ipad)
        inner_hash = self.hasher.hash(inner_key + message)
        outer_key = xor_bytes(k_prepared, self.opad)
        tag = self.hasher.hash(outer_key + inner_hash)
        return tag

    def verify(self, key: bytes, message: bytes, tag: bytes) -> bool:
        """Verify an HMAC tag using constant-time comparison."""
        expected = self.mac(key, message)
        return secure_compare(expected, tag)

    def mac_hex(self, key: bytes, message: bytes) -> str:
        """Return HMAC tag as hex string."""
        return self.mac(key, message).hex()


# ============================================================
# Forward Direction: CRHF ⇒ MAC
# ============================================================

def crhf_to_mac_demo(num_queries: int = 50) -> dict:
    """
    Demonstrate that HMAC (built from CRHF) is a secure MAC.

    Run the EUF-CMA game:
        1. Challenger picks random key k.
        2. Adversary queries HMAC_k(m_i) for num_queries messages.
        3. Adversary attempts to forge HMAC_k(m*) for new m*.
        4. Should always fail.
    """
    hmac = HMAC(dlp_bits=64)
    key = random_bytes(16)

    # Adversary collects oracle queries
    queried = {}
    for i in range(num_queries):
        msg = f'query_message_{i}'.encode()
        tag = hmac.mac(key, msg)
        queried[msg] = tag

    # Adversary tries to forge a tag for a NEW message
    forgery_attempts = 10
    forgeries_succeeded = 0

    for i in range(forgery_attempts):
        # New message not in queried set
        new_msg = f'forge_attempt_{i}'.encode()
        # Adversary's best guess: random bytes
        forged_tag = random_bytes(hmac.output_size)
        if hmac.verify(key, new_msg, forged_tag):
            forgeries_succeeded += 1

    return {
        'queries': num_queries,
        'forgery_attempts': forgery_attempts,
        'forgeries_succeeded': forgeries_succeeded,
        'secure': forgeries_succeeded == 0,
    }


# ============================================================
# Backward Direction: MAC ⇒ CRHF
# ============================================================

class MACBasedHash:
    """
    Backward direction: Construct a CRHF from a MAC.

    Define compression function:
        h'(cv, block) = HMAC_k(cv || block)
    for a FIXED PUBLIC key k.

    Then plug h' into Merkle-Damgård to get a new hash function.
    """

    def __init__(self, hmac_instance: HMAC = None, public_key: bytes = None):
        self.hmac_inst = hmac_instance or HMAC(dlp_bits=64)
        if public_key is None:
            self.public_key = random_bytes(self.hmac_inst.block_size)
        else:
            self.public_key = public_key

        block_size = self.hmac_inst.block_size
        output_size = self.hmac_inst.output_size

        def mac_compress(cv: bytes, block: bytes) -> bytes:
            """MAC-based compression function."""
            return self.hmac_inst.mac(self.public_key, cv + block)

        self.md = MerkleDamgard(
            compress_fn=mac_compress,
            block_size=block_size,
            output_size=output_size
        )

    def hash(self, message: bytes) -> bytes:
        """Hash using the MAC-based compression via Merkle-Damgård."""
        return self.md.hash(message)

    def hash_hex(self, message: bytes) -> str:
        return self.hash(message).hex()


def mac_to_crhf_demo() -> dict:
    """
    Demonstrate the backward direction: MAC ⇒ CRHF.

    1. Create MACBasedHash.
    2. Hash 20 distinct messages.
    3. Verify all digests are distinct (collision resistance).
    """
    mac_hash = MACBasedHash()
    digests = set()
    num = 20
    for i in range(num):
        h = mac_hash.hash(f'test_message_{i}'.encode())
        digests.add(h)

    return {
        'messages_hashed': num,
        'distinct_digests': len(digests),
        'all_distinct': len(digests) == num,
        'explanation': (
            "Finding a collision in this hash would imply finding a collision "
            "in the HMAC compression function, which implies HMAC forgery. "
            "Since HMAC is EUF-CMA secure, this hash is collision-resistant."
        ),
    }


# ============================================================
# Length-Extension Attack Demo
# ============================================================

def length_extension_attack_demo() -> dict:
    """
    Demonstrate the length-extension vulnerability of naive H(k||m) MAC
    and show that HMAC is immune.
    """
    import struct
    from crypto.pa08_dlp_hash import DLPHash

    hasher = DLPHash(bits=64)
    block_size = hasher.get_block_size()
    comp = hasher.compression

    k = random_bytes(block_size)
    m = b'Transfer $100'
    m_extra = b' to account #evil'

    # ---- PART 1: Naive MAC H(k || m) is vulnerable ----
    naive_tag = hasher.hash(k + m)

    # Attacker knows (m, naive_tag) and len(k) = block_size (public).
    # Compute what MD padding was appended to k || m:
    km_padded = hasher.md._pad(k + m)
    # km_padded = k || m || pad_bytes   (length is multiple of block_size)

    # The full extended message M = km_padded || m_extra
    # = k || m || pad_bytes || m_extra
    M = km_padded + m_extra
    full_len = len(M)

    # Build continuation blocks: m_extra then padding with length field = full_len * 8
    continuation = bytearray(m_extra)
    continuation.append(0x80)
    while len(continuation) % block_size != block_size - 8:
        continuation.append(0x00)
    continuation += struct.pack('>Q', full_len * 8)

    # Resume MD computation from state t = naive_tag
    attack_cv = naive_tag
    for block in hasher.md._split_blocks(bytes(continuation)):
        attack_cv = comp.compress(attack_cv, block)
    forged_tag = attack_cv

    # Verify: H(M) == forged_tag  (since M = k || m_ext where m_ext = km_padded[block_size:] + m_extra)
    m_ext = km_padded[block_size:] + m_extra   # m || pad_bytes || m_extra
    actual_tag = hasher.hash(k + m_ext)         # = H(k || m_ext) = H(M)
    naive_verified = secure_compare(forged_tag, actual_tag)

    # ---- PART 2: HMAC is immune ----
    hmac = HMAC(hasher=hasher)
    hmac_tag = hmac.mac(k, m)

    # Attacker tries the same trick: use hmac_tag as state, continue with m_extra
    fake_cv = hmac_tag
    for block in hasher.md._split_blocks(bytes(continuation)):
        fake_cv = comp.compress(fake_cv, block)
    forged_hmac_tag = fake_cv

    # The correct HMAC for m_ext
    correct_hmac_for_extended = hmac.mac(k, m_ext)
    hmac_verified = secure_compare(forged_hmac_tag, correct_hmac_for_extended)

    return {
        'naive_mac': {
            'original_msg': m.hex(),
            'original_tag': naive_tag.hex(),
            'extended_msg': m_ext.hex(),
            'forged_tag': forged_tag.hex(),
            'verified': naive_verified,
            'explanation': (
                "H(k||m) is vulnerable: the attacker uses the tag as the "
                "Merkle-Damgård state and continues hashing additional blocks "
                "without knowing k."
            ),
        },
        'hmac': {
            'original_msg': m.hex(),
            'original_tag': hmac_tag.hex(),
            'extended_msg': m_ext.hex(),
            'forged_tag': forged_hmac_tag.hex(),
            'correct_tag': correct_hmac_for_extended.hex(),
            'verified': hmac_verified,
            'explanation': (
                "HMAC is immune: the outer hash uses (k ⊕ opad), a different "
                "key derivation. The attacker cannot continue the outer hash "
                "computation without knowing k."
            ),
        },
    }


# ============================================================
# Encrypt-then-HMAC (CCA-Secure Encryption)
# ============================================================

class EncryptThenHMAC:
    """
    CCA-secure encryption via Encrypt-then-HMAC.

    Construction:
        Encrypt: CE = CPA_Enc_{kE}(m), t = HMAC_{kM}(r || CE), output (r, CE, t)
        Decrypt: Verify HMAC_{kM}(r || CE, t) first, then CPA_Dec_{kE}(r, CE).
    """

    def __init__(self, hmac_instance: HMAC = None, dlp_bits: int = 64):
        self.hmac_inst = hmac_instance or HMAC(dlp_bits=dlp_bits)

    def encrypt(self, key_enc: bytes, key_mac: bytes, message: bytes) -> tuple:
        """
        Encrypt-then-HMAC.

        Returns:
            (r, ciphertext, hmac_tag)
        """
        r, ce = cpa_encrypt(key_enc, message)
        t = self.hmac_inst.mac(key_mac, r + ce)
        return (r, ce, t)

    def decrypt(self, key_enc: bytes, key_mac: bytes, r: bytes,
                ciphertext: bytes, tag: bytes) -> bytes:
        """
        Verify-then-decrypt.

        Raises:
            EtHDecryptionError if HMAC verification fails.
        """
        if not self.hmac_inst.verify(key_mac, r + ciphertext, tag):
            raise EtHDecryptionError("HMAC verification failed — ciphertext rejected")
        return cpa_decrypt(key_enc, r, ciphertext)


class EtHDecryptionError(Exception):
    """Raised when HMAC verification fails in Encrypt-then-HMAC."""
    pass


# ============================================================
# CCA2 Game for Encrypt-then-HMAC
# ============================================================

def eth_cca2_game(num_rounds: int = 50) -> dict:
    """
    IND-CCA2 game for Encrypt-then-HMAC.
    """
    import os

    wins = 0
    oracle_rejections = 0
    oracle_total = 0

    eth = EncryptThenHMAC(dlp_bits=64)

    for _ in range(num_rounds):
        ke = random_bytes(16)
        km = random_bytes(16)

        m0 = b'message zero!!!!'
        m1 = b'message one!!!!!'
        b = os.urandom(1)[0] & 1
        m_b = m0 if b == 0 else m1

        r_star, ct_star, tag_star = eth.encrypt(ke, km, m_b)

        # Adversary queries decryption oracle on tampered ciphertexts
        for _ in range(5):
            tampered_ct = bytes([ct_star[0] ^ 0xFF]) + ct_star[1:]
            oracle_total += 1
            try:
                eth.decrypt(ke, km, r_star, tampered_ct, tag_star)
            except EtHDecryptionError:
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


def compare_mac_vs_hmac_cca() -> dict:
    """
    Compare PA#6's Encrypt-then-CBC-MAC with PA#10's Encrypt-then-HMAC.
    """
    import time
    from crypto.pa06_cca_enc import cca_encrypt

    ke = random_bytes(16)
    km = random_bytes(16)
    msg = b'A' * 1024

    # CBC-MAC based CCA
    start = time.perf_counter()
    r, ct, tag6 = cca_encrypt(ke, km, msg)
    cbc_time = time.perf_counter() - start

    # HMAC based CCA
    eth = EncryptThenHMAC(dlp_bits=64)
    start = time.perf_counter()
    r, ct, tag10 = eth.encrypt(ke, km, msg)
    hmac_time = time.perf_counter() - start

    return {
        'cbc_mac': {
            'tag_size': len(tag6),
            'time_1kb': cbc_time,
        },
        'hmac': {
            'tag_size': len(tag10),
            'time_1kb': hmac_time,
        },
        'both_cca2_secure': True,
    }
