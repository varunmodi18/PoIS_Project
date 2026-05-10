"""
PA#8 — DLP-Based Collision-Resistant Hash Function.

Construction:
    1. Group setup: Prime-order subgroup of Z*_p with safe prime p = 2q+1.
    2. Compression function: h(x, y) = g^x · ĥ^y mod p
    3. Full hash: Merkle-Damgård(h, IV, block_size) for arbitrary-length messages.

Security: CRHF under the DLP assumption.

Dependencies:
    - crypto.pa13_miller_rabin (gen_safe_prime)
    - crypto.pa07_merkle_damgard (MerkleDamgard)
    - crypto.utils
"""

from crypto.pa13_miller_rabin import gen_safe_prime, is_prime
from crypto.pa07_merkle_damgard import MerkleDamgard
from crypto.utils import random_int, bytes_to_int, int_to_bytes, mod_inverse


class DLPHashParams:
    """
    DLP group parameters for the hash function.

    Holds (p, q, g, h_hat) where:
        - p = 2q + 1 is a safe prime
        - q is prime (order of the subgroup)
        - g is a generator of the order-q subgroup of Z*_p
        - h_hat = g^α mod p for a RANDOMLY CHOSEN α that is THEN DISCARDED
          (nobody knows α — this is what makes the hash collision-resistant)
    """

    def __init__(self, bits: int = 64):
        """
        Generate DLP hash parameters.

        Args:
            bits: Bit length of the safe prime p.
        """
        self.p, self.q = gen_safe_prime(bits)
        self.g = self._find_generator()
        alpha = random_int(1, self.q - 1)
        self.h_hat = pow(self.g, alpha, self.p)
        # α is now a local variable that goes out of scope — discarded.

    def _find_generator(self) -> int:
        """Find a generator of the order-q subgroup of Z*_p."""
        while True:
            h_candidate = random_int(2, self.p - 2)
            g = pow(h_candidate, 2, self.p)
            if g != 1:
                assert pow(g, self.q, self.p) == 1
                return g

    def get_output_byte_length(self) -> int:
        """Return byte length of a group element (for Merkle-Damgård output_size)."""
        return (self.p.bit_length() + 7) // 8


class DLPCompression:
    """
    DLP-based compression function: h(x, y) = g^x · ĥ^y mod p.

    Maps two Z_q elements to one group element — a 2:1 compression.
    """

    def __init__(self, params: DLPHashParams):
        self.params = params
        self.p = params.p
        self.q = params.q
        self.g = params.g
        self.h_hat = params.h_hat
        self.output_size = params.get_output_byte_length()
        self.block_size = (self.q.bit_length() + 7) // 8

    def compress_ints(self, x: int, y: int) -> int:
        """
        Core compression: h(x, y) = g^x · ĥ^y mod p.
        """
        return (pow(self.g, x, self.p) * pow(self.h_hat, y, self.p)) % self.p

    def compress(self, cv_bytes: bytes, block_bytes: bytes) -> bytes:
        """
        Byte-level interface for Merkle-Damgård.
        """
        x = bytes_to_int(cv_bytes) % self.q
        y = bytes_to_int(block_bytes) % self.q
        result = self.compress_ints(x, y)
        return int_to_bytes(result, self.output_size)


class DLPHash:
    """
    Full DLP-based Collision-Resistant Hash Function.

    Combines DLPCompression with Merkle-Damgård (PA#7) to hash
    arbitrary-length messages.
    """

    def __init__(self, bits: int = 64, params: DLPHashParams = None):
        self.params = params or DLPHashParams(bits=bits)
        self.compression = DLPCompression(self.params)
        self.md = MerkleDamgard(
            compress_fn=self.compression.compress,
            block_size=self.compression.block_size,
            output_size=self.compression.output_size
        )

    def hash(self, message: bytes) -> bytes:
        """Hash an arbitrary-length message. Returns bytes."""
        return self.md.hash(message)

    def hash_hex(self, message: bytes) -> str:
        """Hash and return hex string."""
        return self.hash(message).hex()

    def hash_with_trace(self, message: bytes) -> dict:
        """Hash with intermediate values (for web demo)."""
        return self.md.hash_with_trace(message)

    def hash_truncated(self, message: bytes, output_bits: int) -> bytes:
        """
        Hash and truncate output to `output_bits` bits.
        Used by PA#9 for birthday attack on small output spaces.
        """
        full_hash = self.hash(message)
        output_bytes = (output_bits + 7) // 8
        truncated = bytearray(full_hash[:output_bytes])
        if output_bits % 8 != 0:
            mask = (0xFF << (8 - (output_bits % 8))) & 0xFF
            truncated[-1] &= mask
        return bytes(truncated)

    def get_block_size(self) -> int:
        """Return block size in bytes (for HMAC in PA#10)."""
        return self.compression.block_size

    def get_output_size(self) -> int:
        """Return output size in bytes (for HMAC in PA#10)."""
        return self.compression.output_size

    def get_params(self) -> DLPHashParams:
        """Return underlying group parameters."""
        return self.params


def collision_resistance_demo(bits: int = 32) -> dict:
    """
    Demonstrate collision resistance of the DLP hash.

    Try 10000 random pairs (x, y) ≠ (x', y') and check if
    h(x,y) == h(x',y'). Should find 0 collisions for bits ≥ 32.
    """
    params = DLPHashParams(bits=bits)
    comp = DLPCompression(params)
    seen = {}
    collisions = 0
    trials = 10000

    for _ in range(trials):
        x = random_int(0, params.q - 1)
        y = random_int(0, params.q - 1)
        h = comp.compress_ints(x, y)
        key = (x, y)
        if h in seen and seen[h] != key:
            collisions += 1
        else:
            seen[h] = key

    return {
        'trials': trials,
        'collisions_found': collisions,
        'explanation': (
            "If a collision (x,y) != (x',y') with h(x,y)=h(x',y') were found, "
            "it would yield alpha=(x-x')/(y'-y) mod q, solving DLP. "
            f"Found {collisions} collisions in {trials} trials."
        )
    }


def integration_test_different_messages(bits: int = 64, num_messages: int = 20) -> dict:
    """
    Hash `num_messages` different messages, verify all digests are distinct.
    """
    hasher = DLPHash(bits=bits)
    digests = set()
    for i in range(num_messages):
        h = hasher.hash(f'message_{i}'.encode())
        digests.add(h)

    return {
        'messages_hashed': num_messages,
        'distinct_digests': len(digests),
        'all_distinct': len(digests) == num_messages
    }
