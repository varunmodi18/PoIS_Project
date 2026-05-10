"""
crypto/pa07_merkle_damgard.py — Merkle-Damgård Transform (PA#7).

Allowed imports: os, math, struct.
NO crypto libraries.
"""

import struct


class MerkleDamgard:
    """
    Generic Merkle-Damgård hash construction.

    Takes a compression function h: {0,1}^(n+b) -> {0,1}^n and produces
    a hash function for arbitrary-length inputs.

    Args:
        compress_fn: A callable (chaining_value: bytes, block: bytes) -> bytes
                     where len(chaining_value) = output_size and len(block) = block_size.
        block_size: Size of each message block in bytes.
        output_size: Size of the chaining value / hash output in bytes.
    """

    def __init__(self, compress_fn: callable, block_size: int, output_size: int):
        self.compress = compress_fn
        self.block_size = block_size
        self.output_size = output_size
        self.iv = b'\x00' * output_size  # IV = 0^n

    def _pad(self, message: bytes) -> bytes:
        """
        MD-strengthening padding.

        Algorithm:
            1. Start with the original message bytes.
            2. Append a single 0x80 byte.
            3. Append zero bytes until (len(padded) % block_size) == (block_size - 8).
            4. Append the original message length in BITS as a 64-bit big-endian integer.
            5. Total padded length must be a multiple of block_size.

        Returns:
            Padded message as bytes, length is a multiple of block_size.
        """
        msg_len_bits = len(message) * 8
        padded = bytearray(message)
        padded.append(0x80)

        # Pad with zeros until length % block_size == block_size - 8
        while len(padded) % self.block_size != self.block_size - 8:
            padded.append(0x00)

        # Append 64-bit big-endian length in bits
        padded += struct.pack('>Q', msg_len_bits)

        assert len(padded) % self.block_size == 0
        return bytes(padded)

    def _split_blocks(self, padded_message: bytes) -> list[bytes]:
        """Split padded message into block_size-byte blocks."""
        assert len(padded_message) % self.block_size == 0
        return [padded_message[i:i + self.block_size]
                for i in range(0, len(padded_message), self.block_size)]

    def hash(self, message: bytes) -> bytes:
        """
        Compute the Merkle-Damgård hash of the message.

        Algorithm:
            1. Pad the message using _pad().
            2. Split into blocks: M1, M2, ..., Mℓ.
            3. Set z0 = IV.
            4. For i = 1 to ℓ: z_i = self.compress(z_{i-1}, M_i).
            5. Return z_ℓ.

        Returns:
            Hash digest as bytes of length output_size.
        """
        padded = self._pad(message)
        blocks = self._split_blocks(padded)
        z = self.iv
        for block in blocks:
            z = self.compress(z, block)
        return z

    def hash_hex(self, message: bytes) -> str:
        """Return hash as hex string."""
        return self.hash(message).hex()

    def hash_with_trace(self, message: bytes) -> dict:
        """
        Same as hash() but returns intermediate values for the web demo.

        Returns:
            {
                'padded_message_hex': str,
                'blocks': [str, ...],
                'chaining_values': [str, ...],
                'digest': str
            }
        """
        padded = self._pad(message)
        blocks = self._split_blocks(padded)
        chaining_values = [self.iv.hex()]
        z = self.iv
        for block in blocks:
            z = self.compress(z, block)
            chaining_values.append(z.hex())
        return {
            'padded_message_hex': padded.hex(),
            'blocks': [b.hex() for b in blocks],
            'chaining_values': chaining_values,
            'digest': z.hex(),
        }


def xor_compress(chaining_value: bytes, block: bytes) -> bytes:
    """
    Toy XOR-based compression function for testing PA#7.

    h(cv, block) = cv XOR (fold(block) to output_size bytes)

    This is NOT collision-resistant. It exists only to test the
    Merkle-Damgård framework logic.

    Args:
        chaining_value: bytes of length output_size.
        block: bytes of length block_size.

    Returns:
        bytes of length output_size.
    """
    out_size = len(chaining_value)
    # XOR-fold the block down to out_size bytes
    folded = bytearray(out_size)
    for i, byte in enumerate(block):
        folded[i % out_size] ^= byte
    # XOR with chaining value
    result = bytes(a ^ b for a, b in zip(folded, chaining_value))
    return result


def create_toy_hash(block_size: int = 8, output_size: int = 4) -> MerkleDamgard:
    """Create a MerkleDamgard instance using the toy XOR compression function."""
    return MerkleDamgard(
        compress_fn=xor_compress,
        block_size=block_size,
        output_size=output_size
    )
