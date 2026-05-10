"""
Tests for PA#7 — Merkle-Damgård Transform.
"""
import struct
import pytest
from crypto.pa07_merkle_damgard import MerkleDamgard, xor_compress, create_toy_hash

BLOCK_SIZE = 8
OUTPUT_SIZE = 4


@pytest.fixture
def toy_hash():
    return create_toy_hash(block_size=BLOCK_SIZE, output_size=OUTPUT_SIZE)


def test_padding_empty(toy_hash):
    """Pad an empty message. Verify padding starts with 0x80 and ends with 0 length field."""
    # Use block_size=16 so empty message (0 bytes) fits in 1 block
    # (0x80 + 7 zero-pad bytes + 8-byte length field = 16 bytes)
    h = create_toy_hash(block_size=16, output_size=4)
    padded = h._pad(b'')
    assert len(padded) == 16, f"Empty message should pad to 1 block (16 bytes), got {len(padded)}"
    assert padded[0] == 0x80, "First byte of padding should be 0x80"
    # Last 8 bytes encode length in bits = 0
    length_field = struct.unpack('>Q', padded[-8:])[0]
    assert length_field == 0, "Length field should be 0 for empty message"


def test_padding_one_block(toy_hash):
    """Pad a message shorter than block_size - 9. Verify total length is 1 block."""
    # block_size - 9 = 8 - 9 = -1, so any message < (block_size - 8 - 1) bytes
    # For block_size=8, one block means message must fit in block_size - 9 bytes
    # 8 - 9 = -1 so even 0 bytes barely fits, which is empty message test above.
    # With block_size=16 it's more interesting; here we test short message
    h = create_toy_hash(block_size=16, output_size=4)
    msg = b'hello'  # 5 bytes < 16 - 9 = 7 bytes
    padded = h._pad(msg)
    assert len(padded) == 16, f"Short message should pad to 1 block (16 bytes), got {len(padded)}"


def test_padding_exact_boundary(toy_hash):
    """Pad a message that's exactly (block_size - 9) bytes. Verify total length is 1 block."""
    h = create_toy_hash(block_size=16, output_size=4)
    msg = b'A' * (16 - 9)  # 7 bytes
    padded = h._pad(msg)
    assert len(padded) == 16, f"Expected 1 block (16 bytes), got {len(padded)}"


def test_padding_overflow(toy_hash):
    """Pad a message that's (block_size - 8) bytes. Verify total length is 2 blocks."""
    h = create_toy_hash(block_size=16, output_size=4)
    msg = b'A' * (16 - 8)  # 8 bytes — 0x80 + length won't fit in remaining 7 bytes
    padded = h._pad(msg)
    assert len(padded) == 32, f"Expected 2 blocks (32 bytes), got {len(padded)}"


def test_padding_multi_block(toy_hash):
    """Pad a message spanning 3+ blocks. Verify correct length."""
    h = create_toy_hash(block_size=16, output_size=4)
    msg = b'A' * 50  # 50 bytes -> needs ceil((50+1+8)/16) * 16 bytes
    padded = h._pad(msg)
    assert len(padded) % 16 == 0, "Padded length must be a multiple of block_size"
    assert len(padded) >= 50 + 1 + 8, "Padded message must accommodate msg + 0x80 + length"


def test_padding_length_field(toy_hash):
    """Verify the last 8 bytes encode the original message length in bits."""
    h = create_toy_hash(block_size=16, output_size=4)
    for msg_len in [0, 5, 16, 100]:
        msg = b'X' * msg_len
        padded = h._pad(msg)
        length_field = struct.unpack('>Q', padded[-8:])[0]
        assert length_field == msg_len * 8, (
            f"Length field {length_field} != {msg_len * 8} bits for {msg_len}-byte message"
        )


def test_hash_deterministic(toy_hash):
    """Same message produces same hash."""
    msg = b'hello world'
    h1 = toy_hash.hash(msg)
    h2 = toy_hash.hash(msg)
    assert h1 == h2, "Hash is not deterministic"


def test_hash_different_messages(toy_hash):
    """Different messages produce different hashes (high probability for toy hash)."""
    h1 = toy_hash.hash(b'message one')
    h2 = toy_hash.hash(b'message two')
    assert h1 != h2, "Different messages produced same hash"


def test_hash_empty_message(toy_hash):
    """Hash of empty message is well-defined, not a crash."""
    result = toy_hash.hash(b'')
    assert isinstance(result, bytes), "Hash should return bytes"
    assert len(result) == OUTPUT_SIZE, f"Hash length should be {OUTPUT_SIZE}"


def test_hash_with_trace(toy_hash):
    """Verify trace dict has correct structure and chaining value count."""
    msg = b'test message for tracing'
    trace = toy_hash.hash_with_trace(msg)

    assert 'padded_message_hex' in trace
    assert 'blocks' in trace
    assert 'chaining_values' in trace
    assert 'digest' in trace

    num_blocks = len(trace['blocks'])
    # chaining_values should be z0, z1, ..., z_l (l+1 values = num_blocks + 1)
    assert len(trace['chaining_values']) == num_blocks + 1, (
        f"Expected {num_blocks + 1} chaining values, got {len(trace['chaining_values'])}"
    )
    # digest should match last chaining value
    assert trace['digest'] == trace['chaining_values'][-1]


def test_collision_propagation(toy_hash):
    """
    Find two inputs that collide under xor_compress. Verify they also collide
    under the full MD hash. Demonstrates: collision in h implies collision in H.
    """
    # XOR compress trivially: two single-block messages that XOR-fold to same value
    # For block_size=8, output_size=4:
    # xor_compress(IV, block) = fold(block) XOR IV
    # Two blocks that fold to the same value will collide
    # block b1 = [a, b, c, d, a, b, c, d] -> fold = [0, 0, 0, 0] -> XOR IV = IV
    # block b2 = [a, b, c, d, a, b, c, d] (same) -> same result
    # More interesting: find b1 != b2 that fold to same value
    # b1 = bytes([1, 2, 3, 4, 1, 2, 3, 4]) -> fold[i] = b1[i] ^ b1[i+4]
    # fold[0] = 1^1 = 0, fold[1] = 2^2 = 0, etc. -> fold = 0000
    # b2 = bytes([5, 6, 7, 8, 5, 6, 7, 8]) -> fold = 0000
    b1 = bytes([1, 2, 3, 4, 1, 2, 3, 4])
    b2 = bytes([5, 6, 7, 8, 5, 6, 7, 8])

    # Verify they collide under compress
    iv = b'\x00' * OUTPUT_SIZE
    c1 = xor_compress(iv, b1)
    c2 = xor_compress(iv, b2)
    assert c1 == c2, "Test setup: these blocks should collide under xor_compress"

    # Now verify collision propagates through the full hash
    h1 = toy_hash.hash(b1)
    h2 = toy_hash.hash(b2)
    assert h1 == h2, "Collision in compression function should propagate to full MD hash"
