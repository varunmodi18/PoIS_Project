"""PA#7 API routes — Merkle-Damgård hash."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HashRequest(BaseModel):
    message_hex: str
    block_size: int = 16
    output_size: int = 4


class PadRequest(BaseModel):
    message_hex: str
    block_size: int = 16
    output_size: int = 4


@router.post("/hash")
def hash_message(req: HashRequest):
    """Hash the given message using the toy Merkle-Damgård construction."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from crypto.pa07_merkle_damgard import create_toy_hash
    h = create_toy_hash(block_size=req.block_size, output_size=req.output_size)
    message = bytes.fromhex(req.message_hex)
    digest = h.hash_hex(message)
    return {"digest": digest, "message_hex": req.message_hex}


@router.post("/hash-with-trace")
def hash_with_trace(req: HashRequest):
    """Hash with intermediate chaining values."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from crypto.pa07_merkle_damgard import create_toy_hash
    h = create_toy_hash(block_size=req.block_size, output_size=req.output_size)
    message = bytes.fromhex(req.message_hex)
    return h.hash_with_trace(message)


@router.post("/pad")
def pad_message(req: PadRequest):
    """Apply MD-strengthening padding to a message."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from crypto.pa07_merkle_damgard import create_toy_hash
    h = create_toy_hash(block_size=req.block_size, output_size=req.output_size)
    message = bytes.fromhex(req.message_hex)
    padded = h._pad(message)
    return {
        "padded_hex": padded.hex(),
        "original_bytes": len(message),
        "padded_bytes": len(padded),
        "num_blocks": len(padded) // req.block_size,
    }
