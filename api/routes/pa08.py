"""PA#8 API routes — DLP Hash."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class DLPHashRequest(BaseModel):
    message_hex: str
    bits: int = 64


class CollisionHuntRequest(BaseModel):
    output_bits: int = 12


@router.post("/hash")
def dlp_hash(req: DLPHashRequest):
    try:
        from crypto.pa08_dlp_hash import DLPHash
        h = DLPHash(bits=req.bits)
        msg = bytes.fromhex(req.message_hex)
        digest = h.hash(msg)
        params = h.get_params()
        return {
            "digest_hex": digest.hex(),
            "params": {"p": str(params['p']), "g": str(params['g']), "q": str(params['q'])}
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/hash-with-trace")
def dlp_hash_trace(req: DLPHashRequest):
    try:
        from crypto.pa08_dlp_hash import DLPHash
        from crypto.pa07_merkle_damgard import MerkleDamgard
        h = DLPHash(bits=req.bits)
        msg = bytes.fromhex(req.message_hex)
        padded = h.md._pad(msg)
        block_size = h.get_block_size()
        blocks = [padded[i:i+block_size] for i in range(0, len(padded), block_size)]
        cv = bytes(h.get_output_size())
        cvs = [cv.hex()]
        for block in blocks:
            cv = h.md.compression(cv, block)
            cvs.append(cv.hex())
        return {
            "padded_hex": padded.hex(),
            "blocks": [b.hex() for b in blocks],
            "chaining_values": cvs,
            "digest": cvs[-1]
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/collision-hunt")
def collision_hunt(req: CollisionHuntRequest):
    try:
        from crypto.pa09_birthday_attack import attack_truncated_dlp_hash
        result = attack_truncated_dlp_hash(req.output_bits, dlp_bits=64)
        return {
            "collision_found": result.get('input_1_hex') is not None,
            "input1_hex": result.get('input_1_hex') or "",
            "input2_hex": result.get('input_2_hex') or "",
            "hash_hex": result.get('shared_hash_hex') or "",
            "evaluations": result.get('evaluations', 0)
        }
    except Exception as e:
        raise HTTPException(400, str(e))
