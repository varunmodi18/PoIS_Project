"""PA#9 API routes — Birthday Attack."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import math
router = APIRouter()


class AttackRequest(BaseModel):
    output_bits: int = 12
    algorithm: str = "naive"


@router.post("/attack")
def run_attack(req: AttackRequest):
    try:
        from crypto.pa09_birthday_attack import attack_truncated_dlp_hash
        result = attack_truncated_dlp_hash(req.output_bits, dlp_bits=64)
        found = result.get('input_1_hex') is not None
        expected = math.sqrt(math.pi / 2) * (2 ** (req.output_bits / 2))
        evals = result.get('evaluations', 0)
        return {
            "collision_found": found,
            "input1_hex": result.get('input_1_hex') or "",
            "input2_hex": result.get('input_2_hex') or "",
            "evaluations": evals,
            "expected": expected,
            "ratio": evals / expected if expected > 0 else 0
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.get("/context")
def birthday_context():
    return {
        "md5": {"bits": 128, "birthday_bound": str(2**64), "broken_year": 2004},
        "sha1": {"bits": 160, "birthday_bound": str(2**80), "broken_year": 2017},
        "sha256": {"bits": 256, "birthday_bound": str(2**128), "broken_year": None}
    }
