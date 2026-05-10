"""PA#14 API routes — CRT + Håstad Attack."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class CRTRequest(BaseModel):
    residues: list[str]
    moduli: list[str]


class HastadRequest(BaseModel):
    bits: int = 256
    e: int = 3


@router.post("/crt")
def compute_crt(req: CRTRequest):
    try:
        from crypto.pa14_crt import crt
        residues = [int(r) for r in req.residues]
        moduli = [int(m) for m in req.moduli]
        solution = crt(residues, moduli)
        return {"solution": str(solution)}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/hastad")
def hastad_attack(req: HastadRequest):
    try:
        from crypto.pa14_crt import hastad_demo
        result = hastad_demo(e=req.e, bits=req.bits)
        # Serialize big ints as strings
        recipients = []
        for r in result.get('recipients', []):
            recipients.append({k: str(v) if isinstance(v, int) else v for k, v in r.items()})
        return {
            "message": str(result['message']),
            "recovered": str(result['recovered']),
            "attack_succeeded": result['attack_succeeded'],
            "recipients": recipients
        }
    except Exception as e:
        raise HTTPException(400, str(e))
