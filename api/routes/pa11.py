"""PA#11 API routes — Diffie-Hellman."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class DHRequest(BaseModel):
    bits: int = 64


@router.post("/exchange")
def dh_exchange(req: DHRequest):
    try:
        from crypto.pa11_diffie_hellman import DHParams, dh_full_exchange
        params = DHParams(bits=req.bits)
        result = dh_full_exchange(params)
        return {
            "a": str(result['a']),
            "A": str(result['A']),
            "b": str(result['b']),
            "B": str(result['B']),
            "K": str(result['K_alice']),
            "keys_match": result['keys_match'],
            "p": str(params.p),
            "g": str(params.g)
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/mitm")
def dh_mitm(req: DHRequest):
    try:
        from crypto.pa11_diffie_hellman import DHParams, mitm_attack_demo
        params = DHParams(bits=req.bits)
        result = mitm_attack_demo(params)
        return {k: str(v) if isinstance(v, int) else v for k, v in result.items()}
    except Exception as e:
        raise HTTPException(400, str(e))
