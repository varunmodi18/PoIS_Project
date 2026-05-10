"""PA#13 API routes — Miller-Rabin primality testing."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class PrimalityRequest(BaseModel):
    n: str
    rounds: int = 40


class GenPrimeRequest(BaseModel):
    bits: int = 512


@router.post("/test")
def test_primality(req: PrimalityRequest):
    try:
        from crypto.pa13_miller_rabin import miller_rabin_test
        n = int(req.n)
        result = miller_rabin_test(n, req.rounds)
        return {"is_prime": result, "rounds": req.rounds, "n_str": req.n}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/generate")
def generate_prime(req: GenPrimeRequest):
    try:
        from crypto.pa13_miller_rabin import gen_prime
        p = gen_prime(req.bits)
        return {"prime": str(p), "bits": p.bit_length()}
    except Exception as e:
        raise HTTPException(400, str(e))
