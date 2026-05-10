"""PA#20 API routes — MPC."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class MillionairesRequest(BaseModel):
    x: int
    y: int
    n_bits: int = 4


class EqualityRequest(BaseModel):
    x: int
    y: int
    n_bits: int = 4


class AdditionRequest(BaseModel):
    x: int
    y: int
    n_bits: int = 4


@router.post("/millionaires")
def millionaires(req: MillionairesRequest):
    try:
        from crypto.pa20_mpc import millionaires_problem
        result = millionaires_problem(req.x, req.y, req.n_bits)
        stats = result['circuit_stats']
        return {
            "alice_richer": result['alice_richer'],
            "bob_richer": result['bob_richer'],
            "equal": result['equal'],
            "gates": stats['gates'],
            "and_gates": stats['and_gates'],
            "correct": result['correct']
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/equality")
def equality(req: EqualityRequest):
    try:
        from crypto.pa20_mpc import secure_equality_test
        result = secure_equality_test(req.x, req.y, req.n_bits)
        return {"equal": result['equal'], "correct": result['correct']}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/addition")
def addition(req: AdditionRequest):
    try:
        from crypto.pa20_mpc import secure_addition
        result = secure_addition(req.x, req.y, req.n_bits)
        return {"sum": result['sum'], "expected": result['expected'], "correct": result['correct']}
    except Exception as e:
        raise HTTPException(400, str(e))
