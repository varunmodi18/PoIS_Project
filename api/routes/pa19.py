"""PA#19 API routes — Secure Gates."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class GateRequest(BaseModel):
    a: int
    b: int


@router.post("/and")
def secure_and_gate(req: GateRequest):
    try:
        from crypto.pa19_secure_gates import secure_and, SecureGateParams
        params = SecureGateParams(bits=64)
        result = secure_and(req.a, req.b, params)
        return {
            "result": result['result'],
            "ot_messages": list(result['ot_messages']),
            "correct": result['correct']
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/xor")
def secure_xor_gate(req: GateRequest):
    try:
        from crypto.pa19_secure_gates import secure_xor
        result = secure_xor(req.a, req.b)
        return {
            "result": result['result'],
            "shares": {"alice": result['alice_share'], "bob": result['bob_share']},
            "correct": result['correct']
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/run-all")
def run_all_and():
    try:
        from crypto.pa19_secure_gates import secure_and, SecureGateParams
        params = SecureGateParams(bits=64)
        truth_table = []
        for a in [0, 1]:
            for b in [0, 1]:
                r = secure_and(a, b, params)
                truth_table.append({
                    "a": a, "b": b, "result": r['result'],
                    "ot_messages": list(r['ot_messages']),
                    "correct": r['correct']
                })
        return {"truth_table": truth_table}
    except Exception as e:
        raise HTTPException(400, str(e))
