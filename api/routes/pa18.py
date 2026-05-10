"""PA#18 API routes — Oblivious Transfer."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class OTRequest(BaseModel):
    m0: int
    m1: int
    choice: int
    bits: int = 64


@router.post("/run")
def run_ot(req: OTRequest):
    try:
        from crypto.pa18_oblivious_transfer import ot_protocol
        from crypto.pa11_diffie_hellman import DHParams
        params = DHParams(bits=req.bits)
        result = ot_protocol(params, req.m0, req.m1, req.choice)
        log = [
            f"Receiver: choice bit b={req.choice}",
            "Receiver: generated real keypair (sk_b, pk_b)",
            "Receiver: generated fake public key pk_{1-b} (random group element)",
            f"Sender: encrypted m0={req.m0} under pk0",
            f"Sender: encrypted m1={req.m1} under pk1",
            f"Receiver: decrypted C_{req.choice} → m_{req.choice}={result['chosen_message']}",
            f"Receiver: cannot decrypt C_{1 - req.choice} (no secret key for pk_{{1-b}})"
        ]
        return {
            "received_message": result['chosen_message'],
            "correct": result['correct'],
            "protocol_log": log
        }
    except Exception as e:
        raise HTTPException(400, str(e))
