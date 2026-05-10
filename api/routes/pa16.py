"""PA#16 API routes — ElGamal PKC."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class KeygenRequest(BaseModel):
    bits: int = 64


class EncryptRequest(BaseModel):
    p: str
    g: str
    q: str
    h: str
    message: str


class DecryptRequest(BaseModel):
    x: str
    c1: str
    c2: str
    p: str


class MalleabilityRequest(BaseModel):
    bits: int = 64


@router.post("/keygen")
def keygen(req: KeygenRequest):
    try:
        from crypto.pa16_elgamal import ElGamalKeyPair
        kp = ElGamalKeyPair(bits=req.bits)
        pk = kp.public_key()
        sk = kp.private_key()
        return {
            "p": str(pk['p']), "g": str(pk['g']),
            "q": str(pk['q']), "h": str(pk['h']), "x": str(sk)
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/encrypt")
def eg_encrypt(req: EncryptRequest):
    try:
        from crypto.pa16_elgamal import elgamal_encrypt
        pk = {'p': int(req.p), 'g': int(req.g), 'q': int(req.q), 'h': int(req.h)}
        m = int(req.message)
        c1, c2 = elgamal_encrypt(pk, m)
        return {"c1": str(c1), "c2": str(c2)}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/decrypt")
def eg_decrypt(req: DecryptRequest):
    try:
        from crypto.pa16_elgamal import elgamal_decrypt
        sk = int(req.x)
        c1, c2, p = int(req.c1), int(req.c2), int(req.p)
        m = elgamal_decrypt(sk, c1, c2, p)
        return {"plaintext": str(m)}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/malleability-demo")
def malleability_demo(req: MalleabilityRequest):
    try:
        from crypto.pa16_elgamal import ElGamalKeyPair, elgamal_encrypt, elgamal_decrypt, malleability_attack_demo
        result = malleability_attack_demo(req.bits)
        return {k: str(v) if isinstance(v, int) else v for k, v in result.items()}
    except Exception as e:
        raise HTTPException(400, str(e))
