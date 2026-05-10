"""PA#15 API routes — Digital Signatures."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from crypto.pa08_dlp_hash import DLPHash

router = APIRouter()

# Shared hasher so sign and verify use the same DLP params within a session
_shared_hasher = DLPHash(bits=64)


class SignRequest(BaseModel):
    message_hex: str
    rsa_bits: int = 512


class VerifyRequest(BaseModel):
    message_hex: str
    signature: str
    n: str
    e: int


@router.post("/sign")
def sign(req: SignRequest):
    try:
        from crypto.pa15_signatures import RSASignatureScheme
        scheme = RSASignatureScheme(rsa_bits=req.rsa_bits, hasher=_shared_hasher)
        msg = bytes.fromhex(req.message_hex)
        sigma = scheme.sign(msg)
        pk = scheme.kp.public_key()
        return {
            "signature": str(sigma),
            "public_key": {"n": str(pk[0]), "e": pk[1]}
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/verify")
def verify(req: VerifyRequest):
    try:
        from crypto.pa15_signatures import RSASignatureScheme
        scheme = RSASignatureScheme(rsa_bits=512, hasher=_shared_hasher)
        scheme.kp.n = int(req.n)
        scheme.kp.e = req.e
        msg = bytes.fromhex(req.message_hex)
        sigma = int(req.signature)
        valid = scheme.verify(msg, sigma)
        return {"valid": valid}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/forgery-demo")
def forgery_demo():
    try:
        from crypto.pa15_signatures import multiplicative_forgery_demo
        result = multiplicative_forgery_demo()
        return {k: str(v) if isinstance(v, int) else v for k, v in result.items()}
    except Exception as e:
        raise HTTPException(400, str(e))
