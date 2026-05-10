"""PA#15 API routes — Digital Signatures."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


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
        scheme = RSASignatureScheme(rsa_bits=req.rsa_bits)
        msg = bytes.fromhex(req.message_hex)
        sigma = scheme.sign(msg)
        pk = scheme.rsa.public_key()
        return {
            "signature": str(sigma),
            "public_key": {"n": str(pk['n']), "e": pk['e']}
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/verify")
def verify(req: VerifyRequest):
    try:
        from crypto.pa15_signatures import RSASignatureScheme
        # Create scheme, inject public key
        scheme = RSASignatureScheme(rsa_bits=512)
        # Override rsa key's n and e for verification
        scheme.rsa.n = int(req.n)
        scheme.rsa.e = req.e
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
