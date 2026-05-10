"""PA#10 API routes — HMAC."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class HMACRequest(BaseModel):
    key_hex: str
    message_hex: str


class HMACVerifyRequest(BaseModel):
    key_hex: str
    message_hex: str
    tag_hex: str


class LengthExtRequest(BaseModel):
    suffix_hex: str


@router.post("/hmac")
def compute_hmac(req: HMACRequest):
    try:
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        key = bytes.fromhex(req.key_hex)
        msg = bytes.fromhex(req.message_hex)
        tag = hmac.mac(key, msg)
        return {"tag_hex": tag.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/hmac-verify")
def verify_hmac(req: HMACVerifyRequest):
    try:
        from crypto.pa10_hmac import HMAC
        hmac = HMAC(dlp_bits=64)
        key = bytes.fromhex(req.key_hex)
        msg = bytes.fromhex(req.message_hex)
        tag = bytes.fromhex(req.tag_hex)
        valid = hmac.verify(key, msg, tag)
        return {"valid": valid}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/length-extension-demo")
def length_extension_demo(req: LengthExtRequest):
    try:
        from crypto.pa10_hmac import HMAC, length_extension_attack_demo
        result = length_extension_attack_demo()
        return result
    except Exception as e:
        raise HTTPException(400, str(e))
