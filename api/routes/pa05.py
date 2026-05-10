"""PA#5 API routes — MACs."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from crypto.utils import random_bytes
router = APIRouter()

# Hidden key for forge-attempt demo (rotated per server start)
_forge_key = random_bytes(16)


class MACRequest(BaseModel):
    key_hex: str
    message_hex: str
    mode: str = "cbc"


class VerifyRequest(BaseModel):
    key_hex: str
    message_hex: str
    tag_hex: str
    mode: str = "cbc"


class ForgeRequest(BaseModel):
    message_hex: str
    tag_hex: str


@router.post("/mac")
def compute_mac(req: MACRequest):
    try:
        key = bytes.fromhex(req.key_hex)
        msg = bytes.fromhex(req.message_hex)
        mode = req.mode.lower()
        if mode == "prf":
            from crypto.pa05_mac import prf_mac
            tag = prf_mac(key, msg)
        else:
            from crypto.pa05_mac import cbc_mac
            tag = cbc_mac(key, msg)
        return {"tag_hex": tag.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/verify")
def verify_mac(req: VerifyRequest):
    try:
        key = bytes.fromhex(req.key_hex)
        msg = bytes.fromhex(req.message_hex)
        tag = bytes.fromhex(req.tag_hex)
        mode = req.mode.lower()
        if mode == "prf":
            from crypto.pa05_mac import prf_mac_verify
            valid = prf_mac_verify(key, msg, tag)
        else:
            from crypto.pa05_mac import cbc_mac_verify
            valid = cbc_mac_verify(key, msg, tag)
        return {"valid": valid}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/forge-attempt")
def forge_attempt(req: ForgeRequest):
    try:
        from crypto.pa05_mac import cbc_mac_verify
        msg = bytes.fromhex(req.message_hex)
        tag = bytes.fromhex(req.tag_hex)
        valid = cbc_mac_verify(_forge_key, msg, tag)
        return {"forgery_accepted": valid}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.get("/forge-signed-messages")
def get_signed_messages():
    """Return 10 signed (message, tag) pairs using the hidden key."""
    try:
        from crypto.pa05_mac import cbc_mac
        pairs = []
        for i in range(10):
            msg = f"message_{i:02d}".encode()
            tag = cbc_mac(_forge_key, msg)
            pairs.append({"message_hex": msg.hex(), "tag_hex": tag.hex()})
        return {"pairs": pairs}
    except Exception as e:
        raise HTTPException(400, str(e))
