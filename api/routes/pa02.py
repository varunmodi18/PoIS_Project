"""PA#2 API routes — PRF (GGM + AES)."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class GGMRequest(BaseModel):
    key: int
    query: int
    input_bits: int = 4


class AESRequest(BaseModel):
    key_hex: str
    plaintext_hex: str


@router.post("/ggm/evaluate")
def ggm_evaluate(req: GGMRequest):
    """PA#2 demo: Evaluate GGM PRF with trace."""
    try:
        from crypto.pa01_owf_prg import DLP_OWF, PRG
        from crypto.pa02_prf import GGM_PRF
        owf = DLP_OWF(bits=32)
        prg = PRG(owf)
        ggm = GGM_PRF(prg)
        trace = ggm.evaluate_with_trace(key=req.key, x=req.query, input_bits=req.input_bits)
        return {"output": trace['output'], "trace": trace}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/aes/encrypt")
def aes_encrypt(req: AESRequest):
    """AES-128 single block encryption."""
    try:
        from crypto.pa02_prf import AES_PRF
        aes = AES_PRF()
        ct = aes.encrypt_block(bytes.fromhex(req.key_hex), bytes.fromhex(req.plaintext_hex))
        return {"ciphertext_hex": ct.hex(), "key_hex": req.key_hex, "plaintext_hex": req.plaintext_hex}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/aes/decrypt")
def aes_decrypt(req: AESRequest):
    """AES-128 single block decryption."""
    try:
        from crypto.pa02_prf import AES_PRF
        aes = AES_PRF()
        pt = aes.decrypt_block(bytes.fromhex(req.key_hex), bytes.fromhex(req.plaintext_hex))
        return {"plaintext_hex": pt.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))
