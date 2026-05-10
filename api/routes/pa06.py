"""PA#6 API routes — CCA Encryption."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class CCAEncryptRequest(BaseModel):
    key_enc_hex: str
    key_mac_hex: str
    message_hex: str


class CCADecryptRequest(BaseModel):
    key_enc_hex: str
    key_mac_hex: str
    nonce_hex: str
    ciphertext_hex: str
    tag_hex: str


class MalleabilityRequest(BaseModel):
    message_hex: str
    flip_bit: int = 0


@router.post("/encrypt")
def encrypt(req: CCAEncryptRequest):
    try:
        from crypto.pa06_cca_enc import cca_encrypt
        ke = bytes.fromhex(req.key_enc_hex)
        km = bytes.fromhex(req.key_mac_hex)
        msg = bytes.fromhex(req.message_hex)
        nonce, ct, tag = cca_encrypt(ke, km, msg)
        return {"nonce_hex": nonce.hex(), "ciphertext_hex": ct.hex(), "tag_hex": tag.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/decrypt")
def decrypt(req: CCADecryptRequest):
    try:
        from crypto.pa06_cca_enc import cca_decrypt, CCADecryptionError
        ke = bytes.fromhex(req.key_enc_hex)
        km = bytes.fromhex(req.key_mac_hex)
        nonce = bytes.fromhex(req.nonce_hex)
        ct = bytes.fromhex(req.ciphertext_hex)
        tag = bytes.fromhex(req.tag_hex)
        pt = cca_decrypt(ke, km, nonce, ct, tag)
        return {"plaintext_hex": pt.hex()}
    except Exception as e:
        return {"error": str(e)}


@router.post("/malleability-demo")
def malleability_demo(req: MalleabilityRequest):
    try:
        from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
        from crypto.pa06_cca_enc import cca_encrypt, cca_decrypt, CCADecryptionError
        from crypto.utils import random_bytes
        ke = random_bytes(16)
        km = random_bytes(16)
        msg = bytes.fromhex(req.message_hex)

        # CPA only: flip a bit, decryption succeeds with corrupted output
        cpa_nonce, cpa_ct = cpa_encrypt(ke, msg)
        cpa_ct_flipped = bytearray(cpa_ct)
        byte_idx = req.flip_bit // 8
        if byte_idx < len(cpa_ct_flipped):
            cpa_ct_flipped[byte_idx] ^= (1 << (req.flip_bit % 8))
        try:
            cpa_pt_corrupted = cpa_decrypt(ke, cpa_nonce, bytes(cpa_ct_flipped))
            cpa_result = {"corrupted_hex": cpa_pt_corrupted.hex(), "blocked": False}
        except Exception as e2:
            cpa_result = {"corrupted_hex": "", "blocked": False, "error": str(e2)}

        # CCA: flip a bit, MAC rejects
        cca_nonce, cca_ct, cca_tag = cca_encrypt(ke, km, msg)
        cca_ct_flipped = bytearray(cca_ct)
        if byte_idx < len(cca_ct_flipped):
            cca_ct_flipped[byte_idx] ^= (1 << (req.flip_bit % 8))
        try:
            cca_decrypt(ke, km, cca_nonce, bytes(cca_ct_flipped), cca_tag)
            cca_result = {"blocked": False}
        except Exception:
            cca_result = {"blocked": True, "error": "MAC verification failed — ⊥"}

        return {"cpa_only": cpa_result, "cca": cca_result}
    except Exception as e:
        raise HTTPException(400, str(e))
