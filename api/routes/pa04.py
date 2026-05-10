"""PA#4 API routes — Modes of Operation."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class ModeEncryptRequest(BaseModel):
    mode: str
    key_hex: str
    message_hex: str


class ModeDecryptRequest(BaseModel):
    mode: str
    key_hex: str
    iv_hex: str
    ciphertext_hex: str


class BitFlipRequest(BaseModel):
    mode: str
    key_hex: str
    message_hex: str
    flip_block: int = 0
    flip_bit: int = 0


@router.post("/encrypt")
def encrypt(req: ModeEncryptRequest):
    try:
        from crypto.pa04_modes import cbc_encrypt, ofb_encrypt, ctr_encrypt
        key = bytes.fromhex(req.key_hex)
        msg = bytes.fromhex(req.message_hex)
        mode = req.mode.upper()
        if mode == 'CBC':
            iv, ct = cbc_encrypt(key, msg)
        elif mode == 'OFB':
            iv, ct = ofb_encrypt(key, msg)
        elif mode == 'CTR':
            iv, ct = ctr_encrypt(key, msg)
        else:
            raise ValueError(f"Unknown mode: {mode}")
        return {"iv_hex": iv.hex(), "ciphertext_hex": ct.hex(), "mode": mode}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/decrypt")
def decrypt(req: ModeDecryptRequest):
    try:
        from crypto.pa04_modes import cbc_decrypt, ofb_decrypt, ctr_decrypt
        key = bytes.fromhex(req.key_hex)
        iv = bytes.fromhex(req.iv_hex)
        ct = bytes.fromhex(req.ciphertext_hex)
        mode = req.mode.upper()
        if mode == 'CBC':
            pt = cbc_decrypt(key, iv, ct)
        elif mode == 'OFB':
            pt = ofb_decrypt(key, iv, ct)
        elif mode == 'CTR':
            pt = ctr_decrypt(key, iv, ct)
        else:
            raise ValueError(f"Unknown mode: {mode}")
        return {"plaintext_hex": pt.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/bit-flip")
def bit_flip(req: BitFlipRequest):
    try:
        from crypto.pa04_modes import cbc_encrypt, cbc_decrypt, ofb_encrypt, ofb_decrypt, ctr_encrypt, ctr_decrypt
        key = bytes.fromhex(req.key_hex)
        msg = bytes.fromhex(req.message_hex)
        mode = req.mode.upper()

        if mode == 'CBC':
            iv, ct = cbc_encrypt(key, msg)
        elif mode == 'OFB':
            iv, ct = ofb_encrypt(key, msg)
        elif mode == 'CTR':
            iv, ct = ctr_encrypt(key, msg)
        else:
            raise ValueError(f"Unknown mode: {mode}")

        # Flip specified bit in specified block
        block_size = 16
        ct_list = bytearray(ct)
        byte_offset = req.flip_block * block_size + req.flip_bit // 8
        bit_offset = req.flip_bit % 8
        if byte_offset < len(ct_list):
            ct_list[byte_offset] ^= (1 << bit_offset)
        ct_flipped = bytes(ct_list)

        if mode == 'CBC':
            pt_corrupted = cbc_decrypt(key, iv, ct_flipped)
        elif mode == 'OFB':
            pt_corrupted = ofb_decrypt(key, iv, ct_flipped)
        elif mode == 'CTR':
            pt_corrupted = ctr_decrypt(key, iv, ct_flipped)

        # Find which blocks differ
        corrupted_blocks = []
        for i in range(0, len(msg), block_size):
            orig_block = msg[i:i+block_size]
            corr_block = pt_corrupted[i:i+block_size] if i < len(pt_corrupted) else b''
            if orig_block != corr_block:
                corrupted_blocks.append(i // block_size)

        return {
            "original_hex": msg.hex(),
            "corrupted_hex": pt_corrupted.hex(),
            "corrupted_blocks": corrupted_blocks
        }
    except Exception as e:
        raise HTTPException(400, str(e))
