"""PA#3 API routes — CPA Encryption."""
import uuid
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()

# In-memory store for CPA game challenges
_challenges: dict = {}


class EncryptRequest(BaseModel):
    key_hex: str
    message_hex: str


class DecryptRequest(BaseModel):
    key_hex: str
    nonce_hex: str
    ciphertext_hex: str


class CPAGameRequest(BaseModel):
    m0_hex: str
    m1_hex: str


class CPAGuessRequest(BaseModel):
    challenge_id: str
    guess: int


@router.post("/encrypt")
def encrypt(req: EncryptRequest):
    try:
        from crypto.pa03_cpa_enc import cpa_encrypt
        key = bytes.fromhex(req.key_hex)
        msg = bytes.fromhex(req.message_hex)
        nonce, ct = cpa_encrypt(key, msg)
        return {"nonce_hex": nonce.hex(), "ciphertext_hex": ct.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/decrypt")
def decrypt(req: DecryptRequest):
    try:
        from crypto.pa03_cpa_enc import cpa_decrypt
        key = bytes.fromhex(req.key_hex)
        nonce = bytes.fromhex(req.nonce_hex)
        ct = bytes.fromhex(req.ciphertext_hex)
        pt = cpa_decrypt(key, nonce, ct)
        return {"plaintext_hex": pt.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/cpa-game")
def cpa_game(req: CPAGameRequest):
    try:
        from crypto.pa03_cpa_enc import cpa_encrypt
        from crypto.utils import random_int, random_bytes
        b = random_int(0, 1)
        m = bytes.fromhex(req.m0_hex if b == 0 else req.m1_hex)
        key = random_bytes(16)
        nonce, ct = cpa_encrypt(key, m)
        challenge_id = str(uuid.uuid4())
        _challenges[challenge_id] = {'b': b, 'key': key}
        return {"ciphertext_hex": ct.hex(), "nonce_hex": nonce.hex(), "challenge_id": challenge_id}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/cpa-game/guess")
def cpa_game_guess(req: CPAGuessRequest):
    ch = _challenges.pop(req.challenge_id, None)
    if ch is None:
        raise HTTPException(404, "Challenge not found or already answered")
    return {"correct": req.guess == ch['b'], "actual_b": ch['b']}
