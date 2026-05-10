"""PA#12 API routes — RSA."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class KeygenRequest(BaseModel):
    bits: int = 512


class EncryptRequest(BaseModel):
    n: str
    e: int
    message_hex: str
    mode: str = "pkcs15"


class DecryptRequest(BaseModel):
    n: str
    d: str
    p: str
    q: str
    ciphertext: str
    mode: str = "pkcs15"
    byte_size: int = 64


class DeterminismRequest(BaseModel):
    pass


@router.post("/keygen")
def keygen(req: KeygenRequest):
    try:
        from crypto.pa12_rsa import RSAKeyPair
        kp = RSAKeyPair(bits=req.bits)
        sk = kp.private_key()
        return {
            "n": str(kp.n), "e": kp.e, "d": str(sk['d']),
            "p": str(sk['p']), "q": str(sk['q']), "byte_size": kp.byte_size
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/encrypt")
def rsa_encrypt(req: EncryptRequest):
    try:
        from crypto.pa12_rsa import pkcs15_encrypt, rsa_encrypt_raw
        n = int(req.n)
        msg = bytes.fromhex(req.message_hex)
        pk = {'n': n, 'e': req.e}
        if req.mode == "textbook":
            m_int = int.from_bytes(msg, 'big')
            ct_int = rsa_encrypt_raw(pk, m_int)
            return {"ciphertext": str(ct_int)}
        else:
            byte_size = (n.bit_length() + 7) // 8
            ct_int = pkcs15_encrypt(pk, msg, byte_size)
            return {"ciphertext": str(ct_int)}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/decrypt")
def rsa_decrypt(req: DecryptRequest):
    try:
        from crypto.pa12_rsa import pkcs15_decrypt, rsa_decrypt_raw
        sk = {'d': int(req.d), 'p': int(req.p), 'q': int(req.q), 'n': int(req.n),
              'dp': int(req.d) % (int(req.p) - 1), 'dq': int(req.d) % (int(req.q) - 1),
              'q_inv': pow(int(req.q), -1, int(req.p))}
        ct_int = int(req.ciphertext)
        if req.mode == "textbook":
            m_int = rsa_decrypt_raw(sk, ct_int)
            return {"plaintext_hex": m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big').hex()}
        else:
            pt = pkcs15_decrypt(sk, ct_int, req.byte_size)
            return {"plaintext_hex": pt.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/determinism-demo")
def determinism_demo(req: DeterminismRequest):
    try:
        from crypto.pa12_rsa import RSAKeyPair, rsa_encrypt_raw, pkcs15_encrypt
        kp = RSAKeyPair(bits=512)
        pk = kp.public_key()
        msg = b"hello"
        m_int = int.from_bytes(msg, 'big')
        ct1_text = rsa_encrypt_raw(pk, m_int)
        ct2_text = rsa_encrypt_raw(pk, m_int)
        ct1_pkcs = pkcs15_encrypt(pk, msg, kp.byte_size)
        ct2_pkcs = pkcs15_encrypt(pk, msg, kp.byte_size)
        return {
            "textbook": {
                "ct1": str(ct1_text), "ct2": str(ct2_text),
                "identical": ct1_text == ct2_text
            },
            "pkcs15": {
                "ct1": str(ct1_pkcs), "ct2": str(ct2_pkcs),
                "identical": ct1_pkcs == ct2_pkcs
            }
        }
    except Exception as e:
        raise HTTPException(400, str(e))
