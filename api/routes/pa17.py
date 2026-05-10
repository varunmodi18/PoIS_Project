"""PA#17 API routes — CCA-Secure PKC."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()


class CCAEncryptRequest(BaseModel):
    message: str
    elgamal_bits: int = 64
    rsa_bits: int = 512


class TamperDemoRequest(BaseModel):
    elgamal_bits: int = 64
    rsa_bits: int = 512


@router.post("/encrypt")
def cca_encrypt(req: CCAEncryptRequest):
    try:
        from crypto.pa17_cca_pkc import CCASecurePKC
        scheme = CCASecurePKC(elgamal_bits=req.elgamal_bits, rsa_bits=req.rsa_bits)
        m = int(req.message)
        c1, c2, sigma = scheme.encrypt(m)
        return {
            "c1": str(c1), "c2": str(c2), "sigma": str(sigma),
            "elgamal_p": str(scheme.elgamal.params.p),
            "elgamal_g": str(scheme.elgamal.params.g),
            "elgamal_q": str(scheme.elgamal.params.q),
            "elgamal_h": str(scheme.elgamal.kp.public_key()['h']),
            "elgamal_x": str(scheme.elgamal.kp.private_key()),
            "rsa_n": str(scheme.signer.rsa.n),
            "rsa_e": scheme.signer.rsa.e,
            "rsa_d": str(scheme.signer.rsa.private_key()['d'])
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/tamper-demo")
def tamper_demo(req: TamperDemoRequest):
    try:
        from crypto.pa17_cca_pkc import CCASecurePKC, CCADecryptionError
        from crypto.pa16_elgamal import elgamal_decrypt, elgamal_encrypt, ElGamalKeyPair
        from crypto.utils import random_int

        scheme = CCASecurePKC(elgamal_bits=req.elgamal_bits, rsa_bits=req.rsa_bits)
        p = scheme.elgamal.params.p
        m = random_int(2, p - 2)

        c1, c2, sigma = scheme.encrypt(m)

        # Try tampering: multiply c2 by 2
        c2_tampered = (c2 * 2) % p

        # CCA: should reject
        try:
            scheme.decrypt(c1, c2_tampered, sigma)
            cca_result = {"blocked": False}
        except CCADecryptionError:
            cca_result = {"blocked": True, "error": "Signature verification failed — ⊥"}
        except Exception as ex:
            cca_result = {"blocked": True, "error": str(ex)}

        # Plain ElGamal: allows tamper
        eg_kp = scheme.elgamal
        eg_pk = eg_kp.public_key()
        eg_sk = eg_kp.private_key()
        eg_c1, eg_c2 = elgamal_encrypt(eg_pk, m)
        eg_c2_tampered = (eg_c2 * 2) % p
        eg_decrypted = elgamal_decrypt(eg_sk, eg_c1, eg_c2_tampered, p)
        eg_result = {"decrypted": str(eg_decrypted), "expected_2m": str((2 * m) % p), "malleable": eg_decrypted == (2 * m) % p}

        return {
            "original_m": str(m),
            "cca_pkc": cca_result,
            "plain_elgamal": eg_result
        }
    except Exception as e:
        raise HTTPException(400, str(e))
