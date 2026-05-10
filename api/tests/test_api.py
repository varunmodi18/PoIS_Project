"""
API integration tests — verify all endpoints return valid responses.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import pytest
import anyio
from httpx import AsyncClient, ASGITransport
from api.main import app


@pytest.fixture(scope="module")
def client():
    """Synchronous wrapper around async httpx client for ASGI apps."""
    import httpx

    class SyncClient:
        def __init__(self):
            self._transport = ASGITransport(app=app)
            self._base = "http://test"

        def get(self, path, **kwargs):
            return anyio.from_thread.run_sync(self._aget, path, kwargs, backend="trio") if False else self._run(path, "GET", None, **kwargs)

        def post(self, path, json=None, **kwargs):
            return self._run(path, "POST", json, **kwargs)

        def _run(self, path, method, json_data, **kwargs):
            async def _do():
                async with AsyncClient(transport=self._transport, base_url=self._base) as c:
                    if method == "GET":
                        return await c.get(path, **kwargs)
                    return await c.post(path, json=json_data, **kwargs)
            return anyio.from_thread.run_sync(lambda: None) or anyio.run(_do)

    # Use anyio.run to avoid event loop issues in pytest
    class _Client:
        def _call(self, coro):
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        future = pool.submit(asyncio.run, coro)
                        return future.result()
            except RuntimeError:
                pass
            return asyncio.run(coro)

        def get(self, path, **kwargs):
            async def _do():
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    return await c.get(path, **kwargs)
            return self._call(_do())

        def post(self, path, json=None, **kwargs):
            async def _do():
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    return await c.post(path, json=json, **kwargs)
            return self._call(_do())

    yield _Client()


class TestHealthAndBasics:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestPA13API:
    def test_primality(self, client):
        r = client.post("/api/pa13/test", json={"n": "561", "rounds": 20})
        assert r.status_code == 200
        assert r.json()["is_prime"] == False

    def test_primality_true(self, client):
        r = client.post("/api/pa13/test", json={"n": "7919", "rounds": 20})
        assert r.status_code == 200
        assert r.json()["is_prime"] == True

    def test_generate(self, client):
        r = client.post("/api/pa13/generate", json={"bits": 64})
        assert r.status_code == 200
        assert int(r.json()["prime"]) > 0


class TestPA02API:
    def test_aes_nist(self, client):
        r = client.post("/api/pa02/aes/encrypt", json={
            "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
            "plaintext_hex": "3243f6a8885a308d313198a2e0370734"
        })
        assert r.status_code == 200
        assert r.json()["ciphertext_hex"] == "3925841d02dc09fbdc118597196a0b32"


class TestPA03API:
    def test_encrypt_decrypt(self, client):
        key = "00" * 16
        msg = "48656c6c6f"  # "Hello" in hex
        r = client.post("/api/pa03/encrypt", json={"key_hex": key, "message_hex": msg})
        assert r.status_code == 200
        nonce = r.json()["nonce_hex"]
        ct = r.json()["ciphertext_hex"]
        r2 = client.post("/api/pa03/decrypt", json={"key_hex": key, "nonce_hex": nonce, "ciphertext_hex": ct})
        assert r2.status_code == 200
        assert r2.json()["plaintext_hex"] == msg


class TestPA04API:
    def test_all_modes(self, client):
        key = "00" * 16
        msg = "41" * 32  # 32 bytes of 'A'
        for mode in ["CBC", "OFB", "CTR"]:
            r = client.post("/api/pa04/encrypt", json={"mode": mode, "key_hex": key, "message_hex": msg})
            assert r.status_code == 200, f"{mode} encrypt failed: {r.text}"
            iv = r.json()["iv_hex"]
            ct = r.json()["ciphertext_hex"]
            r2 = client.post("/api/pa04/decrypt", json={"mode": mode, "key_hex": key, "iv_hex": iv, "ciphertext_hex": ct})
            assert r2.status_code == 200, f"{mode} decrypt failed: {r2.text}"
            assert r2.json()["plaintext_hex"] == msg, f"{mode} roundtrip failed"


class TestPA05API:
    def test_mac_verify(self, client):
        key = "00" * 16
        msg = "48656c6c6f"
        r = client.post("/api/pa05/mac", json={"key_hex": key, "message_hex": msg, "mode": "cbc"})
        assert r.status_code == 200
        tag = r.json()["tag_hex"]
        r2 = client.post("/api/pa05/verify", json={"key_hex": key, "message_hex": msg, "tag_hex": tag, "mode": "cbc"})
        assert r2.status_code == 200
        assert r2.json()["valid"] == True


class TestPA06API:
    def test_cca_encrypt_decrypt(self, client):
        ke = "00" * 16
        km = "ff" * 16
        msg = "48656c6c6f"
        r = client.post("/api/pa06/encrypt", json={"key_enc_hex": ke, "key_mac_hex": km, "message_hex": msg})
        assert r.status_code == 200
        nonce = r.json()["nonce_hex"]
        ct = r.json()["ciphertext_hex"]
        tag = r.json()["tag_hex"]
        r2 = client.post("/api/pa06/decrypt", json={
            "key_enc_hex": ke, "key_mac_hex": km,
            "nonce_hex": nonce, "ciphertext_hex": ct, "tag_hex": tag
        })
        assert r2.status_code == 200
        assert r2.json()["plaintext_hex"] == msg


class TestPA11API:
    def test_dh_exchange(self, client):
        r = client.post("/api/pa11/exchange", json={"bits": 64})
        assert r.status_code == 200
        assert r.json()["keys_match"] == True


class TestPA12API:
    def test_determinism_demo(self, client):
        r = client.post("/api/pa12/determinism-demo", json={})
        assert r.status_code == 200
        data = r.json()
        assert data["textbook"]["identical"] == True
        assert data["pkcs15"]["identical"] == False


class TestPA16API:
    def test_keygen_encrypt_decrypt(self, client):
        r = client.post("/api/pa16/keygen", json={"bits": 64})
        assert r.status_code == 200
        d = r.json()
        m = "12345"
        r2 = client.post("/api/pa16/encrypt", json={"p": d["p"], "g": d["g"], "q": d["q"], "h": d["h"], "message": m})
        assert r2.status_code == 200
        c1, c2 = r2.json()["c1"], r2.json()["c2"]
        r3 = client.post("/api/pa16/decrypt", json={"x": d["x"], "c1": c1, "c2": c2, "p": d["p"]})
        assert r3.status_code == 200
        assert r3.json()["plaintext"] == m


class TestPA18API:
    def test_ot(self, client):
        r = client.post("/api/pa18/run", json={"m0": 42, "m1": 99, "choice": 0, "bits": 64})
        assert r.status_code == 200
        assert r.json()["received_message"] == 42
        assert r.json()["correct"] == True


class TestPA20API:
    def test_millionaires(self, client):
        r = client.post("/api/pa20/millionaires", json={"x": 7, "y": 3, "n_bits": 4})
        assert r.status_code == 200
        assert r.json()["alice_richer"] == True
        assert r.json()["correct"] == True


class TestCliqueAPI:
    def test_routing_table(self, client):
        r = client.get("/api/clique/routing-table")
        assert r.status_code == 200
        assert len(r.json()) > 0

    def test_proof_summary(self, client):
        r = client.get("/api/clique/proof-summary?source=OWF&target=PRG&foundation=DLP")
        assert r.status_code == 200
        assert r.json()["path_length"] >= 1
