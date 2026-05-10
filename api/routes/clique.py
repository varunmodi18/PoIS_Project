"""Clique Explorer reduction engine API routes."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
router = APIRouter()

ROUTING_TABLE = [
    {"from": "OWF", "to": "PRG", "name": "HILL hard-core-bit construction", "theorem": "HILL Theorem", "pa": 1},
    {"from": "PRG", "to": "PRF", "name": "GGM tree", "theorem": "GGM Theorem", "pa": 2},
    {"from": "PRF", "to": "PRP", "name": "Luby-Rackoff 3-round Feistel", "theorem": "Luby-Rackoff Theorem", "pa": 4},
    {"from": "PRF", "to": "MAC", "name": "PRF-MAC", "theorem": "PRF ⇒ EUF-CMA MAC", "pa": 5},
    {"from": "PRP", "to": "MAC", "name": "PRP/PRF switching + MAC", "theorem": "Switching Lemma + PRF-MAC", "pa": 5},
    {"from": "CRHF", "to": "HMAC", "name": "HMAC construction", "theorem": "HMAC security (Bellare 2006)", "pa": 10},
    {"from": "HMAC", "to": "MAC", "name": "HMAC is EUF-CMA", "theorem": "HMAC ⇒ EUF-CMA", "pa": 10},
    {"from": "PRG", "to": "OWF", "name": "PRG is a OWF", "theorem": "Immediate (expansion ⇒ non-invertible)", "pa": 1},
    {"from": "PRF", "to": "PRG", "name": "G(s) = F_s(0)||F_s(1)", "theorem": "PRF ⇒ PRG", "pa": 2},
    {"from": "PRP", "to": "PRF", "name": "PRP/PRF switching lemma", "theorem": "Switching Lemma", "pa": 4},
    {"from": "MAC", "to": "PRF", "name": "MAC on random inputs is PRF", "theorem": "EUF-CMA ⇒ PRF on uniform", "pa": 5},
    {"from": "HMAC", "to": "CRHF", "name": "Fixed-key HMAC is CRHF", "theorem": "MAC ⇒ CRHF", "pa": 10},
    {"from": "MAC", "to": "HMAC", "name": "PRF-MAC in HMAC structure", "theorem": "MAC ⇒ HMAC", "pa": 10},
]


class BuildRequest(BaseModel):
    foundation: str = "DLP"
    source_primitive: str
    seed_hex: str = ""


class ReduceRequest(BaseModel):
    source_primitive: str
    target_primitive: str
    source_data_hex: str = ""
    query_hex: str = ""


def _find_path(src: str, dst: str) -> list:
    """BFS shortest path in routing table."""
    from collections import deque
    if src == dst:
        return []
    queue = deque([(src, [])])
    visited = {src}
    while queue:
        node, path = queue.popleft()
        for edge in ROUTING_TABLE:
            if edge['from'] == node and edge['to'] not in visited:
                new_path = path + [edge]
                if edge['to'] == dst:
                    return new_path
                visited.add(edge['to'])
                queue.append((edge['to'], new_path))
    return []


@router.post("/build")
def build(req: BuildRequest):
    try:
        seed = bytes.fromhex(req.seed_hex) if req.seed_hex else b'\x00' * 8
        seed_int = int.from_bytes(seed[:8], 'big')
        steps = []

        if req.foundation == "DLP":
            from crypto.pa01_owf_prg import DLP_OWF
            owf = DLP_OWF(bits=64)
            result = owf.evaluate(seed_int)
            steps.append({"function": "DLP OWF", "input_hex": seed_int.to_bytes(8, 'big').hex(), "output_hex": result.to_bytes((result.bit_length() + 7) // 8 or 1, 'big').hex()})
            result_hex = steps[-1]['output_hex']
        else:  # AES
            from crypto.pa02_prf import AES_PRF
            aes = AES_PRF()
            key = (seed[:16] + b'\x00' * 16)[:16]
            ct = aes.encrypt_block(key, bytes(16))
            steps.append({"function": "AES-128 (PRP)", "input_hex": seed.hex(), "output_hex": ct.hex()})
            result_hex = ct.hex()

        return {"steps": steps, "result_hex": result_hex}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/reduce")
def reduce(req: ReduceRequest):
    try:
        path = _find_path(req.source_primitive, req.target_primitive)
        if not path:
            return {"steps": [], "result_hex": req.source_data_hex,
                    "message": f"No reduction path from {req.source_primitive} to {req.target_primitive}"}

        steps = []
        current_hex = req.source_data_hex or "00" * 8
        for edge in path:
            steps.append({
                "function": edge['name'],
                "theorem": edge['theorem'],
                "pa": edge['pa'],
                "input_hex": current_hex,
                "output_hex": current_hex  # Symbolic — actual reduction depends on PA
            })

        return {"steps": steps, "result_hex": current_hex}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.get("/routing-table")
def routing_table():
    return ROUTING_TABLE


@router.get("/proof-summary")
def proof_summary(source: str = "", target: str = "", foundation: str = "DLP"):
    try:
        path = _find_path(source, target) if source and target else []
        theorems = [{"theorem": e['theorem'], "pa": e['pa'], "name": e['name']} for e in path]
        return {
            "source": source,
            "target": target,
            "foundation": foundation,
            "path_length": len(path),
            "theorems": theorems,
            "security_claim": f"If {foundation} is secure, then any {source} is a secure {target} via the reduction chain above."
        }
    except Exception as e:
        raise HTTPException(400, str(e))
