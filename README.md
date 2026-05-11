# CS8.401: Principles of Information Security — Programming Assignments

## Student Information

| Name | Roll Number | Email |
|------|-------------|-------|
| Varun Modi | 2025202040 | varun.modi@students.iiit.ac.in |
| Anurag Kukreti | 2025202041 | anurag.kukreti@students.iiit.ac.in |
| Lalithamsh K | 2025202039 | lalithamsh.karichedu@students.iiit.ac.in |
| Giridharan P | 2025201030 | giridharan.p@students.iiit.ac.in |
| Gokul C | 2025201042 | gokul.c@students.iiit.ac.in |

- **Program:** M.Tech CSE (Information Security), IIIT Hyderabad

## Project Structure
- `crypto/` — All cryptographic primitive implementations (PA#1–PA#20)
- `crypto/tests/` — Unit tests for each PA
- `api/` — FastAPI backend serving crypto operations to the React frontend
- `api/routes/` — Individual route files for each PA endpoint
- `web/` — React web application (PA#0: Minicrypt Clique Explorer + 20 interactive demos)

## Quick Start

### Run crypto tests
```bash
pip install pytest
pytest crypto/tests/ -v
```

### Run the API server
```bash
pip install fastapi uvicorn
uvicorn api.main:app --reload
# API available at http://localhost:8000
# API docs at http://localhost:8000/docs
```

### Run the React app
```bash
cd web
npm install
npm run dev
# App available at http://localhost:5173
```

### Run API tests
```bash
pytest api/tests/ -v
```

## Implementation Notes
- **No external crypto libraries used.** Every primitive is implemented from scratch.
- **Only allowed:** Python built-in `int` (arbitrary precision), `os.urandom`, `math`.
- **Dependency chain:** Each PA uses only prior PAs as dependencies — no shortcuts.
- **Bidirectional reductions** implemented for PA#1 (OWF⇔PRG), PA#2 (PRG⇔PRF), and PA#10 (CRHF⇔MAC via HMAC).
- **Full lineage:** PA#20 (MPC) traces all the way down to PA#13 (Miller-Rabin primes).
