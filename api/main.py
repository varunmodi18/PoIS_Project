"""
FastAPI backend for POIS project.
Serves all crypto operations to the React frontend.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="POIS Crypto API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from api.routes import (
    pa01, pa02, pa03, pa04, pa05, pa06, pa07, pa08, pa09, pa10,
    pa11, pa12, pa13, pa14, pa15, pa16, pa17, pa18, pa19, pa20, clique
)

app.include_router(pa01.router, prefix="/api/pa01", tags=["PA#1"])
app.include_router(pa02.router, prefix="/api/pa02", tags=["PA#2"])
app.include_router(pa03.router, prefix="/api/pa03", tags=["PA#3"])
app.include_router(pa04.router, prefix="/api/pa04", tags=["PA#4"])
app.include_router(pa05.router, prefix="/api/pa05", tags=["PA#5"])
app.include_router(pa06.router, prefix="/api/pa06", tags=["PA#6"])
app.include_router(pa07.router, prefix="/api/pa07", tags=["PA#7"])
app.include_router(pa08.router, prefix="/api/pa08", tags=["PA#8"])
app.include_router(pa09.router, prefix="/api/pa09", tags=["PA#9"])
app.include_router(pa10.router, prefix="/api/pa10", tags=["PA#10"])
app.include_router(pa11.router, prefix="/api/pa11", tags=["PA#11"])
app.include_router(pa12.router, prefix="/api/pa12", tags=["PA#12"])
app.include_router(pa13.router, prefix="/api/pa13", tags=["PA#13"])
app.include_router(pa14.router, prefix="/api/pa14", tags=["PA#14"])
app.include_router(pa15.router, prefix="/api/pa15", tags=["PA#15"])
app.include_router(pa16.router, prefix="/api/pa16", tags=["PA#16"])
app.include_router(pa17.router, prefix="/api/pa17", tags=["PA#17"])
app.include_router(pa18.router, prefix="/api/pa18", tags=["PA#18"])
app.include_router(pa19.router, prefix="/api/pa19", tags=["PA#19"])
app.include_router(pa20.router, prefix="/api/pa20", tags=["PA#20"])
app.include_router(clique.router, prefix="/api/clique", tags=["Clique Explorer"])


@app.get("/api/health")
def health():
    return {"status": "ok", "phase": 6, "pas_implemented": list(range(1, 21))}
