"""INTENTIONALLY VULNERABLE: debug on, docs exposed, CORS wildcard, no TrustedHost."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(debug=True)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/")
def index() -> dict[str, str]:
    return {"hola": "mundo"}
