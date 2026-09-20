"""Minimal FastAPI fixture used by discovery tests.

Expected discovery:
- Two HTTP_ROUTE entry points with framework="fastapi"
- GET /healthz -> healthz()
- POST /users -> create_user()
"""

from fastapi import FastAPI

app = FastAPI()


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/users")
async def create_user(name: str):
    return {"name": name}
