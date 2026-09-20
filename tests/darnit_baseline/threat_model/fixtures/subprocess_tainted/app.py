"""Subprocess-with-tainted-input fixture.

Expected discovery:
- One HTTP_ROUTE entry point for /run
- One subprocess CandidateFinding at the subprocess.run call site
- When Opengrep is available: a taint trace from request.query_params to
  the subprocess sink
"""

import subprocess

from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/run")
async def run_command(request: Request):
    # Tainted input flows directly into subprocess shell=True — classic RCE.
    user_cmd = request.query_params.get("cmd", "")
    result = subprocess.run(user_cmd, shell=True, capture_output=True, text=True)
    return {"stdout": result.stdout}
