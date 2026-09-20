"""Config-driven subprocess fixture.

Expected discovery:
- One DYNAMIC subprocess finding with elevated confidence (config-driven)
"""
import subprocess


def run_tool(config: dict) -> str:
    cmd = config["command"]
    args = config.get("args", [])
    full_cmd = [cmd] + args
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    return result.stdout
