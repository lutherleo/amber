"""Fixture — subprocess calls with hardcoded list arguments.

Expected discovery (four-tier classification):
- Literal-list calls → tier "static" (severity=1, confidence=0.2)
- ``subprocess.run(cmd)`` with a variable → tier "dynamic" (severity=6, confidence=0.8)
- ``shell=True`` variant → tier "shell" (severity=8, confidence=0.9)
"""

import subprocess


def safe_literal_list() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "status", "--porcelain"], capture_output=True, text=True
    )


def safe_run_check_output() -> bytes:
    return subprocess.check_output(["ls", "-la", "/tmp"])


def unsafe_variable_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    # Variable cmd — stays as a finding (we can't rule out tainted input)
    return subprocess.run(cmd, capture_output=True)


def unsafe_shell_true() -> subprocess.CompletedProcess:
    # shell=True with a hardcoded string is still flagged — the shape is a smell
    return subprocess.run("echo hello", shell=True, capture_output=True)
