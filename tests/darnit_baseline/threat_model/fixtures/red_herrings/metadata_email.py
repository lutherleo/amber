"""Red herring — config-metadata parser that assigns to `email`.

This mirrors the `email=data.get("email", "")` case from the old pipeline.
It is NOT PII handling — it is parsing project metadata out of a YAML or
dict, then returning a simple dataclass. The new pipeline MUST produce no
PII findings for this file; the old pipeline flagged it incorrectly.
"""

from dataclasses import dataclass


@dataclass
class MaintainerEntry:
    handle: str
    email: str
    role: str


def parse_maintainer(data: dict) -> MaintainerEntry:
    return MaintainerEntry(
        handle=data.get("handle", ""),
        email=data.get("email", ""),
        role=data.get("role", ""),
    )
