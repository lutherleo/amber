"""A deliberately small Sonnet agent that *reads* the research graph.

Minimally agentic by design: the inconsistencies are computed **deterministically**
(`find_inconsistencies`) and handed to the model as facts; the LLM only phrases an
answer over a compact, read-only view. It never mutates the graph and never invents
verdicts. Mirrors ``darnit.core.llm_step.PydanticAILLMStep``: model id
``anthropic:claude-sonnet-5``, key sourced from ``ANTHROPIC_API_KEY`` by pydantic-ai,
lazy ``Agent`` construction. Without a key (or pydantic-ai) it degrades honestly to a
deterministic textual summary instead of failing.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any

from .graph import ResearchGraph

DEFAULT_MODEL = "anthropic:claude-sonnet-5"
_SYSTEM = (
    "You answer questions about a research reproducibility knowledge graph. "
    "Use ONLY the provided graph JSON and the pre-computed inconsistencies list. "
    "Never invent runs, claims, or verdicts. Be concise. When asked what did not "
    "reproduce, cite the metric and the measured-vs-claimed detail verbatim."
)


def find_inconsistencies(graph: ResearchGraph) -> list[str]:
    """Deterministic problems worth surfacing — the trustworthy core the agent phrases."""
    problems: list[str] = []
    for v in graph.nodes("Verdict"):
        level = v.get("level")
        if v.get("kind") == "claim" and level != "REPRODUCED":
            problems.append(f"claim `{v.get('metric')}` {level}: {v.get('summary')}")
        if v.get("kind") == "reproducibility" and level in ("NOT_REPRODUCED", "INCONCLUSIVE"):
            problems.append(f"reproducibility {level}: {v.get('summary')}")
    for r in graph.nodes("Run"):
        if r.get("exit_code") not in (0, None):
            problems.append(f"run {r.get('run_id')} exited non-zero ({r.get('exit_code')})")
        ref = r.get("code_ref") or {}
        if ref.get("file_path") and ref.get("resolved") is False:
            problems.append(f"run {r.get('run_id')} could not be linked to the code graph ({ref.get('file_path')})")
    # Runs never referenced by any verdict = unverified.
    verified: set[str] = set()
    for e in graph.edges():
        if e["type"] in ("VERIFIED_AGAINST", "CHECKS"):
            verified.add(e["end"])
    for r in graph.nodes("Run"):
        if r["uid"] not in verified:
            problems.append(f"run {r.get('run_id')} is unverified (no reproducibility or claim check)")
    return problems


class SonnetResearchAgent:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        system_prompt: str = _SYSTEM,
        responder: Callable[[str], str] | None = None,
    ) -> None:
        self.model = model
        self._system = system_prompt
        self._responder = responder  # test/offline seam: bypasses pydantic-ai
        self._agent: Any | None = None

    def _build(self) -> Any:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("SonnetResearchAgent requires ANTHROPIC_API_KEY")
        from pydantic_ai import Agent  # lazy: keeps import cost/creds out of construction

        return Agent(model=self.model, output_type=str, system_prompt=self._system)

    def _prompt(self, question: str, graph: ResearchGraph) -> str:
        view = graph.compact_view()
        problems = find_inconsistencies(graph)
        return (
            f"Question: {question}\n\n"
            f"Pre-computed inconsistencies:\n{json.dumps(problems, indent=2)}\n\n"
            f"Graph:\n{json.dumps(view, indent=2, default=str)}"
        )

    def ask(self, question: str, graph: ResearchGraph) -> str:
        prompt = self._prompt(question, graph)
        if self._responder is not None:
            return self._responder(prompt)
        try:
            if self._agent is None:
                self._agent = self._build()
            return self._agent.run_sync(prompt).output
        except Exception as exc:  # noqa: BLE001 - honest degradation, never a hard failure
            return deterministic_answer(graph, note=f"(LLM unavailable: {type(exc).__name__}; deterministic summary)")


def deterministic_answer(graph: ResearchGraph, *, note: str | None = None) -> str:
    """A no-LLM summary of the graph + inconsistencies (the offline fallback)."""
    view = graph.compact_view()
    lines: list[str] = []
    if note:
        lines.append(note)
    papers = view.get("papers") or []
    if papers:
        for p in papers:
            lines.append(f"Paper: {p.get('title') or p.get('url')} — {len(p.get('claims') or [])} claim(s)")
    lines.append(f"Projects: {', '.join(view.get('projects') or []) or '(none)'}")
    lines.append(f"Runs: {len(view.get('runs') or [])}")
    for r in view.get("runs") or []:
        outs = ", ".join(o.get("path") for o in (r.get("outputs") or []) if o.get("path")) or "no outputs"
        methods = f"; code: {len(r.get('executed_methods') or [])} methods" if r.get("executed_methods") else ""
        lines.append(f"  - {r.get('run_id')} (py {r.get('python')}, exit {r.get('exit_code')}): {outs}{methods}")
    problems = find_inconsistencies(graph)
    lines.append("")
    lines.append("Inconsistencies:" if problems else "Inconsistencies: none")
    lines.extend(f"  ! {p}" for p in problems)
    return "\n".join(lines)
