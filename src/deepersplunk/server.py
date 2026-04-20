"""
MCP server for the steelman SOC agent.

Exposes tools and prompts via the Model Context Protocol so that Claude
(Desktop, Code, or any MCP client) can drive the steelman triage workflow
against Splunk Enterprise Security.

Run it locally with STDIO transport (default for Claude Desktop):
    python -m deepersplunk

Or over Streamable HTTP for remote deployment:
    python -m deepersplunk --transport streamable-http --port 8000
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import Settings, load_settings
from .memory import VerdictMemory
from .prompts import (
    ATTACK_HYPOTHESIS_FRAMEWORK,
    RECORD_VERDICT_REMINDER,
    STEELMAN_SYSTEM_PROMPT,
)
from .schemas import (
    EvidenceItem,
    NotableEvent,
    PriorVerdict,
    SplunkSearchResult,
    Verdict,
    VerdictLabel,
)
from .splunk_client import MockSplunkClient, RealSplunkClient, SplunkClient


log = logging.getLogger(__name__)

# Module-level state so FastMCP decorators can reach it.
_settings: Settings | None = None
_splunk: SplunkClient | None = None
_memory: VerdictMemory | None = None
_search_history: dict[str, SplunkSearchResult] = {}

mcp = FastMCP(
    "DeeperSplunk",
    instructions=(
        "Adversarial SOC triage agent for Splunk. Use the `steelman_triage` "
        "prompt as your system prompt for every investigation. The tools "
        "below implement the Steelman Method: fetch the alert, run searches "
        "that would CONFIRM an attack hypothesis, check collective memory, "
        "and record a verdict with full evidence chain."
    ),
)


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def _init_runtime() -> None:
    global _settings, _splunk, _memory
    if _settings is not None:
        return
    _settings = load_settings()
    logging.basicConfig(
        level=_settings.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )
    log.info(
        "DeeperSplunk starting (mock_mode=%s, splunk_host=%s)",
        _settings.mock_mode,
        _settings.splunk_host,
    )
    if _settings.mock_mode:
        _splunk = MockSplunkClient(_settings)
    else:
        _splunk = RealSplunkClient(_settings)
    _memory = VerdictMemory(_settings.memory_db_path)


def _require_splunk() -> SplunkClient:
    _init_runtime()
    assert _splunk is not None
    return _splunk


def _require_memory() -> VerdictMemory:
    _init_runtime()
    assert _memory is not None
    return _memory


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


@mcp.prompt()
def steelman_triage() -> str:
    """
    The master prompt for a steelman triage investigation. Use this as the
    system prompt before handing the agent a notable event ID.
    """
    return STEELMAN_SYSTEM_PROMPT


@mcp.prompt()
def attack_hypothesis_framework() -> str:
    """
    A structured template the agent uses in Step 2 to formulate a specific,
    testable attack hypothesis from a notable event.
    """
    return ATTACK_HYPOTHESIS_FRAMEWORK


@mcp.prompt()
def pre_verdict_checklist() -> str:
    """
    A short checklist the agent should run through before calling
    record_verdict. Intended to catch premature conclusions.
    """
    return RECORD_VERDICT_REMINDER


# ---------------------------------------------------------------------------
# Tools - investigation
# ---------------------------------------------------------------------------


@mcp.tool()
def fetch_notable_event(event_id: str) -> dict[str, Any]:
    """
    Fetch a Splunk Enterprise Security notable event by ID.

    Returns the full event payload including the rule that fired, severity,
    implicated entities (user, host, src_ip, etc.), MITRE techniques the rule
    is tagged with, and the raw field set.

    This is STEP 1 of the Steelman Method. Do not skip it.
    """
    splunk = _require_splunk()
    try:
        event = splunk.fetch_notable_event(event_id)
    except ValueError as exc:
        return {"error": str(exc), "event_id": event_id}
    return event.model_dump(mode="json")


@mcp.tool()
def splunk_search(
    spl: str,
    earliest_time: str = "-24h",
    latest_time: str = "now",
) -> dict[str, Any]:
    """
    Execute an SPL search against Splunk.

    Use this to hunt for evidence that either CONFIRMS or CONTRADICTS your
    attack hypothesis. Every search you run will be recorded with a
    `search_id`; cite that ID when you build evidence items in your verdict.

    Args:
        spl: The SPL query. May or may not start with 'search'.
        earliest_time: Splunk time modifier, e.g. '-24h', '-90d@d', 'rt-5m'.
        latest_time:   Splunk time modifier, e.g. 'now', '-0h'.

    Tips:
        - For baseline/history questions use a 90-day window: earliest_time='-90d@d'
        - For process ancestry use: index=endpoint host=<HOST> | fields parent_process, process, command_line
        - For lateral movement: index=network | stats count by src_ip, dest_ip, dest_port
        - For outbound unknowns: index=proxy | where NOT (dest_domain IN (<allowlist>))
    """
    splunk = _require_splunk()
    settings = _settings
    assert settings is not None

    result = splunk.search(
        spl=spl,
        earliest_time=earliest_time,
        latest_time=latest_time,
        result_limit=settings.search_result_limit,
    )
    _search_history[result.search_id] = result
    return result.model_dump(mode="json")


@mcp.tool()
def list_searches_run() -> list[dict[str, Any]]:
    """
    List every search you have run so far during this investigation, with
    their search_ids. Use this to pick which searches to cite in evidence
    items when building a verdict.
    """
    return [
        {
            "search_id": sid,
            "spl": r.spl,
            "earliest_time": r.earliest_time,
            "latest_time": r.latest_time,
            "result_count": r.result_count,
            "error": r.error,
        }
        for sid, r in _search_history.items()
    ]


# ---------------------------------------------------------------------------
# Tools - memory
# ---------------------------------------------------------------------------


@mcp.tool()
def find_similar_prior_verdicts(
    event_id: str,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """
    Look up prior verdicts the team (or this agent) issued on similar alerts.

    Returns up to `limit` past verdicts for the same detection rule, ranked
    by entity overlap with the current event. Use this as STEP 5 of the
    Steelman Method - but do not let prior FPs lull you into complacency;
    attackers target patterns known to be ignored.
    """
    splunk = _require_splunk()
    memory = _require_memory()
    try:
        event = splunk.fetch_notable_event(event_id)
    except ValueError as exc:
        return [{"error": str(exc), "event_id": event_id}]
    priors = memory.find_similar(event, limit=limit)
    return [p.model_dump(mode="json") for p in priors]


@mcp.tool()
def memory_stats() -> dict[str, int]:
    """
    Return a breakdown of verdicts stored in memory by label
    (TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_HUMAN_REVIEW).
    Useful for a "show me how the agent has been performing" check.
    """
    return _require_memory().stats()


# ---------------------------------------------------------------------------
# Tools - verdict
# ---------------------------------------------------------------------------


@mcp.tool()
def record_verdict(
    event_id: str,
    verdict: str,
    confidence: float,
    attack_hypothesis: str,
    reasoning_trace: str,
    evidence: list[dict[str, Any]],
    mitre_techniques: list[str] | None = None,
    tool_failures: list[str] | None = None,
) -> dict[str, Any]:
    """
    Issue the final verdict for this notable event.

    This is STEP 6 of the Steelman Method. The call will:
      1. Validate the payload (verdict label, confidence bounds, evidence refs)
      2. Persist the verdict to local SQLite memory
      3. Write the verdict as a comment on the notable event in Splunk
         (best-effort; failures are logged but do not fail the tool call)

    Args:
        event_id: The notable event ID being adjudicated.
        verdict:  Exactly one of: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_HUMAN_REVIEW
        confidence: Float 0.0-1.0. If < 0.75, verdict is coerced to NEEDS_HUMAN_REVIEW.
        attack_hypothesis: One paragraph describing the hypothesis you tried to prove.
        reasoning_trace:   Narrative explaining how you reached the verdict.
        evidence:          List of evidence item dicts, each with:
                             - search_id:  ID of a search in list_searches_run()
                             - finding:    one-sentence description of what was found
                             - direction:  'hypothesis' | 'benign' | 'inconclusive'
                             - weight:     'strong' | 'moderate' | 'weak'
                             - related_entities: list of entity values
        mitre_techniques:  MITRE ATT&CK IDs relevant to the hypothesis.
        tool_failures:     Any tool errors encountered during investigation.
    """
    splunk = _require_splunk()
    memory = _require_memory()

    valid_labels: tuple[VerdictLabel, ...] = (
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "NEEDS_HUMAN_REVIEW",
    )
    if verdict not in valid_labels:
        return {
            "error": f"verdict must be one of {valid_labels}, got {verdict!r}",
        }

    if not 0.0 <= confidence <= 1.0:
        return {"error": f"confidence must be in [0.0, 1.0], got {confidence}"}

    # Coerce low-confidence decisions to NEEDS_HUMAN_REVIEW
    coerced = False
    if verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE") and confidence < 0.75:
        log.info(
            "Coercing %s with confidence %.2f -> NEEDS_HUMAN_REVIEW",
            verdict, confidence,
        )
        verdict = "NEEDS_HUMAN_REVIEW"
        coerced = True

    # Validate evidence items and cross-reference search_ids
    ev_objs: list[EvidenceItem] = []
    unknown_search_ids: list[str] = []
    for raw in evidence:
        try:
            item = EvidenceItem(**raw)
        except Exception as exc:
            return {"error": f"invalid evidence item {raw!r}: {exc}"}
        if item.search_id not in _search_history:
            unknown_search_ids.append(item.search_id)
        ev_objs.append(item)

    if unknown_search_ids:
        return {
            "error": (
                "Evidence references unknown search_ids. Every evidence item "
                "must cite a search_id returned by splunk_search earlier in "
                "this session. Unknown: " + ", ".join(unknown_search_ids)
            ),
            "known_search_ids": list(_search_history.keys()),
        }

    # Build Verdict object
    v = Verdict(
        event_id=event_id,
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        attack_hypothesis=attack_hypothesis,
        mitre_techniques=mitre_techniques or [],
        searches_run=list(_search_history.values()),
        evidence=ev_objs,
        reasoning_trace=reasoning_trace,
        tool_failures=tool_failures or [],
    )

    # Fetch the event for rule_name context (needed for memory indexing)
    try:
        event = splunk.fetch_notable_event(event_id)
        rule_name = event.rule_name
        rule_id = event.rule_id
    except ValueError:
        rule_name = "unknown"
        rule_id = None

    memory.record(v, rule_name=rule_name, rule_id=rule_id)

    # Write back to Splunk as a notable comment
    comment_text = _format_verdict_comment(v)
    writeback_ok = splunk.write_verdict_comment(event_id, comment_text)

    return {
        "ok": True,
        "verdict": v.verdict,
        "confidence": v.confidence,
        "coerced_from_low_confidence": coerced,
        "memory_write": "ok",
        "splunk_comment_write": "ok" if writeback_ok else "failed (non-fatal)",
        "summary": v.summary_line(),
    }


def _format_verdict_comment(v: Verdict) -> str:
    lines = [
        f"[DeeperSplunk] verdict={v.verdict} confidence={v.confidence:.2f}",
        "",
        f"Hypothesis: {v.attack_hypothesis}",
        "",
        f"MITRE: {', '.join(v.mitre_techniques) if v.mitre_techniques else 'n/a'}",
        "",
        f"Searches run: {len(v.searches_run)}",
        f"Evidence items: {len(v.evidence)}",
        "",
        "Reasoning:",
        v.reasoning_trace,
    ]
    if v.tool_failures:
        lines.extend(["", "Tool failures:", *(f"  - {f}" for f in v.tool_failures)])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool - analyst override (not intended to be called by the LLM; provided for
# integration with a human UI or webhook).
# ---------------------------------------------------------------------------


@mcp.tool()
def record_analyst_override(
    event_id: str,
    new_verdict: str,
    analyst_note: str,
) -> dict[str, Any]:
    """
    Record a human analyst overriding a prior agent verdict. The new verdict
    and note are stored alongside the original for future similarity lookups,
    so the agent learns from corrections.

    This tool is primarily intended for integrations (webhooks, ChatOps);
    the agent itself should not call it during triage.
    """
    valid = ("TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_HUMAN_REVIEW")
    if new_verdict not in valid:
        return {"error": f"new_verdict must be one of {valid}"}
    ok = _require_memory().record_analyst_override(event_id, new_verdict, analyst_note)
    return {"ok": ok}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="DeeperSplunk MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "sse"],
        default="stdio",
        help="MCP transport to use (default: stdio, for Claude Desktop)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for streamable-http / sse transports",
    )
    args = parser.parse_args(argv)

    _init_runtime()

    if args.transport == "stdio":
        mcp.run()
    else:
        # FastMCP accepts transport kwarg for HTTP modes; settings.port is
        # configured via the FastMCP instance before run().
        mcp.settings.port = args.port  # type: ignore[attr-defined]
        mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
