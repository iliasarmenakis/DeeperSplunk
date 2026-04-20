"""
Pydantic schemas for the steelman SOC agent.

These define the shape of notable events, search results, evidence items,
and the final verdict that the agent writes back.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["informational", "low", "medium", "high", "critical"]
EntityType = Literal[
    "user",
    "host",
    "src_ip",
    "dest_ip",
    "process",
    "file_hash",
    "domain",
    "url",
    "email",
]
VerdictLabel = Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_HUMAN_REVIEW"]
EvidenceDirection = Literal["hypothesis", "benign", "inconclusive"]
EvidenceWeight = Literal["strong", "moderate", "weak"]


class NotableEvent(BaseModel):
    """A notable event pulled from Splunk Enterprise Security (or equivalent)."""

    event_id: str = Field(..., description="Unique ID of the notable event")
    timestamp: datetime = Field(..., description="When the event fired (UTC)")
    rule_name: str = Field(..., description="Detection rule / search that generated it")
    rule_id: str | None = Field(None, description="Stable identifier of the rule")
    severity: Severity
    description: str = Field(..., description="Human-readable summary from the rule")
    entities: dict[EntityType, list[str]] = Field(
        default_factory=dict,
        description="Implicated entities grouped by type",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs the rule is tagged with",
    )
    raw_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Full raw field set from the underlying event",
    )
    source_index: str | None = None


class SplunkSearchResult(BaseModel):
    """The result of one SPL search the agent ran."""

    search_id: str = Field(..., description="Stable ID for referencing this search from evidence items")
    spl: str = Field(..., description="The exact SPL that was executed")
    earliest_time: str = Field(..., description="Earliest time bound (e.g. '-90d@d')")
    latest_time: str = Field(..., description="Latest time bound (e.g. 'now')")
    result_count: int = Field(..., ge=0)
    scan_count: int | None = Field(None, ge=0, description="Events scanned before filtering")
    duration_seconds: float | None = Field(None, ge=0.0)
    results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Up to N result rows; may be truncated",
    )
    truncated: bool = False
    error: str | None = Field(None, description="If the search failed, the error message")


class EntityContext(BaseModel):
    """Enrichment data for a single entity."""

    entity_type: EntityType
    value: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    baseline_activity: dict[str, Any] | None = Field(
        None,
        description="Summary of this entity's normal pattern over the lookback window",
    )
    notes: list[str] = Field(default_factory=list)


class PriorVerdict(BaseModel):
    """A previous verdict retrieved from collective memory."""

    event_id: str
    rule_name: str
    verdict: VerdictLabel
    confidence: float
    attack_hypothesis: str
    entities_snapshot: dict[str, list[str]] = Field(default_factory=dict)
    decided_at: datetime
    decided_by: str = Field(
        default="agent",
        description="'agent' if auto-decided, 'analyst' if human-overridden",
    )
    reasoning_summary: str | None = None


class EvidenceItem(BaseModel):
    """One factual finding, tied to a specific search."""

    search_id: str = Field(
        ...,
        description="Must match the search_id of a SplunkSearchResult the agent ran",
    )
    finding: str = Field(..., description="One sentence describing what was observed")
    direction: EvidenceDirection = Field(
        ...,
        description="Does this evidence support the attack hypothesis, the benign story, or neither?",
    )
    weight: EvidenceWeight
    related_entities: list[str] = Field(default_factory=list)


class Verdict(BaseModel):
    """The final verdict written back to Splunk and stored in memory."""

    event_id: str
    verdict: VerdictLabel
    confidence: float = Field(..., ge=0.0, le=1.0)
    attack_hypothesis: str = Field(
        ...,
        description="One paragraph describing the hypothesis the agent tried to prove",
    )
    mitre_techniques: list[str] = Field(default_factory=list)
    searches_run: list[SplunkSearchResult] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    reasoning_trace: str = Field(
        ...,
        description="Narrative explaining how the agent reached the verdict",
    )
    tool_failures: list[str] = Field(
        default_factory=list,
        description="Any tool errors encountered during investigation",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_version: str = "DeeperSplunk/0.1.0"

    def summary_line(self) -> str:
        return (
            f"[{self.verdict}] ({self.confidence:.2f}) "
            f"{self.event_id} :: {self.attack_hypothesis[:80]}"
        )
