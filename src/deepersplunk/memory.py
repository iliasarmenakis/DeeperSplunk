"""
Verdict memory.

Stores every verdict the agent issues (plus any human overrides) in a
local SQLite database. Supports similarity lookup so the agent can check
"have we decided on alerts like this before?" as part of its Step 5.

Similarity here is deliberately simple and transparent: we match on
rule_name first, then overlap of implicated entities. A fancier vector
approach can be layered on later without changing the public API.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .schemas import NotableEvent, PriorVerdict, Verdict

log = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    event_id         TEXT PRIMARY KEY,
    rule_name        TEXT NOT NULL,
    rule_id          TEXT,
    verdict          TEXT NOT NULL,
    confidence       REAL NOT NULL,
    attack_hypothesis TEXT NOT NULL,
    entities_json    TEXT NOT NULL,
    reasoning_summary TEXT,
    decided_at       TEXT NOT NULL,
    decided_by       TEXT NOT NULL DEFAULT 'agent',
    full_payload     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verdicts_rule_name  ON verdicts(rule_name);
CREATE INDEX IF NOT EXISTS idx_verdicts_decided_at ON verdicts(decided_at);
"""


class VerdictMemory:
    """SQLite-backed store of prior verdicts."""

    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        log.info("Verdict memory initialised at %s", self._db_path)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ----- writes -----

    def record(self, verdict: Verdict, rule_name: str, rule_id: str | None = None) -> None:
        entities_flat: dict[str, list[str]] = {}
        for sr in verdict.searches_run:
            pass  # searches don't directly carry entities; we use evidence refs

        # Pull entity information from the verdict's related_entities fields
        all_entities: set[str] = set()
        for ev in verdict.evidence:
            all_entities.update(ev.related_entities)

        entities_flat = {"all": sorted(all_entities)}

        payload = verdict.model_dump_json()
        reasoning_short = verdict.reasoning_trace[:500]

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO verdicts (
                    event_id, rule_name, rule_id, verdict, confidence,
                    attack_hypothesis, entities_json, reasoning_summary,
                    decided_at, decided_by, full_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    verdict.event_id,
                    rule_name,
                    rule_id,
                    verdict.verdict,
                    verdict.confidence,
                    verdict.attack_hypothesis,
                    json.dumps(entities_flat),
                    reasoning_short,
                    verdict.created_at.isoformat(),
                    "agent",
                    payload,
                ),
            )

    def record_analyst_override(
        self,
        event_id: str,
        new_verdict: str,
        analyst_note: str,
    ) -> bool:
        """Mark a prior agent verdict as overridden by a human analyst."""
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT full_payload FROM verdicts WHERE event_id = ?", (event_id,)
            )
            row = cur.fetchone()
            if row is None:
                return False
            payload = json.loads(row["full_payload"])
            payload["verdict"] = new_verdict
            payload["reasoning_trace"] = (
                f"[ANALYST OVERRIDE at {datetime.now(timezone.utc).isoformat()}]\n"
                f"{analyst_note}\n\n--- original agent reasoning ---\n"
                f"{payload.get('reasoning_trace', '')}"
            )
            conn.execute(
                """
                UPDATE verdicts
                SET verdict = ?,
                    reasoning_summary = ?,
                    decided_by = 'analyst',
                    full_payload = ?
                WHERE event_id = ?
                """,
                (
                    new_verdict,
                    analyst_note[:500],
                    json.dumps(payload),
                    event_id,
                ),
            )
            return True

    # ----- reads -----

    def find_similar(
        self,
        event: NotableEvent,
        limit: int = 5,
    ) -> list[PriorVerdict]:
        """
        Return prior verdicts for the same detection rule, ranked by entity
        overlap with the current event.
        """
        event_entities = {
            val.lower()
            for values in event.entities.values()
            for val in values
        }

        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT event_id, rule_name, rule_id, verdict, confidence,
                       attack_hypothesis, entities_json, reasoning_summary,
                       decided_at, decided_by
                FROM verdicts
                WHERE rule_name = ?
                ORDER BY decided_at DESC
                LIMIT 50
                """,
                (event.rule_name,),
            )
            rows = cur.fetchall()

        scored: list[tuple[float, PriorVerdict]] = []
        for row in rows:
            try:
                ent_map = json.loads(row["entities_json"])
            except json.JSONDecodeError:
                ent_map = {}
            prior_entities = {
                v.lower() for values in ent_map.values() for v in values
            }
            overlap = len(event_entities & prior_entities)
            recency_rank = 1.0  # all already sorted desc by time
            score = overlap + recency_rank * 0.1

            prior = PriorVerdict(
                event_id=row["event_id"],
                rule_name=row["rule_name"],
                verdict=row["verdict"],
                confidence=row["confidence"],
                attack_hypothesis=row["attack_hypothesis"],
                entities_snapshot=ent_map,
                decided_at=datetime.fromisoformat(row["decided_at"]),
                decided_by=row["decided_by"],
                reasoning_summary=row["reasoning_summary"],
            )
            scored.append((score, prior))

        scored.sort(key=lambda t: t[0], reverse=True)
        return [p for _, p in scored[:limit]]

    def stats(self) -> dict[str, int]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT verdict, COUNT(*) as n
                FROM verdicts
                GROUP BY verdict
                """
            )
            return {row["verdict"]: row["n"] for row in cur.fetchall()}
