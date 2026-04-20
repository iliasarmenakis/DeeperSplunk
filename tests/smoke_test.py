"""
Smoke test: exercise the full agent workflow in mock mode, without MCP
transport. Verifies that imports work, the mock Splunk client returns
plausible data, and verdicts are persisted.
"""

import os
import sys
import tempfile
from pathlib import Path

# Force mock mode before any imports
os.environ["DEEPERSPLUNK_MOCK_MODE"] = "true"
with tempfile.TemporaryDirectory() as tmpdir:
    os.environ["DEEPERSPLUNK_MEMORY_DB"] = str(Path(tmpdir) / "memory.sqlite3")

    # Make the package importable from src layout
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

    from deepersplunk.config import load_settings
    from deepersplunk.memory import VerdictMemory
    from deepersplunk.schemas import EvidenceItem, Verdict
    from deepersplunk.splunk_client import MockSplunkClient

    def main() -> int:
        settings = load_settings()
        assert settings.mock_mode, "mock mode should be auto-enabled"
        print(f"[ok] mock_mode={settings.mock_mode}")

        splunk = MockSplunkClient(settings)

        # Fetch both fixture events
        ev1 = splunk.fetch_notable_event("NOT-2026-04-20-0001")
        ev2 = splunk.fetch_notable_event("NOT-2026-04-20-0002")
        assert ev1.rule_name == "Impossible Travel Detected"
        assert ev2.rule_name == "Encoded PowerShell Command Detected"
        print(f"[ok] fetched fixture events: {ev1.rule_name!r}, {ev2.rule_name!r}")

        # Run a few searches that the steelman workflow would run
        r1 = splunk.search(
            'search index=okta user="alice.nguyen@acme.example"',
            earliest_time="-24h",
        )
        assert r1.result_count == 2, f"expected 2 okta login rows, got {r1.result_count}"
        print(f"[ok] okta search returned {r1.result_count} rows, search_id={r1.search_id}")

        r2 = splunk.search(
            'search user="alice.nguyen@acme.example" | baseline_geo',
            earliest_time="-90d@d",
        )
        assert r2.result_count == 1
        assert "Nigeria" in r2.results[0]["never_seen"]
        print(f"[ok] baseline search surfaced novel geo=Nigeria")

        r3 = splunk.search(
            'search 102.89.41.10 threat reputation',
        )
        assert r3.results[0]["known_malicious"] is False
        print(f"[ok] threat-intel search: IP not in known-bad lists")

        # Run searches for the PowerShell fixture
        r4 = splunk.search(
            'search host=WIN-FIN-07 user=svc_backup powershell',
        )
        assert r4.result_count == 1
        assert "185.220.101.50" in r4.results[0]["decoded_hint"]
        print(f"[ok] powershell search surfaced C2 destination in decoded command")

        r5 = splunk.search(
            'search 185.220.101.50 threat reputation',
        )
        assert r5.results[0]["known_malicious"] is True
        assert "c2" in r5.results[0]["categories"]
        print(f"[ok] threat-intel search: IP confirmed known-bad C2/tor")

        # Build a verdict and persist
        memory = VerdictMemory(settings.memory_db_path)

        verdict = Verdict(
            event_id="NOT-2026-04-20-0002",
            verdict="TRUE_POSITIVE",
            confidence=0.92,
            attack_hypothesis=(
                "svc_backup is executing an encoded PowerShell payload that "
                "downloads from a known-bad tor-exit/C2 IP (T1059.001 + T1071.001). "
                "The service account has never previously run PowerShell, and "
                "egress to the destination was never seen before today."
            ),
            mitre_techniques=["T1059.001", "T1027", "T1071.001"],
            searches_run=[r4, r5],
            evidence=[
                EvidenceItem(
                    search_id=r4.search_id,
                    finding="svc_backup ran powershell.exe with encoded command decoding to IEX download from 185.220.101.50",
                    direction="hypothesis",
                    weight="strong",
                    related_entities=["WIN-FIN-07", "svc_backup"],
                ),
                EvidenceItem(
                    search_id=r5.search_id,
                    finding="185.220.101.50 is classified as known_malicious (c2, tor-exit) since 2024-11-02",
                    direction="hypothesis",
                    weight="strong",
                    related_entities=["185.220.101.50"],
                ),
            ],
            reasoning_trace=(
                "Hypothesis: attacker achieved execution on WIN-FIN-07 via the "
                "backup service account and is staging C2. Searched for the "
                "process activity (confirmed: encoded PowerShell decoding to "
                "IEX download) and destination reputation (confirmed: "
                "known-bad). Baseline of svc_backup shows PowerShell has never "
                "been observed before. No benign explanation survives: a "
                "legitimate backup job would not use encoded PowerShell to "
                "fetch from a tor-exit node."
            ),
        )
        memory.record(verdict, rule_name=ev2.rule_name, rule_id=ev2.rule_id)
        print(f"[ok] verdict recorded: {verdict.summary_line()}")

        # Retrieve via similarity lookup
        priors = memory.find_similar(ev2, limit=5)
        assert len(priors) == 1
        assert priors[0].verdict == "TRUE_POSITIVE"
        print(f"[ok] similarity lookup returned {len(priors)} prior verdict(s)")

        stats = memory.stats()
        assert stats.get("TRUE_POSITIVE") == 1
        print(f"[ok] memory stats: {stats}")

        print("\n[SMOKE TEST PASSED]")
        return 0

    sys.exit(main())
