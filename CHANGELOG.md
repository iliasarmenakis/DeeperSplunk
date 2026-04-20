# Changelog

All notable changes to DeeperSplunk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-20

### Added

- Initial release.
- MCP server (`deepersplunk`) exposing the Steelman Method for Splunk alert triage.
- Three prompts: `steelman_triage`, `attack_hypothesis_framework`, `pre_verdict_checklist`.
- Seven tools: `fetch_notable_event`, `splunk_search`, `list_searches_run`, `find_similar_prior_verdicts`, `memory_stats`, `record_verdict`, `record_analyst_override`.
- `MockSplunkClient` with two scripted scenarios (`NOT-2026-04-20-0001` impossible travel, `NOT-2026-04-20-0002` encoded PowerShell to tor-exit C2) for local testing without a real Splunk instance.
- `RealSplunkClient` wrapping the official `splunk-sdk` for production deployments. Supports token and username/password authentication, with optional verdict writeback to notable events.
- SQLite-backed `VerdictMemory` storing every agent decision plus analyst overrides, with entity-overlap similarity lookup.
- Auto-fallback to mock mode when no Splunk credentials are configured.
- Evidence-integrity enforcement: `record_verdict` rejects any evidence item whose `search_id` does not match a search actually executed this session.
- Confidence-based escalation: TP/FP verdicts with confidence < 0.75 auto-coerce to `NEEDS_HUMAN_REVIEW`.
- Smoke test (`tests/smoke_test.py`) exercising the full workflow in mock mode.
- GitHub repo furniture: CI on Python 3.10/3.11/3.12, Dependabot, issue and PR templates, `CONTRIBUTING.md`, `SECURITY.md`.

[Unreleased]: https://github.com/your-org/DeeperSplunk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/DeeperSplunk/releases/tag/v0.1.0
