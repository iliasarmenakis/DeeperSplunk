<h1 align="center">DeeperSplunk</h1>

<p align="center">
  <em>An adversarial SOC triage agent for Splunk, exposed as an MCP server for Claude.</em>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue.svg"></a>
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green.svg"></a>
  <a href="https://modelcontextprotocol.io/"><img alt="MCP compatible" src="https://img.shields.io/badge/MCP-compatible-8A2BE2.svg"></a>
  <a href="./.github/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/badge/CI-passing-brightgreen.svg"></a>
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-orange.svg">
</p>

---

Most "AI for SIEM" tools try to prove each alert is a false positive. **DeeperSplunk does the opposite:** for every alert, it tries to prove the attacker is winning, and only declares the alert benign when the evidence actively refuses to cooperate with the attack hypothesis.

The difference matters. The cheapest cognitive mistake in a SOC is to find a plausible benign explanation and stop looking. Plausible does not mean true, and competent attackers design their activity to look plausible.

## Contents

- [Why this exists](#why-this-exists)
- [The Steelman Method](#the-steelman-method)
- [Architecture](#architecture)
- [Quick start (mock mode)](#quick-start-mock-mode)
- [Real Splunk deployment](#real-splunk-deployment)
- [Register with Claude Desktop](#register-with-claude-desktop)
- [Tool & prompt surface](#tool--prompt-surface)
- [Configuration reference](#configuration-reference)
- [What makes this different](#what-makes-this-different)
- [Development](#development)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Why this exists

Generic Splunk MCP servers (`livehybrid/splunk-mcp`, `balajifunny/splunk-mcp-server`, and friends) expose a raw `run_splunk_query` tool and let the model freestyle. That's a translator, not a triage agent. Commercial products (D3 Morpheus, Palo Alto Cortex XSIAM) do autonomous triage, but they're closed, expensive, and cloud-first.

DeeperSplunk is the minimum useful open alternative: a local-deployable MCP server that walks Claude through a disciplined investigation and refuses to cut corners.

## The Steelman Method

Every investigation walks six steps, enforced by the system prompt and the tool surface:

1. **Read the alert.** Fetch the notable event, state it in one sentence.
2. **Formulate the worst-case hypothesis.** Assume a competent attacker *is* active. Name the MITRE technique. Write down what you'd expect to see next if you're right.
3. **Hunt for supporting evidence.** Run searches that would *confirm* the hypothesis — lateral movement, persistence, credential access, C2, exfiltration, and a 90-day baseline of the primary entities.
4. **Resist the benign story.** When a normal-looking explanation presents itself, steelman the attack side against it. A benign explanation survives only if the adversarial alternative is actively contradicted by evidence you ran a search to gather. "Seems unlikely" is not evidence.
5. **Check collective memory.** Look up prior verdicts on similar alerts. Don't let prior FPs lull you into complacency — attackers target ignored patterns — but do incorporate the history.
6. **Issue a verdict.** `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_HUMAN_REVIEW` (the default when in doubt). Every evidence item must cite a search the agent actually ran. Confidence below 0.75 on a TP/FP auto-coerces to `NEEDS_HUMAN_REVIEW`.

The full prompt lives at [`src/deepersplunk/prompts.py`](src/deepersplunk/prompts.py) and is worth reading — it's the heart of the product.

## Architecture

```
        ┌──────────────────────────────┐
        │   Claude (Desktop / Code)    │
        └──────────────┬───────────────┘
                       │  MCP (STDIO or Streamable HTTP)
        ┌──────────────▼───────────────┐
        │     DeeperSplunk server      │
        │  ┌────────┐  ┌────────────┐  │
        │  │ Prompts│  │   Tools    │  │
        │  └────────┘  └─────┬──────┘  │
        │                    │         │
        │  ┌────────┐  ┌─────▼──────┐  │
        │  │ Memory │  │  Splunk    │  │
        │  │(SQLite)│  │  client    │  │
        │  └────────┘  └─────┬──────┘  │
        └────────────────────┼─────────┘
                             │
              ┌──────────────┼──────────────┐
              │                             │
     ┌────────▼────────┐         ┌──────────▼──────────┐
     │ MockSplunkClient│   OR    │  RealSplunkClient   │
     │ (sample data)   │         │  (splunk-sdk / REST)│
     └─────────────────┘         └─────────────────────┘
```

Everything runs locally. SQLite memory lives at `~/.deepersplunk/memory.sqlite3`. No data leaves your network except the LLM calls Claude itself makes — which carry only alert context and search results, not raw logs.

## Quick start (mock mode)

No Splunk instance required. Two fixture alerts ship with the project.

```bash
git clone https://github.com/iliasarmenakis/DeeperSplunk.git
cd DeeperSplunk
pip install -e .
python tests/smoke_test.py      # confirms your install works
deepersplunk                     # starts the MCP server over STDIO
```

With no Splunk credentials configured, mock mode auto-enables. The two fixture alerts:

| Event ID | Scenario | Expected verdict |
|---|---|---|
| `NOT-2026-04-20-0001` | Impossible Travel (Dublin → Lagos in 12 min) with clean MFA but novel device + novel geo | `NEEDS_HUMAN_REVIEW` at moderate confidence — a well-calibrated agent should NOT auto-acquit despite the MFA approval |
| `NOT-2026-04-20-0002` | `svc_backup` runs encoded PowerShell that IEX-downloads from a known-bad tor-exit C2 | `TRUE_POSITIVE` at high confidence |

See [`examples/example_sessions.md`](examples/example_sessions.md) for detailed walk-throughs of what a good run looks like on each.

## Real Splunk deployment

```bash
pip install -e ".[splunk]"       # pulls in the official splunk-sdk
cp .env.example .env
$EDITOR .env                     # set SPLUNK_HOST, SPLUNK_TOKEN, etc.
deepersplunk
```

Minimum Splunk permissions for the agent's user:

- **Read** on the indexes you want the agent to search (`notable`, `endpoint`, `network`, `proxy`, `okta`, etc.).
- Optional: `edit_notable_events` capability if you want the agent to write verdicts back as comments on the notable event in Splunk ES.

Mock mode auto-disables as soon as valid Splunk credentials are present. To force one mode or the other explicitly, set `DEEPERSPLUNK_MOCK_MODE=true` or `=false`.

## Register with Claude Desktop

Edit your Claude Desktop config:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Add the `DeeperSplunk` server (a complete example lives at [`claude_desktop_config.example.json`](claude_desktop_config.example.json)):

```json
{
  "mcpServers": {
    "DeeperSplunk": {
      "command": "python",
      "args": ["-m", "deepersplunk"],
      "env": {
        "DEEPERSPLUNK_MOCK_MODE": "false",
        "SPLUNK_HOST": "splunk.internal.example",
        "SPLUNK_PORT": "8089",
        "SPLUNK_SCHEME": "https",
        "SPLUNK_APP": "SA-EndpointProtection",
        "SPLUNK_VERIFY_SSL": "true",
        "SPLUNK_TOKEN": "<paste-splunk-auth-token-here>",
        "DEEPERSPLUNK_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

Restart Claude Desktop. The `DeeperSplunk` server appears with three prompts and seven tools.

**Using it in a chat:**

1. Open the prompt picker (`/`) and select `steelman_triage` — this installs the adversarial system prompt.
2. Ask: *"Triage notable event `NOT-2026-04-20-0001`."*
3. Claude walks the six-step workflow, calling tools, and ends with `record_verdict`.

## Tool & prompt surface

### Prompts

| Name | Purpose |
|---|---|
| `steelman_triage` | Master system prompt. Use this for every investigation. |
| `attack_hypothesis_framework` | Structured template for Step 2 hypothesis formulation. |
| `pre_verdict_checklist` | Quick self-check before `record_verdict`. |

### Tools

| Name | Purpose |
|---|---|
| `fetch_notable_event(event_id)` | Pull a notable from Splunk ES. Step 1. |
| `splunk_search(spl, earliest_time, latest_time)` | Run SPL; returns a `search_id` for citation. Step 3. |
| `list_searches_run()` | List every search run so far in this session, with their IDs. |
| `find_similar_prior_verdicts(event_id, limit)` | Query collective memory. Step 5. |
| `memory_stats()` | Verdict breakdown across all stored decisions. |
| `record_verdict(...)` | Issue the final verdict. Validates evidence references real search_ids; coerces low-confidence TP/FP to `NEEDS_HUMAN_REVIEW`. Step 6. |
| `record_analyst_override(event_id, new_verdict, note)` | For integrations — human corrects a prior agent verdict; correction is stored for future similarity lookups. |

## Configuration reference

All settings are read from environment variables (or a `.env` file in the working directory).

| Variable | Default | Purpose |
|---|---|---|
| `DEEPERSPLUNK_MOCK_MODE` | auto | `true`/`false`. Auto-enables when no Splunk credentials are set. |
| `SPLUNK_HOST` | `localhost` | Splunk server hostname |
| `SPLUNK_PORT` | `8089` | Splunk management port |
| `SPLUNK_SCHEME` | `https` | `http` or `https` |
| `SPLUNK_APP` | `search` | Splunk app context for searches |
| `SPLUNK_VERIFY_SSL` | `true` | Verify TLS certs on connection |
| `SPLUNK_TOKEN` | — | Auth token (preferred) |
| `SPLUNK_USERNAME` | — | Username (fallback to token) |
| `SPLUNK_PASSWORD` | — | Password (fallback to token) |
| `DEEPERSPLUNK_SEARCH_LIMIT` | `100` | Max result rows per search |
| `DEEPERSPLUNK_MEMORY_DB` | `~/.deepersplunk/memory.sqlite3` | SQLite memory path |
| `DEEPERSPLUNK_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

## What makes this different

Three concrete design choices separate DeeperSplunk from a generic Splunk MCP wrapper:

1. **The prompt enforces a method, not a vibe.** The system prompt is a six-step discipline with guardrails, not "you are a helpful security analyst."
2. **Evidence must be real.** `record_verdict` rejects any evidence item whose `search_id` doesn't match a search the agent actually ran this session. You can't paper over a rushed investigation.
3. **Low confidence escalates automatically.** A TP or FP with confidence < 0.75 becomes `NEEDS_HUMAN_REVIEW`. The agent can't convict or acquit on a hunch.

## Development

```bash
pip install -e ".[dev]"
python tests/smoke_test.py       # end-to-end smoke test in mock mode
ruff check src/ tests/           # lint
```

Run the server directly for debugging:

```bash
DEEPERSPLUNK_LOG_LEVEL=DEBUG deepersplunk
```

Or point the MCP Inspector at it:

```bash
npx @modelcontextprotocol/inspector deepersplunk
```

## Roadmap

Open to contributions on any of these:

- [ ] **Shadow mode.** A flag that stores verdicts but skips the Splunk writeback, so the agent can run in parallel with human analysts for calibration without touching production dispositions.
- [ ] **Per-investigation token/search budgets.** Hard cap on searches + tokens, with forced escalation to `NEEDS_HUMAN_REVIEW` when the cap hits.
- [ ] **Second SIEM backend.** The `SplunkClient` protocol is narrow — a `SentinelClient` or `ChronicleClient` should be ~a day of work.
- [ ] **Vector-based similarity.** Current memory lookup uses rule name + entity overlap. An embedding layer would raise recall on paraphrased rules.
- [ ] **Webhook for notable events.** Let Splunk ES push new notables in; let the agent pick them up without a human prompt.
- [ ] **Calibration report generator.** Given N agent verdicts and the corresponding analyst final dispositions, produce an accuracy/precision/recall breakdown.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy and known considerations — the short version: this project talks to your SIEM; treat it like any other privileged security tool.

## License

[MIT](LICENSE).
