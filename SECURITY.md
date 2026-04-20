# Security Policy

## Context

DeeperSplunk is itself a security tool. It connects to your SIEM with privileged credentials, executes SPL against production indexes, and writes verdicts back to notable events. Treat it with the same care you'd apply to any other privileged security tool in your environment.

## Supported versions

While DeeperSplunk is in 0.x, only the latest minor release receives security fixes. After 1.0.0 this policy will be revised.

| Version | Supported |
|---|---|
| 0.1.x | ✓ |
| < 0.1 | ✗ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the form with as much detail as you can provide.

If that path is unavailable for any reason, email the maintainers directly (address listed in the repo's profile).

We aim to:

- **Acknowledge** your report within 72 hours.
- **Provide a fix or mitigation timeline** within 7 days.
- **Credit you** in the release notes and the fix commit, unless you prefer otherwise.

## What counts as a vulnerability

Clear yes:

- Authentication bypass against the MCP server
- SPL injection that escalates beyond the agent's intended Splunk permissions
- Storage of credentials in plaintext in logs or memory beyond their intended scope
- Unbounded reflection of user input into Splunk comments or the verdict store that leads to privilege escalation
- Remote code execution via any tool parameter

Probably yes — report them:

- A crafted notable event that causes `record_verdict` to accept evidence the agent did not actually gather
- A prompt-injection vector in notable event fields that reliably flips agent verdicts
- A timing or error-oracle leak that reveals non-public data from the Splunk instance to the MCP client

Probably not — open a regular issue:

- The agent reached a wrong verdict on an alert (that's a prompt/triage-quality issue, not a vulnerability)
- Splunk's own API returned something unexpected and the agent misreported it
- Feature requests for additional access controls

## Known considerations

These are design properties, not bugs — but they're worth knowing:

- **The agent has read access to every index its Splunk user can read.** Create a dedicated read-only Splunk user for the agent and scope its role to the indexes that triage genuinely requires.
- **Verdicts go to an LLM.** Splunk search results flow into Claude as context. If your environment prohibits sensitive data (PII, PCI, PHI, session tokens) from leaving the network boundary where Claude's API lives, filter those fields at search time. The `MockSplunkClient` is useful for testing what the agent sees.
- **Prompt injection via log content is a real risk.** A malicious actor who can get attacker-controlled text into a Splunk field the agent reads could attempt to inject instructions. The system prompt's evidence-citation requirement is the main defence; it does not make the risk zero.
- **Verdict writeback is best-effort.** If `write_verdict_comment` silently fails, the agent's decision is still stored locally but is not visible to analysts in Splunk ES. Monitor the log for writeback failures.

## Dependency policy

- We use Dependabot (see `.github/dependabot.yml`) to surface security updates for Python dependencies and GitHub Actions weekly.
- Critical security updates for direct dependencies are merged within 7 days of a working PR.
