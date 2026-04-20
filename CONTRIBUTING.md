# Contributing to DeeperSplunk

Thanks for your interest. This document covers how to propose changes, the coding conventions the project uses, and a few specific notes on touching the parts that matter most.

## Getting set up

```bash
git clone https://github.com/your-org/DeeperSplunk.git
cd DeeperSplunk
pip install -e ".[dev]"
python tests/smoke_test.py
```

If the smoke test passes, your environment is good.

## How to propose changes

1. **Open an issue first** for anything non-trivial. Drive-by PRs for small fixes (typos, doc clarifications, obvious bugs) are welcome without an issue.
2. **Fork, branch, commit.** One logical change per PR. Small, reviewable PRs merge faster than large ones.
3. **Keep the smoke test green.** `python tests/smoke_test.py` must pass before you open a PR.
4. **Run the linter.** `ruff check src/ tests/` and `ruff format src/ tests/`.
5. **Update CHANGELOG.md** under the "Unreleased" section for any user-visible change.
6. **Open a PR** with the template filled in.

## Coding conventions

- **Python 3.10+ only.** We use modern typing (`str | None`, PEP 604 unions).
- **Pydantic v2** for data models. Add new models to `src/deepersplunk/schemas.py`.
- **Type hints everywhere.** No untyped function signatures in `src/`.
- **Docstrings on every public tool.** The docstring is what Claude sees when it decides whether to use the tool — it is not optional and it is not cosmetic.
- **No emojis in code, logs, or tool output.** Keep it plain.
- **Log to stderr, not stdout.** STDIO transport uses stdout for the MCP protocol.

## Special care areas

### Changing prompts (`src/deepersplunk/prompts.py`)

The system prompt is the core of the product. Before you change it:

1. Describe in the PR what failure mode of the agent you are trying to fix.
2. If you're adding guardrails, show an example of an investigation where the current prompt fails and the new one would not.
3. If you're removing or weakening a guardrail, explain why the existing constraint was too tight and what replaces the safety margin.

The bar is deliberately high here. Prompt regressions are easy to miss and hard to catch.

### Changing the tool surface (`src/deepersplunk/server.py`)

- **Additions** are easy to accept. New tools should have tight docstrings and clear use cases.
- **Renames or signature changes** are breaking and should be flagged in the PR title with `[breaking]`.
- **`record_verdict` validation logic** is security-sensitive. The rule that every evidence item must cite a real `search_id`, and the rule that low-confidence TP/FP coerces to `NEEDS_HUMAN_REVIEW`, are load-bearing. Don't loosen them without a clear argument.

### Changing the Splunk client (`src/deepersplunk/splunk_client.py`)

- The `SplunkClient` protocol is intentionally narrow so a second SIEM backend can drop in. Resist expanding it unless the new method is unavoidable.
- `MockSplunkClient` should stay deterministic and self-contained. Do not add network calls or external fixtures.
- If you add new scenarios to mock mode, add corresponding assertions to `tests/smoke_test.py` and walk-throughs to `examples/example_sessions.md`.

### Changing memory schema (`src/deepersplunk/memory.py`)

Schema changes need a migration story. For v0.x we accept destructive migrations (drop and recreate) if the PR clearly documents that users will lose prior verdicts. Post-1.0 we won't.

## Testing philosophy

- The smoke test is the canary. If you break it, you know immediately.
- Unit tests for pure logic (similarity ranking, confidence coercion, evidence validation) are welcome. Add them under `tests/` with a `test_` prefix.
- Do not write tests that require a live Splunk instance; use `MockSplunkClient`.

## Commit messages

Conventional format is nice but not required. What is required: a subject line a reviewer can understand without opening the diff.

Good: `enforce evidence search_id validation in record_verdict`
Bad: `fix bug`

## Licensing

By contributing, you agree your contributions are licensed under the same MIT license as the project.
