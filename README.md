# Agent Trace Redaction Methodology

Raw-preserving redaction pipeline for coding-agent traces from Codex, OpenCode, and Pi.

The goal is to prepare traces for research or dataset contribution while preserving the native framework shape: JSONL event streams stay JSONL, and OpenCode SQLite trace tables are exported as table-level JSONL.

## What It Does

- Preserves raw framework structure instead of normalizing all traces into a shared chat schema.
- Redacts secrets with deterministic rules for API keys, bearer tokens, private keys, DB URLs, auth headers, environment assignments, and cloud credentials.
- Redacts local identifiers such as home paths, shell prompts, encoded Pi path folders, emails, IPs, private URLs, and SSH remotes.
- Optionally runs `openai/privacy-filter` for contextual PII spans.
- Optionally runs Gitleaks as an independent post-export secret scanner and scrubber.
- Produces a `REDACTION_REPORT.json` and `MANIFEST.json`.

## Sources Expected

By default the exporter expects these paths under `--root`:

- Codex sessions: `.codex/sessions/**/*.jsonl`
- Codex history: `.codex/history.jsonl`
- Pi sessions: `.pi/agent/sessions/**/*.jsonl`
- OpenCode database: `.local/share/opencode/opencode.db`

OpenCode auth/account/credential tables are intentionally excluded. Trace tables such as `session`, `message`, `part`, and `event` are exported as JSONL.

## Quick Start

Create a Python environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Install Gitleaks separately and put it on `PATH`, or place the binary at `bin/gitleaks`.

Run the full pipeline:

```bash
python scripts/export_redacted_traces.py \
  --root "$HOME" \
  --out "$HOME/redacted-agent-traces" \
  --force \
  --private-domain example.com \
  --private-term "Private Project Name" \
  --privacy-filter \
  --gitleaks-fix \
  --gitleaks
```

Run the independent high-risk regex scan:

```bash
python scripts/scan_redacted_output.py \
  --root "$HOME/redacted-agent-traces" \
  --private-domain example.com
```

Optional local LLM final pass, using an OpenAI-compatible vLLM server:

```bash
python scripts/llm_residue_redact.py \
  --root "$HOME/redacted-agent-traces" \
  --base-url http://192.168.10.115:5000 \
  --workers 16 \
  --private-term "Private Project Name"
```

The LLM pass asks the local model for exact substrings to redact and applies replacements inside parsed JSON/JSONL string values and keys, preserving JSON validity.

## Practical Notes

The Privacy Filter model pass can be slow on large trace corpora. The exporter uses a selective/cached pass by default: it only sends strings with likely PII cues to the model. To send every eligible short string through the model, add:

```bash
--privacy-filter-all-strings
```

For large corpora, the recommended sequence is:

1. Run rule-based redaction.
2. Run selective Privacy Filter.
3. Run Gitleaks fix.
4. Run the optional local LLM exact-substring pass.
5. Run final Gitleaks scan.
6. Run independent regex scan.
7. Manually inspect a random sample and any high-risk sessions before publishing.

## Safety Model

This pipeline treats model redaction as an additional layer, not the primary guarantee. Structured secrets are handled with deterministic rules and Gitleaks. The model is used for contextual PII such as names, addresses, phone numbers, account numbers, dates, and private URLs.

The exporter may tombstone individual JSONL records if Gitleaks finds a candidate that cannot be safely replaced exactly.

## Output Layout

```text
redacted-agent-traces/
  codex/
    sessions/
    history.jsonl
  opencode/
    session.jsonl
    message.jsonl
    part.jsonl
    event.jsonl
    ...
  pi/
    agent/sessions/
  MANIFEST.json
  REDACTION_REPORT.json
```

## Disclaimer

No automated redaction pipeline is a guarantee. Use this as a layered methodology and perform manual review before releasing traces publicly.
