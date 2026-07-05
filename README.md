# Agent Trace Redaction Methodology

Raw-preserving, privacy-by-default redaction pipeline for coding-agent traces from Codex, OpenCode, and Pi.

The goal is to prepare traces for research or dataset contribution while preserving native framework shape: JSONL event streams stay JSONL, and OpenCode SQLite trace tables are exported as table-level JSONL.

## What It Does

- Preserves raw framework structure instead of normalizing all traces into a shared chat schema.
- Redacts secrets with deterministic rules for API keys, bearer tokens, private keys, DB URLs, auth headers, environment assignments, cloud credentials, SSH keys, JWTs, and IBAN-like values.
- Redacts local identifiers such as home paths, shell prompts, Pi encoded cwd folders, emails, IPs/IPv6, MAC/Bluetooth IDs, SSH remotes, GPS/ISO6709 metadata, street-address-shaped content, and contextual phone numbers.
- Redacts **all URLs by default**. You can opt into a small public allowlist with `--allow-public-urls` and add domains with `--allow-domain`.
- Applies schema-aware redaction for high-risk fields such as `secret`, `token`, `apiKey`, `password`, `authorization`, `share_url`, `encrypted_content`, `thinkingSignature`, and signatures.
- Excludes OpenCode auth/account/credential/share tables by default.
- Auto-discovers local identity hints from username, home directory, hostname, git config, and SSH config aliases. User-provided `--private-term` and `--private-domain` remain optional hardening knobs, not requirements.
- Optionally runs `openai/privacy-filter` for contextual PII spans, auto-using NVIDIA/CUDA when available.
- Optionally runs Gitleaks as an independent post-export secret scanner and scrubber.
- Produces a redacted `REDACTION_REPORT.json` and `MANIFEST.json`.

## Sources Expected

By default the exporter expects these paths under `--root`:

- Codex sessions: `.codex/sessions/**/*.jsonl`
- Codex history: `.codex/history.jsonl`
- Pi sessions: `.pi/agent/sessions/**/*.jsonl`
- OpenCode database: `.local/share/opencode/opencode.db`

OpenCode operational/auth/share tables are intentionally excluded. Trace tables such as `session`, `message`, `part`, and `event` are exported as JSONL.

## Quick Start

Create a Python environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Install Gitleaks separately and put it on `PATH`, or place the binary at `scripts/bin/gitleaks`.

Run the full privacy-by-default pipeline:

```bash
python scripts/export_redacted_traces.py \
  --root "$HOME" \
  --out "$HOME/redacted-agent-traces" \
  --force \
  --privacy-filter \
  --gitleaks-fix \
  --gitleaks
```

Optional hardening if you know extra private names/domains:

```bash
python scripts/export_redacted_traces.py \
  --root "$HOME" \
  --out "$HOME/redacted-agent-traces" \
  --force \
  --private-term "Private Client Name" \
  --private-domain internal.example \
  --privacy-filter \
  --gitleaks-fix \
  --gitleaks
```

Run the independent high-risk scanner:

```bash
python scripts/scan_redacted_output.py \
  --root "$HOME/redacted-agent-traces"
```

Optional local LLM final pass, using an OpenAI-compatible local server:

```bash
python scripts/llm_residue_redact.py \
  --root "$HOME/redacted-agent-traces" \
  --base-url http://localhost:8000 \
  --workers 16
```

The LLM pass asks the local model for exact substrings to redact and applies replacements inside parsed JSON/JSONL string values and keys, preserving JSON validity.

## Useful Options

- `--no-auto-discover`: disable zero-config discovery of username, hostname, git identity, and SSH aliases.
- `--allow-public-urls`: preserve a small built-in allowlist of public documentation/package URLs.
- `--allow-domain example.org`: add an allowed URL domain when `--allow-public-urls` is enabled.
- `--private-term "..."`: add an exact private term to redact everywhere.
- `--private-domain example.internal`: add a private domain to redact even outside full URLs.
- `--privacy-filter-device auto|cpu|cuda|cuda:N`: choose the device for `openai/privacy-filter`; default `auto` uses NVIDIA/CUDA when available.
- `--privacy-filter-batch-size N`: batch size for the GPU/CPU privacy-filter pass.
- `--privacy-filter-all-strings`: send every eligible short string through `openai/privacy-filter` instead of only strings with PII cues.

## Practical Notes

The Privacy Filter model pass can be slow on large trace corpora. The exporter uses a selective/cached pass by default: it only sends strings with likely PII cues to the model.

For large corpora, the recommended sequence is:

1. Run rule-based/schema-aware redaction.
2. Run selective Privacy Filter.
3. Run Gitleaks fix.
4. Run the optional local LLM exact-substring pass.
5. Run final Gitleaks scan.
6. Run independent regex/path scan.
7. Manually inspect a random sample and any high-risk sessions before publishing.

## Testing

The repo includes a zero-dependency canary test:

```bash
python -m unittest discover -s tests -v
```

It builds synthetic Codex, Pi, and OpenCode traces containing fake PII/secrets/share URLs/encoded paths, runs the exporter, and verifies the scanner reports no leftovers.

## Safety Model

This pipeline treats model redaction as an additional layer, not the primary guarantee. Structured secrets and high-risk schema fields are handled with deterministic rules and Gitleaks. The model is used for contextual PII such as names, addresses, account numbers, dates, and private project/client terms.

No automated redaction pipeline can guarantee perfect removal of all natural-language PII. The default posture is high recall and privacy-by-default, with optional allowlists only when preserving public references matters.
