# Methodology

## 1. Preserve Native Shape

The exporter does not normalize agent traces into one common schema. It preserves the original structure:

- Codex and Pi remain line-delimited JSON event streams.
- OpenCode SQLite trace tables are exported as table-level JSONL.

This keeps tool calls, timestamps, event types, metadata, and framework-specific fields available for downstream analysis.

## 2. Redact Deterministically First

The first pass recursively redacts all string fields and path components with explicit rules:

- API keys and provider tokens
- Bearer tokens and authorization headers
- Private keys and JWTs
- Database URLs and URL basic auth
- Sensitive environment variable assignments
- Emails, IPs, private URLs, SSH remotes
- Local home paths and shell prompts

Stable placeholders are used for repeated identifiers, such as `[HOME_PATH:0001:...]`, so structure remains analyzable without exposing the source value.

## 3. Add Contextual PII Detection

`openai/privacy-filter` can be enabled with `--privacy-filter`. The default mode is selective: only strings with likely PII cues are sent to the token-classification model. This avoids running a model over every code fragment, ID, or tool metadata field.

The model layer targets contextual spans such as private names, addresses, phone numbers, emails, dates, account numbers, and private URLs.

## 4. Use Gitleaks as an Independent Gate

When `--gitleaks-fix` is enabled, the exporter runs Gitleaks with unredacted local output and uses the exact candidate strings to scrub the artifact. It does not print those values. If exact replacement is not possible in a JSONL record, the record is replaced with a small tombstone:

```json
{"type":"redacted_record","redacted":true,"redaction_reason":"gitleaks_jwt"}
```

When `--gitleaks` is enabled, a final Gitleaks report is written outside the artifact folder.

## 5. Verify After Export

The included scanner checks for common high-risk leftovers:

- local home paths
- encoded local path folders
- user-at-host shell prompts
- provider key prefixes
- private keys
- bearer tokens
- normal email addresses

This scan is intentionally narrow and should be complemented by Gitleaks and manual review.

## 6. Optional Local LLM Review

`scripts/llm_residue_redact.py` can call a local OpenAI-compatible vLLM server as a final privacy reviewer. It sends only candidate chunks selected by regexes and optional `--private-term` values. The model returns exact substrings to redact; the script then applies those replacements inside parsed JSON/JSONL string values and object keys.

This avoids sending traces to a hosted API and avoids free-form rewriting that could break raw trace structure.
