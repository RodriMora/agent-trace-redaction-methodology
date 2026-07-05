# Methodology

## 1. Preserve Native Shape

The exporter does not normalize agent traces into one common schema. It preserves the original structure:

- Codex and Pi remain line-delimited JSON event streams.
- OpenCode SQLite trace tables are exported as table-level JSONL.

This keeps tool calls, timestamps, event types, metadata, and framework-specific fields available for downstream analysis.

## 2. Privacy-by-Default, Not Private-Term-by-Default

The default system should be useful without passing concrete names, URLs, paths, or domains. It therefore starts from conservative policies:

- Redact all URLs unless explicitly allowed with `--allow-public-urls` / `--allow-domain`.
- Redact local paths, home directories, user-at-host prompts, SSH remotes, and Pi encoded cwd folders.
- Auto-discover likely local identifiers from username, home directory, hostname, git config name/email parts, local timezone city, Pi encoded session path components, and SSH config aliases.
- Keep `--private-term` and `--private-domain` as optional hardening inputs, not required configuration.

## 3. Redact Deterministically First

The first pass recursively redacts all string fields and path components with explicit rules:

- API keys and provider tokens
- Bearer tokens and authorization headers
- Private keys, SSH public keys, JWTs, and password hashes
- Database URLs and URL basic auth
- Sensitive environment variable assignments
- Emails, IPs/IPv6, MAC/Bluetooth IDs, SSH remotes
- URLs, OpenCode share URLs, and private domains containing local identity terms
- GPS coordinates, ISO6709/QuickTime location metadata, and lat/lon pairs
- Local home paths, generic home paths, shell prompts, and Pi encoded folders
- Contextual phone numbers, street-address-shaped content, identity-like compounds, and IBAN-like identifiers

Stable placeholders are used for repeated identifiers, such as `[HOME_PATH:0001:...]`, so structure remains analyzable without exposing the source value.

## 4. Redact Schema-Aware High-Risk Fields

Agent traces contain framework-specific metadata that can be sensitive even when it does not match a secret regex. The exporter redacts high-risk fields by key, including:

- `secret`, `token`, `apiKey`, `password`, `authorization`, credentials
- `share_url` and share metadata
- `encrypted_content`, `thinkingSignature`, and signatures / opaque provider blobs

OpenCode auth/account/credential/share tables are excluded by default. This avoids publishing operational metadata that is not necessary for trace analysis.

## 5. Add Contextual PII Detection

`openai/privacy-filter` can be enabled with `--privacy-filter`. The default mode is selective: only strings with likely PII cues are sent to the token-classification model. This avoids running a model over every code fragment, ID, or tool metadata field.

The Privacy Filter device defaults to `--privacy-filter-device auto`, which uses an NVIDIA/CUDA GPU when `torch.cuda.is_available()` is true and otherwise falls back to CPU. It can be forced with `--privacy-filter-device cpu`, `cuda`, or `cuda:N`.

The model layer targets contextual spans such as private names, addresses, phone numbers, emails, dates, account numbers, and private URLs.

## 6. Use Gitleaks as an Independent Gate

When `--gitleaks-fix` is enabled, the exporter runs Gitleaks with unredacted local output and uses the exact candidate strings to scrub the artifact. It does not print those values. If exact replacement is not possible in a JSONL record, the record is replaced with a small tombstone:

```json
{"type":"redacted_record","redacted":true,"redaction_reason":"gitleaks_jwt"}
```

When `--gitleaks` is enabled, a final Gitleaks report is written outside the artifact folder. The generated `REDACTION_REPORT.json` is also redacted before publication.

## 7. Verify After Export

The scanner checks both file contents and output path names for high-risk leftovers:

- local home paths and Pi encoded folders
- user-at-host shell prompts, configured username, username-containing domains, and identity-like compounds
- all URLs unless allowlisted
- OpenCode share URLs
- IPs, IPv6, MACs, Bluetooth paths
- GPS/ISO6709 coordinates, lat/lon pairs, and street-address-shaped content
- provider key prefixes, private keys, bearer tokens, SSH public keys, and password hashes
- normal email addresses
- unredacted API-key fields
- unredacted opaque provider blobs

This scanner is an independent gate and should be run after export, after optional LLM review, and in CI.

## 8. Canary Testing

The test suite injects fake PII/secrets into synthetic Codex, Pi, and OpenCode traces and asserts that nothing survives in file contents or path names:

```bash
python -m unittest discover -s tests -v
```

Canaries are important because regressions often appear in framework-specific metadata rather than obvious message text.

## 9. Optional Local LLM Review

`scripts/llm_residue_redact.py` can call a local OpenAI-compatible server as a final privacy reviewer. It sends only candidate chunks selected by regexes and optional `--private-term` values. The model returns exact substrings to redact; the script then applies those replacements inside parsed JSON/JSONL string values and object keys.

This avoids sending traces to a hosted API and avoids free-form rewriting that could break raw trace structure.
