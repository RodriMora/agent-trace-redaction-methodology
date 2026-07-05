#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "http://localhost:8000"

DEFAULT_CANDIDATE_PATTERNS = [
    r"\b[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){4}\b",
    r"/org/bluez/[^\s\"<>`)}\]]+|dev_[0-9A-Fa-f]{2}(?:_[0-9A-Fa-f]{2}){5}",
    r"(?i:\b(serial|s/n|device id|hardware id|bluetooth|bssid|mac address)\b)",
    r"(?i:\b(location|address|client|customer|project|meeting|transcript|recording)\b)",
    r"\bhttps?://[^\s'\"<>`)}\]]+",
    r"(?<![A-Za-z0-9_-])--(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]{3,}--(?![A-Za-z0-9_-])",
]

SYSTEM_PROMPT = """You are a privacy redaction reviewer for coding-agent traces.
Return only JSON. Do not explain.

Find exact substrings in the provided chunk that should be redacted before public release.
Focus on:
- person names
- precise locations or venues
- private organization, client, project, or meeting names
- device names tied to a person
- hardware identifiers, serial numbers, MAC/Bluetooth identifiers
- private hostnames/domains

Do not include:
- placeholders already inside square brackets, e.g. [PRIVATE_NAME]
- generic programming terms, library names, common English/Spanish words, or code identifiers
- values that are already redacted

Return:
{"redactions":[{"text":"exact substring from chunk","category":"PERSON|LOCATION|PROJECT|DEVICE|HARDWARE_ID|DOMAIN|OTHER"}]}
"""


def api_base(base_url: str) -> str:
    base = base_url.rstrip("/")
    return base if base.endswith("/v1") else base + "/v1"


def http_json(url: str, payload: dict[str, Any] | None = None, timeout: int = 60) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def discover_model(base_url: str) -> str:
    data = http_json(api_base(base_url) + "/models", timeout=15)
    models = data.get("data") or []
    if not models:
        raise SystemExit("No models returned by /v1/models")
    return models[0]["id"]


def extract_json(text: str) -> dict[str, Any]:
    if text is None:
        return {"redactions": []}
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return {"redactions": []}
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return {"redactions": []}


def ask_model(base_url: str, model: str, chunk: str, timeout: int) -> list[dict[str, str]]:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "CHUNK:\n" + chunk},
        ],
        "temperature": 0,
        "max_tokens": 1024,
    }
    try:
        data = http_json(api_base(base_url) + "/chat/completions", payload, timeout=timeout)
    except (urllib.error.URLError, TimeoutError):
        return []
    content = data.get("choices", [{}])[0].get("message", {}).get("content") or ""
    parsed = extract_json(content)
    redactions = parsed.get("redactions", [])
    if not isinstance(redactions, list):
        return []
    clean = []
    for item in redactions:
        if isinstance(item, str):
            text = item
            category = "OTHER"
        elif isinstance(item, dict):
            text = str(item.get("text", ""))
            category = str(item.get("category", "OTHER"))
        else:
            continue
        text = text.strip()
        category = re.sub(r"[^A-Z0-9_]", "_", category.upper()) or "OTHER"
        if len(text) < 3 or "[" in text or "]" in text:
            continue
        if text not in chunk:
            continue
        clean.append({"text": text, "category": category})
    return clean


def iter_chunks(path: Path, candidate_re: re.Pattern[str], max_chars: int) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    chunks = []
    if path.suffix == ".jsonl":
        for line in text.splitlines():
            if candidate_re.search(line):
                chunks.append(line[:max_chars])
    else:
        for match in candidate_re.finditer(text):
            start = max(0, match.start() - max_chars // 2)
            end = min(len(text), match.end() + max_chars // 2)
            chunks.append(text[start:end])
    return chunks


def placeholder(category: str) -> str:
    return "[LLM_PII:" + re.sub(r"[^A-Z0-9_]", "_", category.upper()) + "]"


def replace_in_value(value: Any, replacements: dict[str, str]) -> tuple[Any, int]:
    if isinstance(value, str):
        new = value
        count = 0
        for old, category in sorted(replacements.items(), key=lambda kv: len(kv[0]), reverse=True):
            n = new.count(old)
            if n:
                new = new.replace(old, placeholder(category))
                count += n
        return new, count
    if isinstance(value, list):
        total = 0
        items = []
        for item in value:
            new_item, n = replace_in_value(item, replacements)
            items.append(new_item)
            total += n
        return items, total
    if isinstance(value, dict):
        total = 0
        obj = {}
        for key, item in value.items():
            new_key = key
            if isinstance(key, str):
                new_key, key_count = replace_in_value(key, replacements)
                total += key_count
            new_item, n = replace_in_value(item, replacements)
            obj[new_key] = new_item
            total += n
        return obj, total
    return value, 0


def apply_replacements(path: Path, replacements: dict[str, str], dry_run: bool) -> tuple[bool, int]:
    if not replacements:
        return False, 0
    if path.suffix == ".jsonl":
        changed = False
        total = 0
        out_lines = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                out_lines.append(line)
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                out_lines.append(line)
                continue
            new_obj, n = replace_in_value(obj, replacements)
            total += n
            changed = changed or n > 0
            out_lines.append(json.dumps(new_obj, ensure_ascii=False, separators=(",", ":")))
        if changed and not dry_run:
            path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
        return changed, total
    if path.suffix == ".json":
        try:
            obj = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            obj = None
        if obj is not None:
            new_obj, total = replace_in_value(obj, replacements)
            if total and not dry_run:
                path.write_text(json.dumps(new_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            return total > 0, total

    text = path.read_text(encoding="utf-8", errors="ignore")
    new = text
    total = 0
    for old, category in sorted(replacements.items(), key=lambda kv: len(kv[0]), reverse=True):
        n = new.count(old)
        if n:
            new = new.replace(old, placeholder(category))
            total += n
    if total and not dry_run:
        path.write_text(new, encoding="utf-8")
    return total > 0, total


def main() -> int:
    parser = argparse.ArgumentParser(description="Use a local OpenAI-compatible LLM to propose exact privacy redactions.")
    parser.add_argument("--root", type=Path, default=Path.home() / "redacted-agent-traces")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--model", default=None)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--max-chars", type=int, default=6000)
    parser.add_argument("--max-chunks", type=int, default=0, help="0 means no limit.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--candidate-regex", action="append", default=[])
    parser.add_argument("--private-term", action="append", default=[], help="Additional exact term to inspect/redact if model agrees.")
    args = parser.parse_args()

    model = args.model or discover_model(args.base_url)
    patterns = list(DEFAULT_CANDIDATE_PATTERNS) + args.candidate_regex
    patterns.extend(re.escape(term) for term in args.private_term)
    candidate_re = re.compile("|".join("(?:" + p + ")" for p in patterns))

    tasks: list[tuple[Path, str]] = []
    for path in sorted(args.root.rglob("*")):
        if not path.is_file() or path.name.endswith(".pyc"):
            continue
        if path.stat().st_size > 50 * 1024 * 1024:
            continue
        for chunk in iter_chunks(path, candidate_re, args.max_chars):
            tasks.append((path, chunk))
            if args.max_chunks and len(tasks) >= args.max_chunks:
                break
        if args.max_chunks and len(tasks) >= args.max_chunks:
            break

    findings: dict[Path, dict[str, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(ask_model, args.base_url, model, chunk, args.timeout): path
            for path, chunk in tasks
        }
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            try:
                result = future.result()
            except Exception:
                result = []
            for item in result:
                findings.setdefault(path, {})[item["text"]] = item["category"]

    files_changed = 0
    replacements = 0
    for path, values in findings.items():
        changed, count = apply_replacements(path, values, args.dry_run)
        replacements += count
        if changed and not args.dry_run:
            files_changed += 1

    print(json.dumps({
        "model": model,
        "chunks_reviewed": len(tasks),
        "files_with_findings": len(findings),
        "files_changed": 0 if args.dry_run else files_changed,
        "replacements": replacements,
        "dry_run": args.dry_run,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
