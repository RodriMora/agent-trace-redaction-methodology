#!/usr/bin/env python3
import argparse
import json
import os
import re
from pathlib import Path


DEFAULT_PUBLIC_URL_ALLOWLIST = {
    "github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "docs.github.com",
    "npmjs.com",
    "www.npmjs.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "python.org",
    "docs.python.org",
    "nodejs.org",
    "developer.mozilla.org",
}


def build_patterns(user_name: str, home_dir: Path, private_domains: list[str]) -> dict[str, re.Pattern[str]]:
    user = re.escape(user_name)
    home = re.escape(str(home_dir))
    encoded_home = "--" + re.escape(str(home_dir).strip("/").replace("/", "-"))
    patterns = {
        "home_path_content": re.compile(r"(?:" + home + r"|~" + user + r")"),
        "generic_home_path_content": re.compile(r"(?:/home|home|/Users)/(?!\[)[A-Za-z0-9._-]+"),
        "encoded_home_path_content": re.compile(encoded_home),
        "generic_pi_encoded_path": re.compile(r"(?<![A-Za-z0-9_-])--(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]{3,}--(?![A-Za-z0-9_-])"),
        "user_at_host": re.compile(user + r"@"),
        "private_user_name": re.compile(r"(?i)\b" + user + r"\b"),
        "opencode_share_url": re.compile(r"\bhttps?://(?:www\.)?opncd\.ai/share/[^\s'\"<>`)}\]]+", re.I),
        "url": re.compile(r"\bhttps?://[^\s'\"<>`)}\]]+", re.I),
        "private_rfc1918_url": re.compile(r"\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)[^\s'\"<>`]*", re.I),
        "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"),
        "mac_address": re.compile(r"\b[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){4}\b"),
        "bluetooth_path": re.compile(r"/org/bluez/[^\s\"<>`)}\]]+|dev_[0-9A-Fa-f]{2}(?:_[0-9A-Fa-f]{2}){5}"),
        "ssh_public_key": re.compile(r"\bssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/=]{40,}"),
        "openai_key": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
        "short_sk_key": re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b"),
        "anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        "hf_token": re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
        "google_key": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
        "aws_key": re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
        "private_key": re.compile(r"BEGIN [A-Z0-9 ]*PRIVATE KEY"),
        "long_bearer": re.compile(r"Bearer (?!\[SECRET:)[A-Za-z0-9._~+/=-]{20,}"),
        "email": re.compile(r"(?<!\\)\b[A-Za-z0-9._%+-]+@(?!(?:app|router|pytest|bp|auth|admin)\.)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "api_key_field_value": re.compile(r'(?i)(?:api[_-]?key|apikey|apiKey)[ \t]*["\']?[ \t]*[:=][ \t]*["\']?(?!\[SECRET:|\[REDACTED:|\{env:|\$|undefined|null|string|boolean|number|\\n|\\r)[^\s\\"\',}]{3,}'),
        "encrypted_content_field": re.compile(r'"encrypted_content"\s*:\s*"(?!\[REDACTED:)[^"\\]*(?:\\.[^"\\]*)*"'),
        "thinking_signature_field": re.compile(r'"thinkingSignature"\s*:\s*"(?!\[REDACTED:)[^"\\]*(?:\\.[^"\\]*)*"'),
        "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        "contextual_phone": re.compile(r"(?i)\b(?:phone|tel|mobile|call me|telefono|tel[eé]fono)\s*[:=]?\s*(?:\+?\d[\d .()/-]{7,}\d)"),
    }
    if private_domains:
        patterns["private_domain"] = re.compile(
            r"(?i)\b(?:[A-Za-z0-9-]+\.)*(?:" + "|".join(re.escape(d) for d in private_domains) + r")\b"
        )
    return patterns


def is_inside_placeholder(text: str, start: int, end: int) -> bool:
    left = text.rfind("[", 0, start)
    right = text.rfind("]", 0, start)
    return left > right and "]" in text[end:end + 80]


def url_allowed(match: str, allowed_domains: set[str]) -> bool:
    if "[" in match or "]" in match:
        return False
    host_match = re.match(r"(?i)^https?://([^/:?#]+)", match)
    if not host_match:
        return False
    host = host_match.group(1).lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in allowed_domains)


def is_countable(name: str, match: str, text: str, start: int, allowed_domains: set[str]) -> bool:
    end = start + len(match)
    if is_inside_placeholder(text, start, end):
        return False
    if name == "url":
        if match in {"http://\\", "https://\\", "http://", "https://"}:
            return False
        if url_allowed(match, allowed_domains):
            return False
    if name == "email":
        if start > 0 and text[start - 1] in {"\\", "@", "["}:
            return False
        local, _, domain = match.partition("@")
        if len(local) <= 1:
            return False
        if domain.split(".", 1)[0].lower() in {"app", "router", "pytest", "bp", "auth", "admin"}:
            return False
    if name == "private_user_name":
        # Avoid false positives in JSON report keys such as "rodri": 0.
        if start > 0 and text[start - 1] == '"':
            after = text[end:end + 8]
            if after.startswith('"') and re.match(r'"\s*:', after):
                return False
    if name == "api_key_field_value":
        if "[SECRET:" in match or "[REDACTED:" in match:
            return False
        if start > 0 and text[start - 1] == "[":
            return False
        value = re.split(r"[:=]", match, maxsplit=1)[-1].strip().strip('"\'')
        if value in {"...", "***", "Optional[str]", "str", "string", "None", "null", "''", "\"\""}:
            return False
        if value.startswith("<") or value.startswith("str") or value.strip("*") == "":
            return False
        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_.$?]*(?:\s*\|\|\s*'')?", value):
            return False
        if not (len(value) >= 12 and re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
            return False
    if name in {"ipv4", "ipv6"}:
        if match.startswith("0.0.0.") or match in {"127.0.0.1"}:
            return False
        if name == "ipv6":
            groups = match.split(":")
            if re.fullmatch(r"\d{1,4}(?::\d{1,4})+", match):
                return False
            if "::" not in match and not any(re.search(r"[a-fA-F]", group) and len(group) >= 2 for group in groups):
                return False
    return True


def scan_text(text: str, patterns: dict[str, re.Pattern[str]], allowed_domains: set[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name, pattern in patterns.items():
        n = 0
        for m in pattern.finditer(text):
            if is_countable(name, m.group(0), text, m.start(), allowed_domains):
                n += 1
        if n:
            counts[name] = n
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan redacted trace output for high-risk leftovers.")
    parser.add_argument("--root", type=Path, default=Path.home() / "redacted-agent-traces")
    parser.add_argument("--user-name", default=os.environ.get("USER") or Path.home().name)
    parser.add_argument("--home-dir", type=Path, default=Path.home())
    parser.add_argument("--private-domain", action="append", default=[], help="Additional private domain to scan for. Can be repeated.")
    parser.add_argument("--allow-public-urls", action="store_true", help="Ignore a small built-in allowlist of public documentation/package URLs.")
    parser.add_argument("--allow-domain", action="append", default=[], help="Additional URL domain to ignore when --allow-public-urls is set.")
    args = parser.parse_args()

    allowed_domains = set(DEFAULT_PUBLIC_URL_ALLOWLIST if args.allow_public_urls else set())
    allowed_domains.update(domain.lower().lstrip(".") for domain in args.allow_domain)
    patterns = build_patterns(args.user_name, args.home_dir, args.private_domain)

    failed = False
    results: dict[str, dict[str, object]] = {name: {"matches": 0, "files": 0, "examples": []} for name in patterns}
    for path in sorted(args.root.rglob("*")):
        rel = str(path.relative_to(args.root))
        path_counts = scan_text(rel, patterns, allowed_domains)
        text_counts: dict[str, int] = {}
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            text_counts = scan_text(text, patterns, allowed_domains)
        names = set(path_counts) | set(text_counts)
        for name in names:
            count = path_counts.get(name, 0) + text_counts.get(name, 0)
            if count <= 0:
                continue
            results[name]["matches"] = int(results[name]["matches"]) + count
            results[name]["files"] = int(results[name]["files"]) + 1
            examples = results[name]["examples"]
            if isinstance(examples, list) and len(examples) < 5:
                where = "path" if path_counts.get(name, 0) else "content"
                examples.append(f"{rel} ({where})")
            failed = True

    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
