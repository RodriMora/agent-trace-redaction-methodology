#!/usr/bin/env python3
import argparse
import json
import os
import re
from pathlib import Path
from collections.abc import Callable


def build_patterns(user_name: str, home_dir: Path, private_domains: list[str]) -> dict[str, re.Pattern[str]]:
    user = re.escape(user_name)
    home = re.escape(str(home_dir))
    encoded_home = "--" + re.escape(str(home_dir).strip("/").replace("/", "-"))
    patterns = {
    "home_path_content": re.compile(r"(?:" + home + r"|~" + user + r")"),
    "generic_home_path_content": re.compile(r"(?:/home|home)/(?!\[)[A-Za-z0-9._-]+"),
    "encoded_home_path_content": re.compile(encoded_home),
    "user_at_host": re.compile(user + r"@"),
    "private_user_name": re.compile(r"(?i)\b" + user + r"\b"),
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
    "api_key_field_value": re.compile(r'(?i)(?:api[_-]?key|apikey|apiKey)[ \t]*["\']?[ \t]*[:=][ \t]*["\']?(?!\[SECRET:|\[APIKEY_FIELD\]|\{env:|\$|undefined|null|string|boolean|number|\\n|\\r)[^\s\\"\',}]{3,}'),
    }
    if private_domains:
        patterns["private_domain"] = re.compile(
            r"(?i)\b(?:[A-Za-z0-9-]+\.)*(?:" + "|".join(re.escape(d) for d in private_domains) + r")\b"
        )
    return patterns


def is_countable(name: str, match: str, text: str, start: int) -> bool:
    if name == "email":
        if start > 0 and text[start - 1] in {"\\", "@", "["}:
            return False
        local, _, domain = match.partition("@")
        if len(local) <= 1:
            return False
        if domain.split(".", 1)[0].lower() in {"app", "router", "pytest", "bp", "auth", "admin"}:
            return False
    if name == "api_key_field_value":
        if "[APIKEY_FIELD]" in match or "[SECRET:" in match:
            return False
        if start > 0 and text[start - 1] == "[":
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan redacted trace output for high-risk leftovers.")
    parser.add_argument("--root", type=Path, default=Path.home() / "redacted-agent-traces")
    parser.add_argument("--user-name", default=os.environ.get("USER") or Path.home().name)
    parser.add_argument("--home-dir", type=Path, default=Path.home())
    parser.add_argument("--private-domain", action="append", default=[], help="Private domain to scan for. Can be repeated.")
    args = parser.parse_args()

    failed = False
    results = {}
    for name, pattern in build_patterns(args.user_name, args.home_dir, args.private_domain).items():
        count = 0
        files = 0
        examples = []
        for path in args.root.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            matches = [
                m.group(0)
                for m in pattern.finditer(text)
                if is_countable(name, m.group(0), text, m.start())
            ]
            if matches:
                count += len(matches)
                files += 1
                if len(examples) < 5:
                    examples.append(str(path.relative_to(args.root)))
        results[name] = {"matches": count, "files": files, "examples": examples}
        failed = failed or count > 0
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
