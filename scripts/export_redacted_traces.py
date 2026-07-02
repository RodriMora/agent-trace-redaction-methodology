#!/usr/bin/env python3
import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Any


DEFAULT_ROOT = Path.home()
DEFAULT_OUT = DEFAULT_ROOT / "redacted-agent-traces"

OPENCODE_TABLES = [
    "workspace",
    "project",
    "project_directory",
    "session",
    "session_context_epoch",
    "session_message",
    "session_share",
    "session_input",
    "message",
    "part",
    "event",
    "event_sequence",
    "permission",
    "todo",
]


class Redactor:
    def __init__(
        self,
        privacy_filter: "PrivacyFilter | None" = None,
        user_name: str | None = None,
        home_dir: Path | None = None,
        private_domains: list[str] | None = None,
        private_terms: list[str] | None = None,
    ) -> None:
        self.counts: collections.Counter[str] = collections.Counter()
        self.maps: dict[str, dict[str, str]] = collections.defaultdict(dict)
        self.privacy_filter = privacy_filter
        self.user_name = user_name or os.environ.get("USER") or Path.home().name
        self.home_dir = home_dir or Path.home()
        user = re.escape(self.user_name)
        home = re.escape(str(self.home_dir))
        encoded_home = "--" + re.escape(str(self.home_dir).strip("/").replace("/", "-"))
        domain_pattern = None
        if private_domains:
            domain_pattern = r"(?i)\b(?:[A-Za-z0-9-]+\.)*(?:" + "|".join(
                re.escape(domain) for domain in private_domains
            ) + r")\b"
        term_pattern = None
        if private_terms:
            term_pattern = r"(?i)\b(?:" + "|".join(re.escape(term) for term in private_terms) + r")\b"
        self.patterns: list[tuple[str, re.Pattern[str], str | None]] = [
            (
                "private_key",
                re.compile(
                    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                    re.DOTALL,
                ),
                "[SECRET:PRIVATE_KEY]",
            ),
            (
                "authorization_bearer",
                re.compile(r"(?i)(Authorization\s*:\s*Bearer\s+)(?:REDACTED|[A-Za-z0-9._~+/=-]{8,})"),
                r"\1[SECRET:BEARER_TOKEN]",
            ),
            (
                "bearer_token",
                re.compile(r"(?i)\b(Bearer\s+)(?!\[SECRET:)(?:REDACTED|[A-Za-z0-9._~+/=-]{8,})"),
                r"\1[SECRET:BEARER_TOKEN]",
            ),
            (
                "env_secret_assignment",
                re.compile(
                    r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDS[_-]?(?:KEY|IV))[A-Z0-9_]*\s*=\s*)(['\"]?)(?:REDACTED|[^\s'\"\\]{8,})\2"
                ),
                r"\1[SECRET:ENV_VALUE]",
            ),
            ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"), "[SECRET:OPENAI_API_KEY]"),
            ("short_sk_key", re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b"), "[SECRET:API_KEY_FIELD]"),
            ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "[SECRET:ANTHROPIC_API_KEY]"),
            ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[SECRET:GITHUB_TOKEN]"),
            ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "[SECRET:HUGGINGFACE_TOKEN]"),
            ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "[SECRET:GOOGLE_API_KEY]"),
            ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"), "[SECRET:AWS_ACCESS_KEY]"),
            ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[SECRET:JWT]"),
            ("mac_address", re.compile(r"\b[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){4}\b"), "[HW:MAC_ADDRESS]"),
            ("bluetooth_path", re.compile(r"/org/bluez/[^\s\"<>`)}\]]+|dev_[0-9A-Fa-f]{2}(?:_[0-9A-Fa-f]{2}){5}"), "[HW:BLUETOOTH_PATH]"),
            ("airpods_pro", re.compile(r"(?i)\bAirPods\s+Pro\b"), "[HW:BLUETOOTH_DEVICE]"),
            ("scarlett_solo", re.compile(r"(?i)\bScarlett\s+Solo\b"), "[HW:AUDIO_DEVICE]"),
            ("focusrite_device", re.compile(r"(?i)\bFocusrite(?:[_\s-]+[A-Za-z0-9]+)*\b"), "[HW:AUDIO_DEVICE]"),
            (
                "url_basic_auth",
                re.compile(r"\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s:@]+@"),
                r"\1[SECRET:BASIC_AUTH]@",
            ),
            (
                "database_url",
                re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"<>`]+", re.I),
                "[SECRET:DATABASE_URL]",
            ),
            (
                "api_key_json_field",
                re.compile(r'(?i)((?:\\?")api[_-]?key(?:\\?")\s*:\s*(?:\\?"))(?!\[SECRET:|\{env:)[^\\"]+((?:\\?"))'),
                r"\1[SECRET:API_KEY_FIELD]\2",
            ),
            (
                "api_key_assignment",
                re.compile(r"(?i)\b(api[_-]?key|apikey)\s*=\s*(['\"]?)(?!\[SECRET:|\{env:)[^\s'\"\\]{3,}\2"),
                r"\1=[SECRET:API_KEY_FIELD]",
            ),
            ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
            ("user_at_host", re.compile(user + r"@[A-Za-z0-9._-]+\b"), "[PII:USER_AT_HOST]"),
            ("user_at_literal", re.compile(user + r"@"), "[PII:USER_AT]"),
            ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[PII:IP_ADDRESS]"),
            ("encoded_home_path", re.compile(encoded_home + r"(?:-[A-Za-z0-9_.]+)*--"), None),
            ("encoded_home_path_literal", re.compile(encoded_home), "[ENCODED_HOME_PATH]"),
            *(
                [("private_domain", re.compile(domain_pattern), "[PRIVATE_DOMAIN]")]
                if domain_pattern
                else []
            ),
            *(
                [("private_term", re.compile(term_pattern), "[PRIVATE_TERM]")]
                if term_pattern
                else []
            ),
            ("private_user_name", re.compile(r"(?i)\b" + user + r"\b"), "[PRIVATE_USER]"),
            ("redacted_literal", re.compile(r"\bREDACTED\b"), "[OMITTED]"),
            ("generic_home_path", re.compile(r"(?:/home|home)/[A-Za-z0-9._-]+(?:/[^\s'\"<>`)}\]]*)?"), None),
            ("home_path", re.compile(r"(?:" + home + r"|~)(?:/[^\s'\"<>`)}\]]*)?"), None),
            ("mac_home_path", re.compile(r"/Users/[A-Za-z0-9._-]+(?:/[^\s'\"<>`)}\]]*)?"), None),
            (
                "ssh_remote",
                re.compile(r"\b(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+:(?:/)?[A-Za-z0-9._/-]+\.git\b"),
                None,
            ),
            (
                "private_url",
                re.compile(r"\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)[^\s'\"<>`]*"),
                "[PRIVATE_URL]",
            ),
        ]

    def stable(self, category: str, value: str) -> str:
        bucket = self.maps[category]
        if value not in bucket:
            digest = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:10]
            bucket[value] = f"[{category.upper()}:{len(bucket) + 1:04d}:{digest}]"
        return bucket[value]

    def redact_string(self, value: str) -> str:
        out = value
        for category, pattern, replacement in self.patterns:
            def repl(match: re.Match[str]) -> str:
                self.counts[category] += 1
                if replacement is None:
                    return self.stable(category, match.group(0))
                return match.expand(replacement)

            out = pattern.sub(repl, out)
        if self.privacy_filter is not None:
            out, spans = self.privacy_filter.redact(out)
            for label, count in spans.items():
                self.counts[f"privacy_filter_{label}"] += count
        return out

    def redact(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_string(value)
        if isinstance(value, list):
            return [self.redact(v) for v in value]
        if isinstance(value, dict):
            return {
                self.redact_string(k) if isinstance(k, str) else k: self.redact(v)
                for k, v in value.items()
            }
        return value


class PrivacyFilter:
    def __init__(
        self,
        model_name: str = "openai/privacy-filter",
        threshold: float = 0.65,
        max_chars: int = 12000,
        selective: bool = True,
    ) -> None:
        try:
            from transformers import pipeline
        except Exception as exc:
            raise SystemExit(
                "Privacy Filter requested, but transformers/torch are not installed. "
                "Use the venv setup described in MANIFEST or run without --privacy-filter."
            ) from exc
        self.threshold = threshold
        self.max_chars = max_chars
        self.selective = selective
        self.cache: dict[str, tuple[str, collections.Counter[str]]] = {}
        self.cue_pattern = re.compile(
            r"(?i)\b("
            r"name is|my name|i am|i'm|address|live at|phone|call me|contact|"
            r"email|e-mail|passport|ssn|social security|dni|nif|cif|"
            r"customer|client|user|usuario|nombre|direcci[oó]n|tel[eé]fono|"
            r"full name|first name|last name|surname|street|city|zip|postcode"
            r")\b"
        )
        self.pipe = pipeline("token-classification", model=model_name, aggregation_strategy="simple")

    def redact(self, text: str) -> tuple[str, collections.Counter[str]]:
        if not text or len(text) > self.max_chars:
            return text, collections.Counter()
        if self.selective and not self.cue_pattern.search(text):
            return text, collections.Counter()
        cached = self.cache.get(text)
        if cached is not None:
            return cached
        try:
            entities = self.pipe(text)
        except Exception:
            return text, collections.Counter({"errors": 1})
        spans: list[tuple[int, int, str]] = []
        counts: collections.Counter[str] = collections.Counter()
        for entity in entities:
            score = float(entity.get("score", 0.0))
            start = entity.get("start")
            end = entity.get("end")
            label = str(entity.get("entity_group") or entity.get("entity") or "PII")
            if start is None or end is None or score < self.threshold or start >= end:
                continue
            spans.append((int(start), int(end), label.upper()))
        if not spans:
            result = (text, counts)
            self.cache[text] = result
            return result
        spans.sort(key=lambda item: (item[0], item[1]))
        merged: list[tuple[int, int, str]] = []
        for start, end, label in spans:
            if merged and start <= merged[-1][1]:
                prev_start, prev_end, prev_label = merged[-1]
                merged[-1] = (prev_start, max(prev_end, end), prev_label)
            else:
                merged.append((start, end, label))
        out = text
        for start, end, label in reversed(merged):
            counts[label] += 1
            out = out[:start] + f"[PII_MODEL:{label}]" + out[end:]
        result = (out, counts)
        self.cache[text] = result
        return result


def redact_relative_path(rel: Path, redactor: Redactor) -> Path:
    parts = []
    for part in rel.parts:
        clean = redactor.redact_string(part)
        clean = clean.replace("/", "_").replace("\\", "_")
        parts.append(clean)
    return Path(*parts)


def write_jsonl_record(path: Path, record: Any) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def redact_jsonl_tree(src: Path, dst: Path, redactor: Redactor) -> dict[str, int]:
    stats = {"files": 0, "lines": 0, "invalid_lines": 0}
    if not src.exists():
        return stats
    for in_file in sorted(src.rglob("*.jsonl")):
        rel = in_file.relative_to(src)
        out_file = dst / redact_relative_path(rel, redactor)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        stats["files"] += 1
        with in_file.open("r", encoding="utf-8", errors="replace") as inp, out_file.open(
            "w", encoding="utf-8"
        ) as out:
            for line in inp:
                stats["lines"] += 1
                stripped = line.rstrip("\n")
                if not stripped:
                    out.write("\n")
                    continue
                try:
                    obj = json.loads(stripped)
                    obj = redactor.redact(obj)
                    out.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
                except json.JSONDecodeError:
                    stats["invalid_lines"] += 1
                    out.write(redactor.redact_string(stripped) + "\n")
    return stats


def redact_jsonl_file(src: Path, dst: Path, redactor: Redactor) -> dict[str, int]:
    stats = {"files": 0, "lines": 0, "invalid_lines": 0}
    if not src.exists():
        return stats
    dst.parent.mkdir(parents=True, exist_ok=True)
    stats["files"] = 1
    with src.open("r", encoding="utf-8", errors="replace") as inp, dst.open(
        "w", encoding="utf-8"
    ) as out:
        for line in inp:
            stats["lines"] += 1
            stripped = line.rstrip("\n")
            if not stripped:
                out.write("\n")
                continue
            try:
                obj = json.loads(stripped)
                obj = redactor.redact(obj)
                out.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
            except json.JSONDecodeError:
                stats["invalid_lines"] += 1
                out.write(redactor.redact_string(stripped) + "\n")
    return stats


def export_opencode(db_path: Path, dst: Path, redactor: Redactor) -> dict[str, Any]:
    stats: dict[str, Any] = {"tables": {}, "skipped_tables": []}
    if not db_path.exists():
        return stats
    dst.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        existing = {
            row["name"]
            for row in conn.execute("select name from sqlite_master where type='table'")
        }
        for table in OPENCODE_TABLES:
            if table not in existing:
                stats["skipped_tables"].append(table)
                continue
            out_file = dst / f"{table}.jsonl"
            count = 0
            with out_file.open("w", encoding="utf-8") as out:
                for row in conn.execute(f'select * from "{table}"'):
                    record = redactor.redact(dict(row))
                    out.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                    count += 1
            stats["tables"][table] = count
    finally:
        conn.close()
    return stats


def copy_manifest_file(src: Path, dst: Path, redactor: Redactor) -> None:
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    text = src.read_text(encoding="utf-8", errors="replace")
    dst.write_text(redactor.redact_string(text), encoding="utf-8")


def final_safety_pass(root: Path, redactor: Redactor) -> dict[str, int]:
    stats = {"files_scanned": 0, "files_changed": 0}
    privacy_filter = redactor.privacy_filter
    redactor.privacy_filter = None
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        stats["files_scanned"] += 1
        if path.suffix == ".jsonl":
            changed = False
            out_lines = []
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    out_lines.append(line)
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    redacted = redactor.redact_string(line)
                    changed = changed or redacted != line
                    out_lines.append(redacted)
                    continue
                redacted_obj = redactor.redact(obj)
                changed = changed or redacted_obj != obj
                out_lines.append(json.dumps(redacted_obj, ensure_ascii=False, separators=(",", ":")))
            if changed:
                path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
                stats["files_changed"] += 1
            continue
        if path.suffix == ".json":
            text = path.read_text(encoding="utf-8", errors="replace")
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                obj = None
            if obj is not None:
                redacted_obj = redactor.redact(obj)
                if redacted_obj != obj:
                    path.write_text(json.dumps(redacted_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                    stats["files_changed"] += 1
                continue
        text = path.read_text(encoding="utf-8", errors="replace")
        redacted = redactor.redact_string(text)
        if redacted != text:
            path.write_text(redacted, encoding="utf-8")
            stats["files_changed"] += 1
    redactor.privacy_filter = privacy_filter
    return stats


def run_gitleaks_scan(root: Path) -> dict[str, Any]:
    local_binary = Path(__file__).resolve().parent / "bin" / "gitleaks"
    binary = shutil.which("gitleaks") or (str(local_binary) if local_binary.exists() else None)
    report_path = Path(__file__).resolve().parent / "gitleaks-final-report.json"
    if binary is None:
        return {"available": False, "status": "skipped", "reason": "gitleaks binary not found"}
    if report_path.exists():
        report_path.unlink()
    cmd = [
        binary,
        "dir",
        str(root),
        "--redact=100",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
    ]
    proc = subprocess.run(cmd, cwd=str(root), text=True, capture_output=True)
    findings = None
    if report_path.exists():
        try:
            findings = len(json.loads(report_path.read_text(encoding="utf-8") or "[]"))
        except Exception:
            findings = None
    return {
        "available": True,
        "status": "clean" if proc.returncode == 0 else "findings_or_error",
        "exit_code": proc.returncode,
        "findings": findings,
        "report": str(report_path),
        "stderr_tail": proc.stderr[-2000:],
    }


def scrub_gitleaks_findings(root: Path, max_rounds: int = 3) -> dict[str, Any]:
    local_binary = Path(__file__).resolve().parent / "bin" / "gitleaks"
    binary = shutil.which("gitleaks") or (str(local_binary) if local_binary.exists() else None)
    if binary is None:
        return {"available": False, "status": "skipped", "reason": "gitleaks binary not found"}
    summary: dict[str, Any] = {"available": True, "rounds": []}
    for round_index in range(1, max_rounds + 1):
        report_path = Path(__file__).resolve().parent / f".gitleaks-fix-round-{round_index}.json"
        if report_path.exists():
            report_path.unlink()
        cmd = [
            binary,
            "dir",
            str(root),
            "--redact=0",
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
        ]
        subprocess.run(cmd, cwd=str(root), text=True, capture_output=True)
        findings = json.loads(report_path.read_text(encoding="utf-8") or "[]") if report_path.exists() else []
        report_path.unlink(missing_ok=True)
        round_summary: dict[str, Any] = {
            "round": round_index,
            "findings": len(findings),
            "files_changed": 0,
            "exact_replacements": 0,
            "records_tombstoned": 0,
            "by_rule": {},
        }
        if not findings:
            summary["rounds"].append(round_summary)
            summary["status"] = "clean"
            return summary
        for item in findings:
            secret = item.get("Secret") or ""
            file_name = item.get("File") or ""
            rule = item.get("RuleID") or "secret"
            path = Path(file_name)
            if not path.exists() or not str(path).startswith(str(root) + "/"):
                continue
            changed = False
            if secret:
                text = path.read_text(encoding="utf-8", errors="ignore")
                placeholder = "[SECRET:GITLEAKS_" + "".join(
                    ch if ch.isalnum() else "_" for ch in rule.upper()
                ) + "]"
                new = text.replace(secret, placeholder)
                if new != text:
                    path.write_text(new, encoding="utf-8")
                    count = text.count(secret)
                    round_summary["files_changed"] += 1
                    round_summary["exact_replacements"] += count
                    round_summary["by_rule"][rule] = round_summary["by_rule"].get(rule, 0) + count
                    changed = True
            if not changed and str(path).endswith(".jsonl"):
                start_line = int(item.get("StartLine") or 0)
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if 1 <= start_line <= len(lines):
                    try:
                        old = json.loads(lines[start_line - 1])
                        record_type = old.get("type", "redacted_record") if isinstance(old, dict) else "redacted_record"
                    except Exception:
                        record_type = "redacted_record"
                    lines[start_line - 1] = json.dumps(
                        {
                            "type": record_type,
                            "redacted": True,
                            "redaction_reason": "gitleaks_" + rule,
                        },
                        separators=(",", ":"),
                    )
                    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    round_summary["files_changed"] += 1
                    round_summary["records_tombstoned"] += 1
                    round_summary["by_rule"][rule] = round_summary["by_rule"].get(rule, 0) + 1
        summary["rounds"].append(round_summary)
    summary["status"] = "max_rounds_reached"
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Export raw agent traces with in-place redaction.")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--user-name", default=os.environ.get("USER") or Path.home().name)
    parser.add_argument("--home-dir", type=Path, default=Path.home())
    parser.add_argument("--private-domain", action="append", default=[], help="Private domain to redact, including subdomains. Can be repeated.")
    parser.add_argument("--private-term", action="append", default=[], help="Private person/location/project/device term to redact. Can be repeated.")
    parser.add_argument("--force", action="store_true", help="Replace an existing output directory.")
    parser.add_argument("--privacy-filter", action="store_true", help="Run openai/privacy-filter on short string fields.")
    parser.add_argument("--privacy-filter-threshold", type=float, default=0.65)
    parser.add_argument("--privacy-filter-max-chars", type=int, default=12000)
    parser.add_argument("--privacy-filter-all-strings", action="store_true", help="Send all eligible strings to the model instead of only likely PII candidates.")
    parser.add_argument("--gitleaks", action="store_true", help="Run gitleaks dir scan after export if installed.")
    parser.add_argument("--gitleaks-fix", action="store_true", help="Use gitleaks findings to scrub exact candidate strings before the final scan.")
    args = parser.parse_args()

    if args.out.exists():
        if not args.force:
            raise SystemExit(f"Output exists: {args.out}. Use --force to replace it.")
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True)

    privacy_filter = (
        PrivacyFilter(
            threshold=args.privacy_filter_threshold,
            max_chars=args.privacy_filter_max_chars,
            selective=not args.privacy_filter_all_strings,
        )
        if args.privacy_filter
        else None
    )
    redactor = Redactor(
        privacy_filter=privacy_filter,
        user_name=args.user_name,
        home_dir=args.home_dir,
        private_domains=args.private_domain,
        private_terms=args.private_term,
    )
    report: dict[str, Any] = {
        "format": "raw-preserving-redacted-agent-traces-v1",
        "options": {
            "privacy_filter": args.privacy_filter,
            "privacy_filter_threshold": args.privacy_filter_threshold,
            "privacy_filter_max_chars": args.privacy_filter_max_chars,
            "privacy_filter_selective": not args.privacy_filter_all_strings,
            "gitleaks": args.gitleaks,
            "gitleaks_fix": args.gitleaks_fix,
        },
        "sources": {},
        "excluded": {
            "opencode_tables": [
                "account",
                "account_state",
                "control_account",
                "credential",
                "data_migration",
                "migration",
                "__drizzle_migrations",
                "sqlite_sequence",
            ],
            "reason": "Non-trace operational/auth tables are excluded from the raw trace export.",
        },
    }

    report["sources"]["codex_sessions"] = redact_jsonl_tree(
        args.root / ".codex" / "sessions",
        args.out / "codex" / "sessions",
        redactor,
    )
    report["sources"]["codex_history"] = redact_jsonl_file(
        args.root / ".codex" / "history.jsonl",
        args.out / "codex" / "history.jsonl",
        redactor,
    )

    report["sources"]["pi_sessions"] = redact_jsonl_tree(
        args.root / ".pi" / "agent" / "sessions",
        args.out / "pi" / "agent" / "sessions",
        redactor,
    )
    report["sources"]["opencode"] = export_opencode(
        args.root / ".local" / "share" / "opencode" / "opencode.db",
        args.out / "opencode",
        redactor,
    )

    manifest = {
        "notes": [
            "Raw framework shapes are preserved as JSONL event streams or SQLite table JSONL exports.",
            "Secrets and PII are replaced with typed placeholders.",
            "Review REDACTION_REPORT.json and run independent scans before publication.",
            "Optional: run with --privacy-filter from a venv containing transformers and torch.",
            "Optional: run with --gitleaks after installing gitleaks for an independent secret scan.",
        ],
        "sources": report["sources"],
    }
    (args.out / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    report["final_safety_pass"] = final_safety_pass(args.out, redactor)
    if args.gitleaks_fix:
        report["gitleaks_fix"] = scrub_gitleaks_findings(args.out)
    if args.gitleaks:
        report["gitleaks"] = run_gitleaks_scan(args.out)
    report["redaction_counts"] = dict(redactor.counts)
    report["stable_placeholder_counts"] = {k: len(v) for k, v in redactor.maps.items()}
    (args.out / "REDACTION_REPORT.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
