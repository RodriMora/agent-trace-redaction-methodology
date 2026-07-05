#!/usr/bin/env python3
import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import socket
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
    "session_input",
    "message",
    "part",
    "event",
    "event_sequence",
    "permission",
    "todo",
]

# OpenCode auth/share tables are excluded by default. session_share contains share
# IDs, URLs, and secrets that are operational metadata rather than trace content.
OPENCODE_EXCLUDED_TABLES = [
    "account",
    "account_state",
    "control_account",
    "credential",
    "data_migration",
    "migration",
    "__drizzle_migrations",
    "sqlite_sequence",
    "session_share",
]

SENSITIVE_FIELD_EXACT = {
    "authorization",
    "cookie",
    "setcookie",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "privatekey",
    "private_key",
    "credential",
    "credentials",
    "encryptedcontent",
    "encrypted_content",
    "thinkingsignature",
    "thinking_signature",
    "signature",
    "shareurl",
    "share_url",
}

SENSITIVE_FIELD_SUBSTRINGS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "credential",
    "encrypted_content",
    "encryptedcontent",
    "password",
    "private_key",
    "privatekey",
    "refresh_token",
    "secret",
    "session_secret",
    "share_url",
    "shareurl",
    "thinking_signature",
    "thinkingsignature",
)

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


def normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")


def run_text(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def discover_private_terms(root: Path, user_name: str, home_dir: Path) -> list[str]:
    terms: set[str] = set()
    for value in {user_name, home_dir.name, os.environ.get("USER", ""), os.environ.get("LOGNAME", "")}:
        if value and len(value) >= 3:
            terms.add(value)
    hostname = socket.gethostname().split(".", 1)[0]
    if hostname and len(hostname) >= 3 and hostname not in {"localhost"}:
        terms.add(hostname)
    git_name = run_text(["git", "config", "--global", "user.name"])
    if git_name and len(git_name) >= 3:
        terms.add(git_name)
    git_email = run_text(["git", "config", "--global", "user.email"])
    if git_email:
        local = git_email.split("@", 1)[0]
        if len(local) >= 3:
            terms.add(local)
    ssh_config = root / ".ssh" / "config"
    if ssh_config.exists():
        for line in ssh_config.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped.lower().startswith("host "):
                continue
            for alias in stripped.split()[1:]:
                if "*" not in alias and "?" not in alias and len(alias) >= 3:
                    terms.add(alias)
    return sorted(terms, key=lambda item: (-len(item), item.lower()))


class Redactor:
    def __init__(
        self,
        privacy_filter: "PrivacyFilter | None" = None,
        user_name: str | None = None,
        home_dir: Path | None = None,
        private_domains: list[str] | None = None,
        private_terms: list[str] | None = None,
        allow_public_urls: bool = False,
        allowed_domains: list[str] | None = None,
    ) -> None:
        self.counts: collections.Counter[str] = collections.Counter()
        self.maps: dict[str, dict[str, str]] = collections.defaultdict(dict)
        self.privacy_filter = privacy_filter
        self.user_name = user_name or os.environ.get("USER") or Path.home().name
        self.home_dir = home_dir or Path.home()
        self.allow_public_urls = allow_public_urls
        self.allowed_domains = set(DEFAULT_PUBLIC_URL_ALLOWLIST if allow_public_urls else set())
        self.allowed_domains.update(domain.lower().lstrip(".") for domain in (allowed_domains or []))
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
            term_pattern = r"(?i)(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(term) for term in private_terms) + r")(?![A-Za-z0-9_])"
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
                "pi_encoded_path_component",
                re.compile(r"(?<![A-Za-z0-9_-])--(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]{3,}--(?![A-Za-z0-9_-])"),
                None,
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
            (
                "env_secret_default",
                re.compile(
                    r"(?i)([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDS[_-]?(?:KEY|IV))[A-Z0-9_]*\s*:\s*\$\{[^}:]+:-)([^}\s]{8,})"
                ),
                r"\1[SECRET:ENV_DEFAULT]",
            ),
            ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"), "[SECRET:OPENAI_API_KEY]"),
            ("short_sk_key", re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b"), "[SECRET:API_KEY_FIELD]"),
            ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "[SECRET:ANTHROPIC_API_KEY]"),
            ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[SECRET:GITHUB_TOKEN]"),
            ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "[SECRET:HUGGINGFACE_TOKEN]"),
            ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "[SECRET:GOOGLE_API_KEY]"),
            ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"), "[SECRET:AWS_ACCESS_KEY]"),
            ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[SECRET:JWT]"),
            ("ssh_public_key", re.compile(r"\bssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/=]{40,}(?:\s+[^\s'\"<>`]+)?"), "[SECRET:SSH_PUBLIC_KEY]"),
            ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), "[PII:IBAN]"),
            (
                "quicktime_location_iso6709",
                re.compile(r"(?i)(com\.apple\.quicktime\.location\.ISO6709\s*:\s*)[+-]\d{2,3}\.\d{3,}[+-]\d{2,3}\.\d{3,}(?:[+-]\d+(?:\.\d+)?)?/"),
                r"\1[PII:GPS_COORDINATES]",
            ),
            (
                "quicktime_location_accuracy",
                re.compile(r"(?i)(com\.apple\.quicktime\.location\.accuracy\.horizontal\s*:\s*)\d+(?:\.\d+)?"),
                r"\1[PII:LOCATION_ACCURACY]",
            ),
            ("iso6709_coordinates", re.compile(r"(?<![A-Za-z0-9_.])[+-]\d{2,3}\.\d{3,}[+-]\d{2,3}\.\d{3,}(?:[+-]\d+(?:\.\d+)?)?/"), "[PII:GPS_COORDINATES]"),
            ("latlon_coordinates", re.compile(r"\b-?\d{1,2}\.\d{5,}\s*,\s*-?\d{1,3}\.\d{5,}\b"), "[PII:GPS_COORDINATES]"),
            ("street_address", re.compile(r"\b\d{1,6}\s+(?:[A-Z][A-Za-z0-9.'-]+\s+){1,5}(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Court|Ct\.?|Place|Pl\.?)\b"), "[PII:STREET_ADDRESS]"),
            ("ipv6", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"), "[PII:IPV6_ADDRESS]"),
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
                "opencode_share_url",
                re.compile(r"\bhttps?://(?:www\.)?opncd\.ai/share/[^\s'\"<>`)}\]]+", re.I),
                "[PRIVATE_SHARE_URL]",
            ),
            (
                "private_url",
                re.compile(r"\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)[^\s'\"<>`]*", re.I),
                "[PRIVATE_URL]",
            ),
            ("url", re.compile(r"\bhttps?://[^\s'\"<>`)}\]]+", re.I), None),
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
            (
                "contextual_phone",
                re.compile(r"(?i)\b((?:phone|tel|mobile|call me|telefono|tel[eé]fono)\s*[:=]?\s*)(?:\+?\d[\d .()/-]{7,}\d)"),
                r"\1[PII:PHONE]",
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
        ]

    def stable(self, category: str, value: str) -> str:
        bucket = self.maps[category]
        if value not in bucket:
            digest = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:10]
            bucket[value] = f"[{category.upper()}:{len(bucket) + 1:04d}:{digest}]"
        return bucket[value]

    def is_allowed_url(self, value: str) -> bool:
        if not self.allowed_domains:
            return False
        match = re.match(r"(?i)^https?://([^/:?#]+)", value)
        if not match:
            return False
        host = match.group(1).lower().rstrip(".")
        return any(host == domain or host.endswith("." + domain) for domain in self.allowed_domains)

    def sensitive_field_category(self, key: str) -> str | None:
        normalized = normalize_key(key)
        compact = normalized.replace("_", "")
        if normalized in SENSITIVE_FIELD_EXACT or compact in SENSITIVE_FIELD_EXACT:
            return "FIELD"
        if any(fragment in normalized or fragment in compact for fragment in SENSITIVE_FIELD_SUBSTRINGS):
            return "FIELD"
        return None

    def redact_sensitive_field(self, key: str, value: Any) -> Any:
        category = self.sensitive_field_category(key)
        if category is None:
            return self.redact(value)
        self.counts["sensitive_field_" + normalize_key(key)] += 1
        if value is None or isinstance(value, (int, float, bool)):
            return value
        if isinstance(value, (dict, list)):
            return "[REDACTED:SENSITIVE_FIELD]"
        if re.search(r"(?i)encrypted|signature", key):
            return "[REDACTED:OPAQUE_PROVIDER_BLOB]"
        if re.search(r"(?i)share", key):
            return "[REDACTED:SHARE_METADATA]"
        return "[REDACTED:SENSITIVE_FIELD]"

    def redact_string(self, value: str) -> str:
        out = value
        for category, pattern, replacement in self.patterns:
            def repl(match: re.Match[str]) -> str:
                if category == "url" and self.is_allowed_url(match.group(0)):
                    return match.group(0)
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
            redacted: dict[Any, Any] = {}
            for key, item in value.items():
                new_key = self.redact_string(key) if isinstance(key, str) else key
                if isinstance(key, str):
                    redacted[new_key] = self.redact_sensitive_field(key, item)
                else:
                    redacted[new_key] = self.redact(item)
            return redacted
        return value


class PrivacyFilter:
    def __init__(
        self,
        model_name: str = "openai/privacy-filter",
        threshold: float = 0.65,
        max_chars: int = 12000,
        selective: bool = True,
        device: str = "auto",
    ) -> None:
        try:
            import torch
            from transformers import pipeline
        except Exception as exc:
            raise SystemExit(
                "Privacy Filter requested, but transformers/torch are not installed. "
                "Use the venv setup described in MANIFEST or run without --privacy-filter."
            ) from exc
        self.threshold = threshold
        self.max_chars = max_chars
        self.selective = selective
        self.requested_device = device
        self.pipeline_device, self.device_description = self.resolve_device(torch, device)
        self.cache: dict[str, tuple[str, collections.Counter[str]]] = {}
        self.cue_pattern = re.compile(
            r"(?i)\b("
            r"name is|my name|i am|i'm|address|live at|phone|call me|contact|"
            r"email|e-mail|passport|ssn|social security|dni|nif|cif|"
            r"customer|client|user|usuario|nombre|direcci[oó]n|tel[eé]fono|"
            r"full name|first name|last name|surname|street|city|zip|postcode"
            r")\b"
        )
        self.pipe = pipeline(
            "token-classification",
            model=model_name,
            aggregation_strategy="simple",
            device=self.pipeline_device,
        )

    @staticmethod
    def resolve_device(torch: Any, requested: str) -> tuple[int, str]:
        normalized = requested.lower().strip()
        if normalized in {"cpu", "-1"}:
            return -1, "cpu"
        if normalized.startswith("cuda") or normalized in {"gpu", "nvidia"}:
            if not torch.cuda.is_available():
                raise SystemExit("--privacy-filter-device requested CUDA/NVIDIA, but torch.cuda.is_available() is false.")
            index = 0
            if ":" in normalized:
                try:
                    index = int(normalized.rsplit(":", 1)[1])
                except ValueError as exc:
                    raise SystemExit(f"Invalid CUDA device: {requested}") from exc
            return index, f"cuda:{index} ({torch.cuda.get_device_name(index)})"
        if normalized != "auto":
            raise SystemExit("--privacy-filter-device must be one of: auto, cpu, cuda, cuda:N")
        if torch.cuda.is_available():
            return 0, f"cuda:0 ({torch.cuda.get_device_name(0)})"
        return -1, "cpu"

    def should_process(self, text: str) -> bool:
        if not text or len(text) > self.max_chars:
            return False
        return not (self.selective and not self.cue_pattern.search(text))

    def redact_from_entities(self, text: str, entities: Any) -> tuple[str, collections.Counter[str]]:
        spans: list[tuple[int, int, str]] = []
        counts: collections.Counter[str] = collections.Counter()
        for entity in entities or []:
            score = float(entity.get("score", 0.0))
            start = entity.get("start")
            end = entity.get("end")
            label = str(entity.get("entity_group") or entity.get("entity") or "PII")
            if start is None or end is None or score < self.threshold or start >= end:
                continue
            spans.append((int(start), int(end), label.upper()))
        if not spans:
            return text, counts
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
        return out, counts

    def redact(self, text: str) -> tuple[str, collections.Counter[str]]:
        if not self.should_process(text):
            return text, collections.Counter()
        cached = self.cache.get(text)
        if cached is not None:
            return cached
        try:
            entities = self.pipe(text)
        except Exception:
            return text, collections.Counter({"errors": 1})
        result = self.redact_from_entities(text, entities)
        self.cache[text] = result
        return result

    def redact_many(self, texts: list[str], batch_size: int = 64) -> dict[str, tuple[str, collections.Counter[str]]]:
        unique = []
        seen = set()
        for text in texts:
            if text in seen or text in self.cache or not self.should_process(text):
                continue
            seen.add(text)
            unique.append(text)
        for start in range(0, len(unique), batch_size):
            batch = unique[start:start + batch_size]
            try:
                outputs = self.pipe(batch, batch_size=batch_size)
            except Exception:
                for text in batch:
                    try:
                        self.cache[text] = self.redact_from_entities(text, self.pipe(text))
                    except Exception:
                        self.cache[text] = (text, collections.Counter({"errors": 1}))
                continue
            if len(batch) == 1 and (not outputs or isinstance(outputs[0], dict)):
                outputs = [outputs]
            for text, entities in zip(batch, outputs):
                self.cache[text] = self.redact_from_entities(text, entities)
        return {text: self.cache[text] for text in texts if text in self.cache}


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


def iter_string_values(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, str):
        values.append(value)
    elif isinstance(value, list):
        for item in value:
            values.extend(iter_string_values(item))
    elif isinstance(value, dict):
        for item in value.values():
            values.extend(iter_string_values(item))
    return values


def apply_string_mapping(value: Any, mapping: dict[str, str]) -> tuple[Any, bool]:
    if isinstance(value, str):
        new = mapping.get(value, value)
        return new, new != value
    if isinstance(value, list):
        changed = False
        items = []
        for item in value:
            new_item, item_changed = apply_string_mapping(item, mapping)
            items.append(new_item)
            changed = changed or item_changed
        return items, changed
    if isinstance(value, dict):
        changed = False
        obj = {}
        for key, item in value.items():
            new_item, item_changed = apply_string_mapping(item, mapping)
            obj[key] = new_item
            changed = changed or item_changed
        return obj, changed
    return value, False


def privacy_filter_batch_pass(root: Path, privacy_filter: PrivacyFilter, redactor: Redactor, batch_size: int = 64) -> dict[str, int]:
    stats = {"files_scanned": 0, "files_changed": 0, "strings_reviewed": 0, "strings_changed": 0}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".jsonl", ".json"}:
            continue
        stats["files_scanned"] += 1
        if path.suffix == ".jsonl":
            records: list[Any] = []
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            candidates: list[str] = []
            for line in raw_lines:
                if not line.strip():
                    records.append(None)
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    records.append(line)
                    if privacy_filter.should_process(line):
                        candidates.append(line)
                    continue
                records.append(obj)
                candidates.extend(text for text in iter_string_values(obj) if privacy_filter.should_process(text))
            results = privacy_filter.redact_many(candidates, batch_size=batch_size)
            mapping = {text: redacted for text, (redacted, _) in results.items() if redacted != text}
            stats["strings_reviewed"] += len(results)
            stats["strings_changed"] += len(mapping)
            if not mapping:
                continue
            out_lines = []
            changed = False
            for record in records:
                if record is None:
                    out_lines.append("")
                elif isinstance(record, str):
                    new = mapping.get(record, record)
                    changed = changed or new != record
                    out_lines.append(new)
                else:
                    new_obj, item_changed = apply_string_mapping(record, mapping)
                    changed = changed or item_changed
                    out_lines.append(json.dumps(new_obj, ensure_ascii=False, separators=(",", ":")))
            if changed:
                path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
                stats["files_changed"] += 1
            continue
        try:
            obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        candidates = [text for text in iter_string_values(obj) if privacy_filter.should_process(text)]
        results = privacy_filter.redact_many(candidates, batch_size=batch_size)
        mapping = {text: redacted for text, (redacted, _) in results.items() if redacted != text}
        stats["strings_reviewed"] += len(results)
        stats["strings_changed"] += len(mapping)
        if not mapping:
            continue
        new_obj, changed = apply_string_mapping(obj, mapping)
        if changed:
            path.write_text(json.dumps(new_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            stats["files_changed"] += 1
    for _text, (_redacted, spans) in privacy_filter.cache.items():
        for label, count in spans.items():
            redactor.counts[f"privacy_filter_{label}"] += count
    return stats


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
    legacy_binary = Path.home() / "dev" / "agent-trace-redaction" / "bin" / "gitleaks"
    binary = shutil.which("gitleaks") or (str(local_binary) if local_binary.exists() else (str(legacy_binary) if legacy_binary.exists() else None))
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
    legacy_binary = Path.home() / "dev" / "agent-trace-redaction" / "bin" / "gitleaks"
    binary = shutil.which("gitleaks") or (str(local_binary) if local_binary.exists() else (str(legacy_binary) if legacy_binary.exists() else None))
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
    parser.add_argument("--private-domain", action="append", default=[], help="Additional private domain to redact, including subdomains. Can be repeated.")
    parser.add_argument("--private-term", action="append", default=[], help="Additional private person/location/project/device term to redact. Can be repeated.")
    parser.add_argument("--no-auto-discover", action="store_true", help="Disable zero-config discovery of local usernames, hostnames, git identity, and SSH aliases.")
    parser.add_argument("--allow-public-urls", action="store_true", help="Preserve a small built-in allowlist of public documentation/package URLs. Default redacts every URL.")
    parser.add_argument("--allow-domain", action="append", default=[], help="Domain whose URLs may be preserved when --allow-public-urls is set. Can be repeated.")
    parser.add_argument("--force", action="store_true", help="Replace an existing output directory.")
    parser.add_argument("--privacy-filter", action="store_true", help="Run openai/privacy-filter on short string fields.")
    parser.add_argument("--privacy-filter-threshold", type=float, default=0.65)
    parser.add_argument("--privacy-filter-max-chars", type=int, default=12000)
    parser.add_argument("--privacy-filter-device", default="auto", help="Device for openai/privacy-filter: auto, cpu, cuda, or cuda:N. Auto uses NVIDIA/CUDA when available.")
    parser.add_argument("--privacy-filter-batch-size", type=int, default=64, help="Batch size for the openai/privacy-filter pass.")
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
            device=args.privacy_filter_device,
        )
        if args.privacy_filter
        else None
    )
    auto_terms = [] if args.no_auto_discover else discover_private_terms(args.root, args.user_name, args.home_dir)
    redactor = Redactor(
        privacy_filter=None,
        user_name=args.user_name,
        home_dir=args.home_dir,
        private_domains=args.private_domain,
        private_terms=sorted(set(args.private_term + auto_terms), key=lambda item: (-len(item), item.lower())),
        allow_public_urls=args.allow_public_urls,
        allowed_domains=args.allow_domain,
    )
    report: dict[str, Any] = {
        "format": "raw-preserving-redacted-agent-traces-v1",
        "options": {
            "privacy_filter": args.privacy_filter,
            "privacy_filter_threshold": args.privacy_filter_threshold,
            "privacy_filter_max_chars": args.privacy_filter_max_chars,
            "privacy_filter_device_requested": args.privacy_filter_device,
            "privacy_filter_device_resolved": privacy_filter.device_description if privacy_filter else None,
            "privacy_filter_batch_size": args.privacy_filter_batch_size,
            "privacy_filter_selective": not args.privacy_filter_all_strings,
            "gitleaks": args.gitleaks,
            "gitleaks_fix": args.gitleaks_fix,
            "auto_discover": not args.no_auto_discover,
            "allow_public_urls": args.allow_public_urls,
            "allow_domains": args.allow_domain,
        },
        "sources": {},
        "excluded": {
            "opencode_tables": OPENCODE_EXCLUDED_TABLES,
            "reason": "Non-trace operational/auth/share tables are excluded from the raw trace export.",
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
            "By default all URLs, share metadata, opaque provider blobs, local paths, and discovered local identities are redacted.",
        ],
        "sources": report["sources"],
    }
    (args.out / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    if privacy_filter is not None:
        report["privacy_filter_batch_pass"] = privacy_filter_batch_pass(args.out, privacy_filter, redactor, batch_size=args.privacy_filter_batch_size)
    report["final_safety_pass"] = final_safety_pass(args.out, redactor)
    if args.gitleaks_fix:
        report["gitleaks_fix"] = scrub_gitleaks_findings(args.out)
    if args.gitleaks:
        report["gitleaks"] = run_gitleaks_scan(args.out)
    report["redaction_counts"] = dict(redactor.counts)
    report["stable_placeholder_counts"] = {k: len(v) for k, v in redactor.maps.items()}
    (args.out / "REDACTION_REPORT.json").write_text(
        json.dumps(redactor.redact(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    # The report is generated after the main passes and may contain paths, URLs, or
    # command tails. Scrub the complete artifact one last time, including the report.
    final_safety_pass(args.out, redactor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
