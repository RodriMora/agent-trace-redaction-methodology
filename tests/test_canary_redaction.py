import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EXPORTER = REPO / "scripts" / "export_redacted_traces.py"
SCANNER = REPO / "scripts" / "scan_redacted_output.py"


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


class CanaryRedactionTest(unittest.TestCase):
    def test_end_to_end_canaries_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            out = Path(td) / "out"
            write_jsonl(root / ".codex" / "history.jsonl", [
                {
                    "type": "history",
                    "text": "Alice used sk-proj-abcdefghijklmnopqrstuvwxyz at alice@example.test from /home/alice/private and https://private.example.test/path",
                    "encrypted_content": "gAAAAABabcdefghijklmnopqrstuvwxyz0123456789",
                    "thinkingSignature": "{\"encrypted_content\":\"gAAAAABabcdefghijklmnopqrstuvwxyz0123456789\"}",
                    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM alice@host",
                }
            ])
            write_jsonl(root / ".codex" / "sessions" / "2026" / "01" / "01" / "session.jsonl", [
                {
                    "type": "message",
                    "payload": {
                        "content": "Call me +1 415 555 1212, share https://opncd.ai/share/abc123XYZ, cwd --home-alice-secret-project--",
                        "apiKey": "not-a-real-secret-but-sensitive-field",
                        "share_url": "https://opncd.ai/share/abc123XYZ",
                    },
                }
            ])
            write_jsonl(root / ".pi" / "agent" / "sessions" / "--home-alice-secret-project--" / "pi.jsonl", [
                {"type": "message", "message": {"role": "user", "content": "alice@workstation in /home/alice/project"}}
            ])

            db = root / ".local" / "share" / "opencode" / "opencode.db"
            db.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db)
            conn.execute('create table "session" (id text, directory text, share_url text, title text)')
            conn.execute('insert into "session" values (?,?,?,?)', (
                "ses_123",
                "/home/alice/private-project",
                "https://opncd.ai/share/abc123XYZ",
                "Alice private task",
            ))
            conn.execute('create table "session_share" (id text, secret text, url text)')
            conn.execute('insert into "session_share" values (?,?,?)', ("abc123XYZ", "secret", "https://opncd.ai/share/abc123XYZ"))
            conn.commit()
            conn.close()

            subprocess.run([
                sys.executable,
                str(EXPORTER),
                "--root", str(root),
                "--out", str(out),
                "--user-name", "alice",
                "--home-dir", "/home/alice",
                "--no-auto-discover",
                "--force",
            ], check=True, cwd=str(REPO))

            self.assertFalse((out / "opencode" / "session_share.jsonl").exists())
            scan = subprocess.run([
                sys.executable,
                str(SCANNER),
                "--root", str(out),
                "--user-name", "alice",
                "--home-dir", "/home/alice",
            ], text=True, capture_output=True, cwd=str(REPO))
            self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)


if __name__ == "__main__":
    unittest.main()
