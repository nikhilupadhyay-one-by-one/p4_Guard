#!/usr/bin/env python3
"""Guard: simple file-integrity monitoring in one self-contained Python file.

Read this file from top to bottom. The program follows one flow:

    settings -> fingerprints -> SQLite -> severity rules -> burst detection
             -> filesystem watcher -> dashboard / terminal / CLI

The dashboard HTML is embedded below, so app.py is the only application file.
Python 3.10+ is required. The only third-party dependency is watchdog.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import queue
import sqlite3
import stat
import sys
import threading
import time
import webbrowser
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except ImportError:  # Baseline and audit still work without the watcher dependency.
    WATCHDOG_AVAILABLE = False

    class FileSystemEventHandler:  # type: ignore[no-redef]
        """Small fallback so the non-watching commands remain usable."""

    Observer = None  # type: ignore[assignment,misc]


APP_NAME = "Guard"
__version__ = "3.0.0"

# Severity is ordered from least to most serious. Use this map for sorting/filtering.
INFO, NOTICE, WARNING, CRITICAL = "info", "notice", "warning", "critical"
SEVERITY_RANK = {INFO: 0, NOTICE: 1, WARNING: 2, CRITICAL: 3}

DEFAULT_IGNORE = [
    "guard.db", "guard.db-wal", "guard.db-shm", ".git", ".hg", ".svn",
    "__pycache__", "*.pyc", "*.pyo", "node_modules", ".venv", "venv", "env",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox", ".idea", ".vscode",
    ".DS_Store", "Thumbs.db", "*.swp", "*.swx", "*~", "~$*", "*.tmp", "*.temp",
    "*.part", "*.crdownload",
]

SENSITIVE_GLOBS = [
    "*/.ssh/*", "*/authorized_keys", "*/known_hosts", "*/.aws/credentials",
    "*/.kube/config", "*/.docker/config.json", "*.pem", "*.key", "*.p12", "*.pfx",
    "*.keystore", "*.jks", "*/.env", "*/.env.*", "*/.netrc", "*/.npmrc",
    "*/.pypirc", "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
    "*/crontab", "*/cron.d/*",
]

EXECUTABLE_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".msi", ".com", ".scr", ".sh", ".bash",
    ".zsh", ".bat", ".cmd", ".ps1", ".vbs", ".jar",
}

ALREADY_COMPRESSED = {
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".tgz", ".zst",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".avif", ".mp3", ".mp4",
    ".mkv", ".mov", ".avi", ".flac", ".ogg", ".webm", ".pdf", ".docx", ".xlsx",
    ".pptx", ".odt", ".whl", ".jar", ".apk", ".woff", ".woff2",
}

CONFIG_SUFFIXES = {
    ".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".toml", ".xml",
    ".plist", ".properties", ".htaccess",
}


# ---------------------------------------------------------------------------
# 1. Settings and fingerprints
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    """All configurable behaviour for one watched folder."""

    root: Path
    db_path: Path = Path("guard.db")
    quiet_period: float = 0.4
    max_hash_bytes: int = 256 * 1024 * 1024
    entropy_sample: int = 256 * 1024
    ignore: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE))
    sensitive: list[str] = field(default_factory=lambda: list(SENSITIVE_GLOBS))
    burst_threshold: int = 20
    burst_window: float = 30.0
    entropy_floor: float = 7.2

    def is_ignored(self, path: Path) -> bool:
        """Match an ignore rule against the relative path or any path component."""
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            relative = path

        text = relative.as_posix()
        return any(
            fnmatch(text, pattern) or any(fnmatch(part, pattern) for part in relative.parts)
            for pattern in self.ignore
        )

    def is_sensitive(self, path: Path) -> bool:
        return any(fnmatch(path.as_posix(), pattern) for pattern in self.sensitive)


@dataclass
class Fingerprint:
    """A compact description of file content and permissions at one moment."""

    size: int
    sha256: str
    mode: int
    mtime: float
    entropy: float

    @property
    def short_hash(self) -> str:
        return self.sha256[:12] if self.sha256 else "—"

    @property
    def is_executable(self) -> bool:
        return bool(self.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    @property
    def permissions(self) -> str:
        return stat.filemode(self.mode)[1:]


def shannon_entropy(data: bytes) -> float:
    """Return byte entropy (0 to 8 bits); encrypted data tends toward 8."""
    if not data:
        return 0.0
    length = len(data)
    value = -sum((count / length) * math.log2(count / length) for count in Counter(data).values())
    return value if value else 0.0  # Avoid displaying negative zero.


def fingerprint(path: Path, settings: Settings) -> Fingerprint | None:
    """Hash a regular file and sample its entropy; return None if unavailable."""
    try:
        info = path.stat()
    except (OSError, ValueError):
        return None

    if not stat.S_ISREG(info.st_mode):
        return None

    digest, entropy = "", 0.0
    if info.st_size <= settings.max_hash_bytes:
        hasher = hashlib.sha256()
        sample = bytearray()
        try:
            with path.open("rb") as file:
                while chunk := file.read(64 * 1024):
                    hasher.update(chunk)
                    remaining = settings.entropy_sample - len(sample)
                    if remaining > 0:
                        sample.extend(chunk[:remaining])
        except OSError:
            return None
        digest = hasher.hexdigest()
        entropy = shannon_entropy(bytes(sample))

    return Fingerprint(info.st_size, digest, stat.S_IMODE(info.st_mode), info.st_mtime, entropy)


# ---------------------------------------------------------------------------
# 2. SQLite storage (the table layout is compatible with the original V2 DB)
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
    mode INTEGER NOT NULL, mtime REAL NOT NULL, entropy REAL NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, path TEXT NOT NULL,
    action TEXT NOT NULL, severity TEXT NOT NULL, reason TEXT NOT NULL,
    old_hash TEXT, new_hash TEXT, size_before INTEGER, size_after INTEGER, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Change:
    """A verified file event, with a plain-language explanation."""

    ts: str
    path: str
    action: str
    severity: str
    reason: str
    before: Fingerprint | None = None
    after: Fingerprint | None = None
    detail: str | None = None

    @property
    def size_delta(self) -> int:
        return (self.after.size if self.after else 0) - (self.before.size if self.before else 0)

    def as_dict(self) -> dict:
        return {
            "ts": self.ts, "path": self.path, "action": self.action,
            "severity": self.severity, "reason": self.reason,
            "old_hash": self.before.sha256 if self.before else None,
            "new_hash": self.after.sha256 if self.after else None,
            "size_before": self.before.size if self.before else None,
            "size_after": self.after.size if self.after else None, "detail": self.detail,
        }


class Database:
    """Own the SQLite connection and keep every database operation in one place."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._closed = False
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def get_file(self, path: str) -> Fingerprint | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT size, sha256, mode, mtime, entropy FROM files WHERE path = ?", (path,)
            ).fetchone()
        return Fingerprint(row["size"], row["sha256"], row["mode"], row["mtime"], row["entropy"]) if row else None

    def put_file(self, path: str, measured: Fingerprint) -> None:
        now = timestamp()
        with self._lock:
            self._conn.execute(
                """INSERT INTO files(path,size,sha256,mode,mtime,entropy,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(path) DO UPDATE SET size=excluded.size,sha256=excluded.sha256,
                   mode=excluded.mode,mtime=excluded.mtime,entropy=excluded.entropy,last_seen=excluded.last_seen""",
                (path, measured.size, measured.sha256, measured.mode, measured.mtime,
                 measured.entropy, now, now),
            )
            self._conn.commit()

    def drop_file(self, path: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM files WHERE path = ?", (path,))
            self._conn.commit()

    def tracked_files(self) -> dict[str, Fingerprint]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT path,size,sha256,mode,mtime,entropy FROM files"
            ).fetchall()
        return {
            row["path"]: Fingerprint(row["size"], row["sha256"], row["mode"], row["mtime"], row["entropy"])
            for row in rows
        }

    def file_count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM files").fetchone()[0])

    def add_event(self, change: Change) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """INSERT INTO events(ts,path,action,severity,reason,old_hash,new_hash,
                   size_before,size_after,detail) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (change.ts, change.path, change.action, change.severity, change.reason,
                 change.before.sha256 if change.before else None,
                 change.after.sha256 if change.after else None,
                 change.before.size if change.before else None,
                 change.after.size if change.after else None, change.detail),
            )
            self._conn.commit()
            return int(cursor.lastrowid or 0)

    def events_since(self, event_id: int, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?", (event_id, limit)
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_events(self, limit: int = 50, severity: str | None = None,
                      path_like: str | None = None) -> list[dict]:
        conditions, values = [], []
        if severity:
            allowed = [name for name, rank in SEVERITY_RANK.items() if rank >= SEVERITY_RANK[severity]]
            conditions.append(f"severity IN ({','.join('?' for _ in allowed)})")
            values.extend(allowed)
        if path_like:
            conditions.append("path LIKE ?")
            values.append(f"%{path_like}%")
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        values.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM events{where} ORDER BY id DESC LIMIT ?", values
            ).fetchall()
        return [dict(row) for row in rows]

    def severity_counts(self, since: str | None = None) -> dict[str, int]:
        query, values = "SELECT severity,COUNT(*) AS n FROM events", []
        if since:
            query += " WHERE ts >= ?"
            values.append(since)
        query += " GROUP BY severity"
        with self._lock:
            rows = self._conn.execute(query, values).fetchall()
        result = dict.fromkeys(SEVERITY_RANK, 0)
        for row in rows:
            result[row["severity"]] = row["n"]
        return result

    def busiest_paths(self, limit: int = 6, since: str | None = None) -> list[dict]:
        query, values = "SELECT path,COUNT(*) AS n FROM events WHERE action != 'alert'", []
        if since:
            query += " AND ts >= ?"
            values.append(since)
        query += " GROUP BY path ORDER BY n DESC LIMIT ?"
        values.append(limit)
        with self._lock:
            rows = self._conn.execute(query, values).fetchall()
        return [{"path": row["path"], "count": row["n"]} for row in rows]

    def latest_event_id(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COALESCE(MAX(id),0) AS id FROM events").fetchone()
        return int(row["id"])

    def total_events(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self._conn.commit()

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._conn.close()
                self._closed = True


# ---------------------------------------------------------------------------
# 3. Severity rules and ransomware-pattern detection
# ---------------------------------------------------------------------------

def human_size(count: int | None) -> str:
    if count is None:
        return "—"
    size = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def judge(action: str, path: Path, before: Fingerprint | None,
          after: Fingerprint | None, settings: Settings) -> tuple[str, str]:
    """Apply severity rules from most serious to least serious."""
    suffix = path.suffix.lower()

    if settings.is_sensitive(path):
        return CRITICAL, f"{action} under a path holding credentials or access control"
    if before and after and not before.is_executable and after.is_executable:
        return CRITICAL, f"permissions changed to executable ({before.permissions} → {after.permissions})"
    if (before and after and before.entropy > 0 and before.entropy < 6.0
            and after.entropy >= settings.entropy_floor):
        return CRITICAL, (
            f"contents became unreadable — randomness rose from {before.entropy:.1f} "
            f"to {after.entropy:.1f} bits per byte"
        )

    if suffix in EXECUTABLE_SUFFIXES:
        return WARNING, f"{action} an executable file"
    if action == "deleted":
        return WARNING, "file removed"
    if before and after and before.mode != after.mode:
        return WARNING, f"permissions changed ({before.permissions} → {after.permissions})"
    if before and after and before.size > 1024 and after.size < before.size * 0.1:
        return WARNING, f"shrank from {human_size(before.size)} to {human_size(after.size)}"

    if suffix in CONFIG_SUFFIXES:
        return NOTICE, f"{action} a configuration file"
    if action == "moved":
        return NOTICE, "file moved or renamed"
    if action == "created":
        return NOTICE, "new file"
    return INFO, "contents changed"


class BurstDetector:
    """Detect many formerly readable files becoming high-entropy in a short time."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._recent: deque[tuple[float, str]] = deque()
        self._last_alert: float | None = None
        self._cooldown = 60.0

    def _looks_encrypted(self, change: Change) -> bool:
        if change.after is None or change.after.entropy < self.settings.entropy_floor:
            return False
        if Path(change.path).suffix.lower() in ALREADY_COMPRESSED:
            return False
        return change.before is None or change.before.entropy < 6.0

    def observe(self, change: Change) -> str | None:
        if change.action not in ("modified", "created", "moved") or not self._looks_encrypted(change):
            return None

        now = time.monotonic()
        self._recent.append((now, change.path))
        cutoff = now - self.settings.burst_window
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

        affected = {path for seen, path in self._recent}
        if len(affected) < self.settings.burst_threshold:
            return None
        if self._last_alert is not None and now - self._last_alert < self._cooldown:
            return None

        self._last_alert = now
        return (
            f"{len(affected)} files became unreadable within {self.settings.burst_window:.0f} seconds — "
            "this is what ransomware encrypting a folder looks like"
        )

    def reset(self) -> None:
        self._recent.clear()
        self._last_alert = None


# ---------------------------------------------------------------------------
# 4. Filesystem watcher and offline baseline/audit
# ---------------------------------------------------------------------------

class _EventBridge(FileSystemEventHandler):
    """Keep OS callbacks tiny: queue hints and let the worker do the real work."""

    def __init__(self, events: queue.Queue) -> None:
        self.events = events

    def on_created(self, event):
        if not event.is_directory:
            self.events.put((str(event.src_path), "created", None))

    def on_modified(self, event):
        if not event.is_directory:
            self.events.put((str(event.src_path), "modified", None))

    def on_deleted(self, event):
        if not event.is_directory:
            self.events.put((str(event.src_path), "deleted", None))

    def on_moved(self, event):
        if not event.is_directory:
            self.events.put((str(event.src_path), "moved", str(event.dest_path)))


@dataclass
class _Pending:
    hint: str
    last_seen: float
    destination: str | None = None


class Guard:
    """Connect the watcher, database, fingerprint checks, and event listeners."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = Database(settings.db_path)
        self.burst = BurstDetector(settings)
        self._incoming: queue.Queue = queue.Queue()
        self._pending: dict[str, _Pending] = {}
        self._stop = threading.Event()
        self._observer = None
        self._worker: threading.Thread | None = None
        self._started = False
        self.listeners: list[Callable[[Change], None]] = []
        self.started_at = time.time()
        self.events_seen = 0

    def start(self) -> None:
        if self._started:
            return
        if not WATCHDOG_AVAILABLE or Observer is None:
            raise RuntimeError("Live monitoring needs watchdog. Install it with: python -m pip install watchdog")
        self._stop.clear()
        self._observer = Observer()
        self._observer.schedule(_EventBridge(self._incoming), str(self.settings.root), recursive=True)
        self._observer.start()
        self._worker = threading.Thread(target=self._run, name="guard-worker", daemon=True)
        self._worker.start()
        self._started = True

    def stop(self) -> None:
        """Stop safely, even if start() was never called or stop() runs twice."""
        self._stop.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=3)
            self._observer = None
        if self._worker is not None:
            self._worker.join(timeout=3)
            self._worker = None
        self._started = False
        self.db.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                path, hint, destination = self._incoming.get(timeout=0.1)
                self._remember(path, hint, destination)
            except queue.Empty:
                pass
            self._flush_settled()

    def _remember(self, path: str, hint: str, destination: str | None) -> None:
        if self.settings.is_ignored(Path(path)):
            return
        previous = self._pending.get(path)
        self._pending[path] = _Pending(
            hint=previous.hint if previous else hint,
            last_seen=time.monotonic(),
            destination=destination or (previous.destination if previous else None),
        )

    def _flush_settled(self) -> None:
        now = time.monotonic()
        ready = [path for path, item in self._pending.items()
                 if now - item.last_seen >= self.settings.quiet_period]
        for path in ready:
            item = self._pending.pop(path)
            change = self.examine(path, item.hint, item.destination)
            if change:
                self._publish(change)

    def examine(self, path: str, hint: str = "modified", destination: str | None = None) -> Change | None:
        """Verify an OS hint by comparing fingerprints; discard noise."""
        target = Path(path)
        if self.settings.is_ignored(target):
            return None

        stored = self.db.get_file(path)
        current = fingerprint(target, self.settings)
        if hint == "moved" and destination:
            return self._handle_move(path, destination, stored)
        if current is None and stored is None:
            return None

        if current is None:
            action = "deleted"
        elif stored is None:
            action = "created"
        elif stored.sha256 == current.sha256:
            if stored.mode == current.mode:
                self.db.put_file(path, current)  # Refresh mtime without creating noise.
                return None
            action = "permissions"
        else:
            action = "modified"

        severity, reason = judge(action, target, stored, current, self.settings)
        change = Change(timestamp(), path, action, severity, reason, stored, current)
        if current is None:
            self.db.drop_file(path)
        else:
            self.db.put_file(path, current)
        return change

    def _handle_move(self, source: str, destination: str, stored: Fingerprint | None) -> Change | None:
        if self.settings.is_ignored(Path(destination)):
            self.db.drop_file(source)
            return None
        current = fingerprint(Path(destination), self.settings)
        if current is None:
            return None
        severity, reason = judge("moved", Path(destination), stored, current, self.settings)
        self.db.drop_file(source)
        self.db.put_file(destination, current)
        return Change(timestamp(), source, "moved", severity, reason, stored, current, destination)

    def _publish(self, change: Change) -> None:
        self.db.add_event(change)
        self.events_seen += 1
        for listener in tuple(self.listeners):
            try:
                listener(change)
            except Exception as error:
                print(f"Guard listener error: {error}", file=sys.stderr)

        alert = self.burst.observe(change)
        if alert:
            warning = Change(timestamp(), str(self.settings.root), "alert", CRITICAL, alert)
            self.db.add_event(warning)
            for listener in tuple(self.listeners):
                try:
                    listener(warning)
                except Exception as error:
                    print(f"Guard listener error: {error}", file=sys.stderr)

    def walk(self):
        """Yield included files, pruning ignored folders before descending."""
        for directory, subdirectories, filenames in os.walk(self.settings.root):
            folder = Path(directory)
            subdirectories[:] = [name for name in subdirectories
                                 if not self.settings.is_ignored(folder / name)]
            for name in filenames:
                path = folder / name
                if not self.settings.is_ignored(path):
                    yield path

    def baseline(self, on_progress: Callable[[int, Path], None] | None = None) -> int:
        """Record fingerprints for the current tree as the comparison point."""
        count = 0
        for path in self.walk():
            measured = fingerprint(path, self.settings)
            if measured is None:
                continue
            self.db.put_file(str(path), measured)
            count += 1
            if on_progress:
                on_progress(count, path)
        self.db.set_meta("baseline_taken", timestamp())
        self.db.set_meta("baseline_root", str(self.settings.root))
        self.db.set_meta("baseline_count", str(count))
        return count

    def audit(self) -> dict[str, list]:
        """Find files added, changed, or removed since the stored fingerprints."""
        stored = self.db.tracked_files()
        added, changed = [], []
        for path in self.walk():
            name = str(path)
            current = fingerprint(path, self.settings)
            if current is None:
                continue
            previous = stored.pop(name, None)
            if previous is None:
                added.append((name, current))
            elif previous.sha256 != current.sha256 or previous.mode != current.mode:
                changed.append((name, previous, current))
        return {"added": added, "changed": changed, "removed": sorted(stored.items())}


# ---------------------------------------------------------------------------
# 5. Terminal output
# ---------------------------------------------------------------------------

_COLOURS = {INFO: "37", NOTICE: "36", WARNING: "33", CRITICAL: "1;31"}
_SYMBOLS = {INFO: "·", NOTICE: "+", WARNING: "!", CRITICAL: "✕"}
_USE_COLOUR = sys.stdout.isatty()


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text


def dim(text: str) -> str:
    return paint(text, "2")


def shorten(path: str, root: Path | None) -> str:
    if root is None:
        return path
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return path


def format_change(change: Change, root: Path | None = None) -> str:
    symbol = paint(_SYMBOLS[change.severity], _COLOURS[change.severity])
    line = f"{dim(change.ts[11:19])}  {symbol} {change.action:<11} {shorten(change.path, root)}"
    extra = []
    if change.detail:
        extra.append(f"→ {shorten(change.detail, root)}")
    if change.action == "modified" and change.size_delta:
        sign = "+" if change.size_delta > 0 else "−"
        extra.append(f"{sign}{human_size(abs(change.size_delta))}")
    if change.after and change.after.short_hash != "—":
        extra.append(change.after.short_hash)
    if extra:
        line += dim("   " + "  ".join(extra))
    if change.severity in (WARNING, CRITICAL):
        line += "\n" + " " * 13 + paint(change.reason, _COLOURS[change.severity])
    return line


# ---------------------------------------------------------------------------
# 6. Embedded dashboard and local HTTP API
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r'''<!DOCTYPE html>
<!--
  Guard's live dashboard.

  One file, no build step, no framework. It polls two JSON endpoints that
  guard.py serves:

      GET /api/events?since=<id>   everything newer than an event id
      GET /api/summary             counts, uptime, busiest paths

  Polling with a cursor rather than a streaming connection keeps this simple:
  whatever id the page is holding stays valid if you close the laptop lid, so
  there is no reconnect logic anywhere in here.
-->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guard</title>
<style>
  /* ── design tokens ───────────────────────────────────────────────────── */
  :root {
    --base:    #12100D;   /* warm near-black, like paper in a dark room */
    --panel:   #1A1714;
    --raised:  #221E19;
    --rule:    #2A2520;
    --text:    #E8E2D8;
    --muted:   #8E857A;
    --faint:   #5B544B;

    /* Severity is the whole colour system here — it is the information,
       not decoration, so nothing else in the page competes with it. */
    --info:     #6E8BA0;
    --notice:   #4FA97E;
    --warning:  #D9903F;
    --critical: #D9534F;

    --sans: "Inter", system-ui, -apple-system, "Segoe UI", sans-serif;
    --mono: "JetBrains Mono", ui-monospace, "SF Mono", "Cascadia Mono",
            Consolas, "DejaVu Sans Mono", monospace;
  }

  * { box-sizing: border-box; }

  body {
    margin: 0;
    background: var(--base);
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    line-height: 1.5;
  }

  /* ── top bar ─────────────────────────────────────────────────────────── */
  header {
    display: flex; align-items: baseline; gap: 18px;
    padding: 16px 22px;
    border-bottom: 1px solid var(--rule);
    background: var(--panel);
    flex-wrap: wrap;
  }
  .wordmark { font-family: var(--sans); font-size: 18px; font-weight: 600; letter-spacing: -0.01em; }
  .watching { color: var(--muted); flex: 1; min-width: 200px; word-break: break-all; }
  .watching b { color: var(--text); font-weight: 400; }
  .state { display: flex; align-items: center; gap: 7px; color: var(--muted); }
  .pulse {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--notice);
    box-shadow: 0 0 0 0 rgba(79,169,126,.6);
    animation: breathe 2.4s ease-out infinite;
  }
  /* The one piece of unprompted motion in the page: it answers "is this
     thing still alive", which a static dot cannot. */
  @keyframes breathe {
    0%   { box-shadow: 0 0 0 0 rgba(79,169,126,.5); }
    70%  { box-shadow: 0 0 0 7px rgba(79,169,126,0); }
    100% { box-shadow: 0 0 0 0 rgba(79,169,126,0); }
  }

  /* ── severity strip, doubles as the filter ───────────────────────────── */
  .levels { display: flex; border-bottom: 1px solid var(--rule); background: var(--panel); }
  .level {
    flex: 1; padding: 11px 18px; cursor: pointer;
    border: none; border-top: 2px solid transparent; border-right: 1px solid var(--rule);
    background: transparent; color: var(--muted);
    font-family: var(--mono); font-size: 13px; text-align: left;
  }
  .level:last-child { border-right: none; }
  .level:hover { background: var(--raised); }
  .level[aria-pressed="true"] { background: var(--raised); color: var(--text); }
  .level .n { display: block; font-size: 22px; font-weight: 500; color: var(--text); font-variant-numeric: tabular-nums; }
  .level .k { font-family: var(--sans); font-size: 11px; }
  .level[data-level="info"][aria-pressed="true"]     { border-top-color: var(--info); }
  .level[data-level="notice"][aria-pressed="true"]   { border-top-color: var(--notice); }
  .level[data-level="warning"][aria-pressed="true"]  { border-top-color: var(--warning); }
  .level[data-level="critical"][aria-pressed="true"] { border-top-color: var(--critical); }
  .level[data-level="critical"] .n { color: var(--critical); }
  .level[data-level="warning"]  .n { color: var(--warning); }

  /* ── alert banner ────────────────────────────────────────────────────── */
  .alarm {
    display: none; gap: 12px; align-items: baseline;
    padding: 13px 22px;
    background: rgba(217,83,79,.13);
    border-bottom: 1px solid var(--critical);
    color: #FFD7D5;
  }
  .alarm.on { display: flex; }
  .alarm b { font-family: var(--sans); color: var(--critical); }
  .alarm button {
    margin-left: auto; background: none; border: 1px solid var(--critical);
    color: var(--critical); padding: 3px 11px; cursor: pointer; font-family: var(--mono); font-size: 12px;
  }

  /* ── two-column body ─────────────────────────────────────────────────── */
  main { display: grid; grid-template-columns: 1fr 260px; gap: 1px; background: var(--rule); }
  @media (max-width: 860px) { main { grid-template-columns: 1fr; } }

  .ledger, aside { background: var(--base); }

  .ledger-head {
    display: flex; align-items: center; gap: 12px;
    padding: 11px 22px; border-bottom: 1px solid var(--rule); color: var(--muted);
  }
  .ledger-head .title { font-family: var(--sans); color: var(--text); }
  .ledger-head button {
    margin-left: auto; background: var(--raised); border: 1px solid var(--rule);
    color: var(--muted); padding: 4px 12px; cursor: pointer;
    font-family: var(--mono); font-size: 12px;
  }
  .ledger-head button:hover { color: var(--text); }

  #rows { height: calc(100vh - 230px); overflow-y: auto; }
  @media (max-width: 860px) { #rows { height: 60vh; } }

  /* Each row carries a coloured gutter. The gutter is the severity — it
     means the rows are scannable without reading a single word. */
  .row {
    display: flex; flex-wrap: wrap; align-items: baseline; gap: 14px;
    padding: 6px 22px 6px 19px;
    border-left: 3px solid transparent;
    border-bottom: 1px solid rgba(42,37,32,.55);
  }
  .row[data-level="info"]     { border-left-color: var(--info); }
  .row[data-level="notice"]   { border-left-color: var(--notice); }
  .row[data-level="warning"]  { border-left-color: var(--warning); }
  .row[data-level="critical"] { border-left-color: var(--critical); background: rgba(217,83,79,.07); }
  .row:hover { background: var(--panel); }

  /* Brief highlight so your eye catches what just arrived, then it settles
     into the record like everything else. */
  .row.fresh { animation: land 1.6s ease-out; }
  @keyframes land {
    from { background: rgba(232,226,216,.09); }
    to   { background: transparent; }
  }

  .clock  { color: var(--faint); font-variant-numeric: tabular-nums; flex: none; }
  .action { color: var(--muted); width: 88px; flex: none; }
  .row[data-level="warning"]  .action { color: var(--warning); }
  .row[data-level="critical"] .action { color: var(--critical); }
  .path   { flex: 1; min-width: 0; word-break: break-all; }
  .meta   { color: var(--faint); flex: none; text-align: right; font-variant-numeric: tabular-nums; }
  .why {
    flex-basis: 100%; padding-left: 102px; color: var(--muted); font-size: 12px;
  }
  .row[data-level="critical"] .why { color: #E8908D; }
  /* Folder-wide alerts are not about one file, so they get the full width. */
  .row[data-action="alert"] { background: rgba(217,83,79,.14); }
  .row[data-action="alert"] .path { color: #FFD7D5; word-break: normal; }

  .empty { padding: 60px 22px; text-align: center; color: var(--faint); }

  /* ── sidebar ─────────────────────────────────────────────────────────── */
  aside { padding: 18px 20px; }
  aside section { margin-bottom: 26px; }
  aside h2 {
    font-family: var(--sans); font-size: 11px; font-weight: 500;
    color: var(--muted); margin: 0 0 9px;
  }
  .big { font-size: 24px; font-variant-numeric: tabular-nums; }
  .sub { color: var(--faint); font-size: 12px; }
  .bar { display: flex; justify-content: space-between; gap: 10px; padding: 3px 0; }
  .bar span:last-child { color: var(--faint); font-variant-numeric: tabular-nums; flex: none; }
  .bar span:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  ::-webkit-scrollbar { width: 9px; }
  ::-webkit-scrollbar-thumb { background: var(--rule); border-radius: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
</style>
</head>

<body>

<header>
  <span class="wordmark">Guard</span>
  <span class="watching">watching <b id="root">…</b></span>
  <span class="state"><span class="pulse"></span><span id="uptime">starting</span></span>
</header>

<div class="alarm" id="alarm">
  <b>Alert</b>
  <span id="alarm-text"></span>
  <button onclick="dismissAlarm()">Dismiss</button>
</div>

<div class="levels" id="levels">
  <button class="level" data-level="critical" aria-pressed="false"><span class="n" id="n-critical">0</span><span class="k">critical</span></button>
  <button class="level" data-level="warning"  aria-pressed="false"><span class="n" id="n-warning">0</span><span class="k">warning</span></button>
  <button class="level" data-level="notice"   aria-pressed="false"><span class="n" id="n-notice">0</span><span class="k">notice</span></button>
  <button class="level" data-level="info"     aria-pressed="false"><span class="n" id="n-info">0</span><span class="k">info</span></button>
</div>

<main>
  <div class="ledger">
    <div class="ledger-head">
      <span class="title">Change log</span>
      <span id="filter-note"></span>
      <button id="follow" onclick="toggleFollow()">Following</button>
    </div>
    <div id="rows"><div class="empty">Waiting for the first change. Try editing a file in the watched folder.</div></div>
  </div>

  <aside>
    <section>
      <h2>Files tracked</h2>
      <div class="big" id="tracked">—</div>
      <div class="sub" id="baseline">no baseline</div>
    </section>
    <section>
      <h2>Events recorded</h2>
      <div class="big" id="total">—</div>
      <div class="sub">since the log was created</div>
    </section>
    <section>
      <h2>Busiest paths, last 24h</h2>
      <div id="busiest"><div class="sub">nothing yet</div></div>
    </section>
  </aside>
</main>

<script>
// ── state ──────────────────────────────────────────────────────────────────
let cursor = 0;          // highest event id this page has drawn
let following = true;    // auto-scroll to the newest row
let filter = null;       // severity to show, or null for everything
let rootPath = '';       // watched folder, so paths can be shown relative to it
let alarmLocked = false; // a burst alert holds the banner until it is dismissed
const MAX_ROWS = 500;    // the log is unbounded; the DOM should not be

const rowsEl = document.getElementById('rows');

// ── drawing one event ──────────────────────────────────────────────────────
function shortHash(h) { return h ? h.slice(0, 12) : ''; }

// The log stores absolute paths, which is what an audit trail should do.
// Screens are narrow, so strip the watched root off for display.
function relative(path) {
  if (rootPath && path.startsWith(rootPath)) {
    return path.slice(rootPath.length).replace(/^[\\/]/, '') || '.';
  }
  return path;
}

function sizeNote(event) {
  const before = event.size_before, after = event.size_after;
  if (before == null || after == null || before === after) return shortHash(event.new_hash);
  const delta = after - before;
  const sign = delta > 0 ? '+' : '−';
  return sign + humanSize(Math.abs(delta));
}

function humanSize(n) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
}

function addRow(event, fresh) {
  if (rowsEl.firstElementChild?.className === 'empty') rowsEl.innerHTML = '';

  const row = document.createElement('div');
  row.className = 'row' + (fresh ? ' fresh' : '');
  row.dataset.level = event.severity;
  row.dataset.path = event.path;
  row.dataset.action = event.action;
  if (filter && filter !== event.severity) row.style.display = 'none';

  const clock = event.ts.slice(11, 19);
  const path = event.detail && event.action === 'moved'
    ? `${relative(event.path)} → ${relative(event.detail)}`
    : relative(event.path);

  // Only warnings and alerts get their reason spelled out. Explaining every
  // routine edit would bury the ones that matter.
  const loud = event.severity === 'warning' || event.severity === 'critical';

  // A burst alert is about the whole folder, not one file, so its message is
  // the row rather than a footnote under a path that means nothing.
  const isAlert = event.action === 'alert';

  row.innerHTML = `
    <span class="clock">${clock}</span>
    <span class="action">${event.action}</span>
    <span class="path"></span>
    <span class="meta">${isAlert ? '' : sizeNote(event)}</span>
    ${loud && !isAlert ? '<span class="why"></span>' : ''}`;

  // textContent, not innerHTML: a filename is untrusted input and could
  // contain angle brackets.
  row.querySelector('.path').textContent = isAlert ? event.reason : path;
  if (loud && !isAlert) row.querySelector('.why').textContent = event.reason;

  rowsEl.appendChild(row);
  while (rowsEl.children.length > MAX_ROWS) rowsEl.firstElementChild.remove();

  if (event.severity === 'critical' && fresh) raiseAlarm(event.reason, isAlert);
  if (following) rowsEl.scrollTop = rowsEl.scrollHeight;
}

function raiseAlarm(text, isAlert) {
  // A folder-wide alert outranks any single file's warning. Without this the
  // ransomware message is replaced a second later by the next routine
  // critical, which is precisely the wrong way round.
  if (alarmLocked && !isAlert) return;
  if (isAlert) alarmLocked = true;
  document.getElementById('alarm-text').textContent = text;
  document.getElementById('alarm').classList.add('on');
}

function dismissAlarm() {
  alarmLocked = false;
  document.getElementById('alarm').classList.remove('on');
}

// ── controls ───────────────────────────────────────────────────────────────
function toggleFollow() {
  following = !following;
  document.getElementById('follow').textContent = following ? 'Following' : 'Paused';
  if (following) rowsEl.scrollTop = rowsEl.scrollHeight;
}

// Scrolling up by hand means you want to read something, so stop yanking the
// view away from you.
rowsEl.addEventListener('scroll', () => {
  const atBottom = rowsEl.scrollHeight - rowsEl.scrollTop - rowsEl.clientHeight < 40;
  if (!atBottom && following) toggleFollow();
});

document.getElementById('levels').addEventListener('click', (e) => {
  const button = e.target.closest('.level');
  if (!button) return;

  filter = filter === button.dataset.level ? null : button.dataset.level;
  for (const other of document.querySelectorAll('.level')) {
    other.setAttribute('aria-pressed', String(other.dataset.level === filter));
  }
  document.getElementById('filter-note').textContent =
    filter ? `showing ${filter} only` : '';
  for (const row of rowsEl.querySelectorAll('.row')) {
    row.style.display = (!filter || row.dataset.level === filter) ? '' : 'none';
  }
});

// ── polling ────────────────────────────────────────────────────────────────
function uptimeText(seconds) {
  const h = Math.floor(seconds / 3600), m = Math.floor(seconds % 3600 / 60), s = seconds % 60;
  if (h) return `watching ${h}h ${String(m).padStart(2, '0')}m`;
  if (m) return `watching ${m}m ${String(s).padStart(2, '0')}s`;
  return `watching ${s}s`;
}

async function refreshSummary() {
  const summary = await (await fetch('/api/summary')).json();
  rootPath = summary.root;
  document.getElementById('root').textContent = summary.root;
  document.getElementById('uptime').textContent = uptimeText(summary.uptime);
  document.getElementById('tracked').textContent = summary.tracked.toLocaleString();
  document.getElementById('total').textContent = summary.total_events.toLocaleString();
  document.getElementById('baseline').textContent =
    summary.baseline ? 'baseline ' + summary.baseline.slice(0, 10) : 'no baseline';

  for (const [level, count] of Object.entries(summary.severity)) {
    const el = document.getElementById('n-' + level);
    if (el) el.textContent = count.toLocaleString();
  }

  const busiest = document.getElementById('busiest');
  busiest.innerHTML = summary.busiest.length
    ? summary.busiest.map(entry => {
        const line = document.createElement('div');
        line.className = 'bar';
        const name = document.createElement('span');
        name.textContent = relative(entry.path);
        name.title = entry.path;
        const n = document.createElement('span');
        n.textContent = entry.count;
        line.append(name, n);
        return line.outerHTML;
      }).join('')
    : '<div class="sub">nothing yet</div>';

  return summary;
}

async function poll(firstRun = false) {
  try {
    const events = (await (await fetch(`/api/events?since=${cursor}`)).json()).events;
    for (const event of events) {
      cursor = event.id;
      addRow(event, !firstRun);
    }
    await refreshSummary();
  } catch {
    // Guard has stopped, or the page outlived it. Keep trying quietly.
    document.getElementById('uptime').textContent = 'not responding';
  }
}

// Start near the end of the log rather than replaying it from event one.
(async function start() {
  const summary = await refreshSummary().catch(() => null);
  if (summary) cursor = Math.max(0, summary.latest_id - 200);
  await poll(true);
  setInterval(poll, 1000);
})();
</script>
</body>
</html>
'''


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve the embedded dashboard plus its event and summary endpoints."""

    guard: Guard

    def do_GET(self) -> None:
        route = urlparse(self.path)
        query = parse_qs(route.query)
        if route.path in ("/", "/index.html"):
            self._send(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif route.path == "/api/events":
            try:
                since = max(0, int(query.get("since", ["0"])[0]))
            except ValueError:
                self.send_error(400, "since must be an integer")
                return
            self._send_json({"events": self.guard.db.events_since(since)})
        elif route.path == "/api/summary":
            self._send_json(self._summary())
        else:
            self.send_error(404)

    def _summary(self) -> dict:
        guard = self.guard
        day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
        return {
            "root": str(guard.settings.root), "tracked": guard.db.file_count(),
            "total_events": guard.db.total_events(), "latest_id": guard.db.latest_event_id(),
            "uptime": int(time.time() - guard.started_at),
            "severity": guard.db.severity_counts(since=day_ago),
            "busiest": guard.db.busiest_paths(since=day_ago),
            "baseline": guard.db.get_meta("baseline_taken"),
        }

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict) -> None:
        self._send(200, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def log_message(self, *args) -> None:
        pass  # Request logs would drown out the file-change log.


def serve_dashboard(guard: Guard, host: str, port: int) -> ThreadingHTTPServer:
    DashboardHandler.guard = guard
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    threading.Thread(target=server.serve_forever, name="guard-dashboard", daemon=True).start()
    return server


# ---------------------------------------------------------------------------
# 7. CLI commands
# ---------------------------------------------------------------------------

def banner() -> None:
    print(f"\n  {paint(APP_NAME, '1')} {dim(__version__)}")
    print(dim("  File integrity monitoring"))
    print(dim("  " + "─" * 54) + "\n")


def settings_from(args: argparse.Namespace) -> Settings:
    root = Path(args.directory).expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"  {root} is not a directory.")
    settings = Settings(root=root, db_path=Path(args.database).expanduser())
    settings.ignore.extend(getattr(args, "ignore", None) or [])
    if getattr(args, "quiet_period", None) is not None:
        settings.quiet_period = args.quiet_period
    return settings


def cmd_watch(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)
    minimum = SEVERITY_RANK[args.min_severity]
    guard.listeners.append(
        lambda change: print(format_change(change, settings.root))
        if SEVERITY_RANK[change.severity] >= minimum else None
    )

    server = None
    try:
        if guard.db.file_count() == 0:
            print(dim("  No baseline yet — taking one first so changes can be compared."))
            print(dim(f"  Fingerprinted {guard.baseline():,} files.\n"))
        if args.dashboard:
            server = serve_dashboard(guard, args.host, args.port)
            url = f"http://{args.host}:{args.port}"
            print(f"  Dashboard on {paint(url, '4')}")
            if not args.no_browser:
                webbrowser.open(url)
        guard.start()
        print(f"  Watching {paint(str(settings.root), '1')}")
        print(dim(f"  Tracking {guard.db.file_count():,} files. Press Ctrl+C to stop.\n"))
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\n  Stopped after {guard.events_seen} recorded changes.")
    finally:
        if server:
            server.shutdown()
            server.server_close()
        guard.stop()
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)
    try:
        print(f"  Fingerprinting {settings.root}\n")

        def progress(count: int, _path: Path) -> None:
            if count % 50 == 0:
                print(f"\r  {count:,} files…", end="", flush=True)

        started = time.monotonic()
        count = guard.baseline(progress)
        elapsed = time.monotonic() - started
        print(f"\r  {paint(f'{count:,} files', '1')} fingerprinted in {elapsed:.1f}s.")
        print(dim(f"  Baseline saved to {settings.db_path}. Run 'audit' to compare later."))
        return 0
    finally:
        guard.stop()


def cmd_audit(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)
    try:
        if guard.db.file_count() == 0:
            print("  No baseline to compare against. Run 'baseline' first.")
            return 1

        taken = guard.db.get_meta("baseline_taken")
        note = dim(" from " + taken) if taken else ""
        print(f"  Comparing {settings.root} against the baseline{note}\n")
        result = guard.audit()
        total = sum(len(group) for group in result.values())
        for path, current in result["added"]:
            print(f"  {paint('+', _COLOURS[NOTICE])} added     {shorten(path, settings.root)}"
                  f"{dim('  ' + human_size(current.size))}")
        for path, old, new in result["changed"]:
            note = (f"{old.permissions} → {new.permissions}" if old.sha256 == new.sha256
                    else f"{old.short_hash} → {new.short_hash}")
            print(f"  {paint('~', _COLOURS[WARNING])} changed   {shorten(path, settings.root)}"
                  f"{dim('  ' + note)}")
        for path, old in result["removed"]:
            print(f"  {paint('−', _COLOURS[WARNING])} removed   {shorten(path, settings.root)}"
                  f"{dim('  was ' + human_size(old.size))}")
        print()
        if total == 0:
            print(f"  {paint('Clean.', _COLOURS[NOTICE])} Nothing has changed since the baseline.")
            return 0
        print(f"  {len(result['added'])} added, {len(result['changed'])} changed, "
              f"{len(result['removed'])} removed.")
        return 1  # CI and scheduled checks can detect differences.
    finally:
        guard.stop()


def cmd_history(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)
    try:
        rows = guard.db.recent_events(
            limit=args.limit,
            severity=args.min_severity if args.min_severity != INFO else None,
            path_like=args.path,
        )
        if not rows:
            print("  Nothing recorded yet.")
            return 0
        for row in reversed(rows):
            change = Change(row["ts"], row["path"], row["action"], row["severity"],
                            row["reason"], detail=row["detail"])
            print(f"  {dim(row['ts'][:10])} {format_change(change, settings.root)}")
        print(dim(f"\n  {len(rows)} of {guard.db.total_events():,} recorded events."))
        return 0
    finally:
        guard.stop()


def cmd_stats(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)
    try:
        day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
        print(f"  Watching   {settings.root}")
        print(f"  Tracking   {guard.db.file_count():,} files")
        print(f"  Recorded   {guard.db.total_events():,} events")
        print(f"  Baseline   {guard.db.get_meta('baseline_taken') or 'never taken'}\n")
        counts = guard.db.severity_counts(since=day_ago)
        print(dim("  Last 24 hours"))
        for level in (CRITICAL, WARNING, NOTICE, INFO):
            bar = "█" * min(40, counts[level])
            print(f"    {level:<9} {counts[level]:>5}  {paint(bar, _COLOURS[level])}")
        busiest = guard.db.busiest_paths(since=day_ago)
        if busiest:
            print(dim("\n  Busiest paths"))
            for entry in busiest:
                print(f"    {entry['count']:>4}  {shorten(entry['path'], settings.root)}")
        return 0
    finally:
        guard.stop()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guard", description="Guard — file integrity monitoring for a directory tree.",
        epilog="Start with:  python app.py watch ./my-folder --dashboard",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> argparse.ArgumentParser:
        command.add_argument("directory", help="folder to monitor")
        command.add_argument("-d", "--database", default="guard.db", help="SQLite database file")
        command.add_argument("-i", "--ignore", action="append", metavar="PATTERN",
                             help="extra ignore pattern; repeatable")
        return command

    watch = common(commands.add_parser("watch", help="monitor the folder in real time"))
    watch.add_argument("--dashboard", action="store_true", help="serve the live dashboard")
    watch.add_argument("--host", default="127.0.0.1")
    watch.add_argument("--port", type=int, default=8420)
    watch.add_argument("--no-browser", action="store_true", help="do not open a browser")
    watch.add_argument("-m", "--min-severity", choices=SEVERITY_RANK, default=INFO,
                       help="hide lower-severity terminal messages")
    watch.add_argument("-q", "--quiet-period", type=float, default=0.4,
                       help="seconds a file must be quiet before inspection")
    watch.set_defaults(func=cmd_watch)

    baseline = common(commands.add_parser("baseline", help="save the current folder state"))
    baseline.set_defaults(func=cmd_baseline)
    audit = common(commands.add_parser("audit", help="compare the folder with the saved state"))
    audit.set_defaults(func=cmd_audit)
    history = common(commands.add_parser("history", help="show recorded events"))
    history.add_argument("-n", "--limit", type=int, default=40)
    history.add_argument("-p", "--path", help="only paths containing this text")
    history.add_argument("-m", "--min-severity", choices=SEVERITY_RANK, default=INFO)
    history.set_defaults(func=cmd_history)
    stats = common(commands.add_parser("stats", help="summarise the event log"))
    stats.set_defaults(func=cmd_stats)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    banner()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n  Stopped.")
        return 130
    except (OSError, sqlite3.Error, RuntimeError) as error:
        print(f"\n  Guard error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
