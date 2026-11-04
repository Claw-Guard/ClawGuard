"""Skill inventory, integrity checks, verdict storage, and manual overrides.

This module is deliberately independent of the LLM gateway transport.  The
gateway supplies an async judge callback and translates a review result into a
normal model-tool policy denial when the effective verdict is unsafe.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml


_SKILL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SKIPPED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".openclaw",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "node_modules",
}
_HASH_ONLY_ASSET_SUFFIXES = {
    ".avif",
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".otf",
    ".png",
    ".svgz",
    ".ttf",
    ".webp",
    ".woff",
    ".woff2",
}
_RISK_LEVELS = {"none", "low", "medium", "high", "critical"}
_SAFE_WORDS = {"safe", "allow", "allowed", "benign"}
_UNSAFE_WORDS = {
    "unsafe",
    "deny",
    "denied",
    "harmful",
    "malicious",
    "unsafe_for_use",
}


class SkillBundleError(ValueError):
    """Raised when a Skill directory cannot be represented as a bundle."""


@dataclass(frozen=True)
class SkillFileEntry:
    path: str
    sha256: str
    size: int
    kind: str
    mode: int = 0
    content: Optional[str] = None

    def manifest_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "kind": self.kind,
            "mode": self.mode,
        }


@dataclass(frozen=True)
class SkillBundle:
    name: str
    description: str
    path: str
    content_hash: str
    markdown: str
    files: Tuple[SkillFileEntry, ...]
    complete: bool = True
    incomplete_reason: str = ""

    def manifest(self) -> List[Dict[str, Any]]:
        return [entry.manifest_dict() for entry in self.files]

    def judge_payload(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "path": self.path,
            "content_hash": self.content_hash,
            "complete": self.complete,
            "incomplete_reason": self.incomplete_reason,
            "file_manifest": self.manifest(),
            "files": {
                entry.path: entry.content
                for entry in self.files
                if entry.content is not None
            },
        }


@dataclass
class SkillVerdict:
    verdict: str
    risk_level: str
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)
    source: str = "judge"

    def __post_init__(self) -> None:
        normalized = str(self.verdict or "").strip().casefold()
        if normalized in _SAFE_WORDS:
            self.verdict = "safe"
        elif normalized in _UNSAFE_WORDS:
            self.verdict = "unsafe"
        else:
            invalid = str(self.verdict or "")
            self.verdict = "unsafe"
            self.details.setdefault("invalid_verdict", invalid)
        self.risk_level = (
            self.risk_level
            if str(self.risk_level).casefold() in _RISK_LEVELS
            else ("high" if self.verdict == "unsafe" else "none")
        )
        self.risk_level = str(self.risk_level).casefold()

    @property
    def is_safe(self) -> bool:
        return self.verdict == "safe"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "details": self.details,
            "source": self.source,
        }


@dataclass
class SkillReview:
    record: Dict[str, Any]
    bundle: SkillBundle
    cached: bool = False
    hash_changed: bool = False

    @property
    def effective_verdict(self) -> str:
        return str(self.record.get("effective_verdict") or "unsafe")

    @property
    def model_verdict(self) -> str:
        return str(self.record.get("model_verdict") or "unsafe")

    @property
    def is_safe(self) -> bool:
        return self.effective_verdict == "safe"


def _read_text(data: bytes, limit: int) -> Tuple[Optional[str], bool]:
    if b"\x00" in data:
        return None, False
    if len(data) > limit:
        try:
            return data[:limit].decode("utf-8", errors="replace"), False
        except Exception:
            return None, False
    try:
        return data.decode("utf-8"), True
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), False


def _parse_frontmatter(markdown: str) -> Tuple[Dict[str, Any], bool]:
    if not markdown.startswith("---"):
        return {}, True
    lines = markdown.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, True
    try:
        closing = next(index for index in range(1, len(lines)) if lines[index].strip() == "---")
    except StopIteration:
        return {}, False
    try:
        parsed = yaml.safe_load("\n".join(lines[1:closing])) or {}
    except yaml.YAMLError:
        return {}, False
    return (dict(parsed) if isinstance(parsed, Mapping) else {}), True


def _normalize_skill_name(value: Any, fallback: str = "unnamed-skill") -> str:
    raw = str(value or "").strip().casefold()
    normalized = re.sub(r"[^a-z0-9._-]+", "-", raw).strip(".-_")
    if _SKILL_NAME_RE.fullmatch(normalized):
        return normalized
    fallback_name = re.sub(r"[^a-z0-9._-]+", "-", fallback.casefold()).strip(".-_")
    return fallback_name[:64] or "unnamed-skill"


def _bundle_hash(files: Sequence[SkillFileEntry]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(files, key=lambda item: item.path):
        digest.update(entry.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(entry.kind.encode("ascii"))
        digest.update(b"\0")
        digest.update(entry.sha256.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry.size).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry.mode).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def build_skill_bundle(
    skill_path: str | Path,
    *,
    max_files: int = 256,
    max_file_bytes: int = 256 * 1024,
    max_total_bytes: int = 1024 * 1024,
) -> SkillBundle:
    """Build a deterministic bundle from a Skill directory or SKILL.md path."""

    candidate = Path(skill_path).expanduser()
    if candidate.is_file() and candidate.name == "SKILL.md":
        root = candidate.parent
    else:
        root = candidate
    root_was_symlink = root.is_symlink()
    root = root.resolve()
    skill_file = root / "SKILL.md"
    if not skill_file.is_file():
        raise SkillBundleError(f"SKILL.md not found under {root}")
    skill_file_was_symlink = skill_file.is_symlink()

    markdown = skill_file.read_text(encoding="utf-8", errors="replace")
    frontmatter, frontmatter_valid = _parse_frontmatter(markdown)
    name = _normalize_skill_name(frontmatter.get("name"), fallback=root.name)
    description = str(frontmatter.get("description") or "").strip()

    entries: List[SkillFileEntry] = []
    complete = (
        frontmatter_valid
        and not root_was_symlink
        and not skill_file_was_symlink
    )
    reasons: List[str] = []
    if root_was_symlink:
        reasons.append("Skill root is a symbolic link")
    if skill_file_was_symlink:
        reasons.append("SKILL.md is a symbolic link")
    if not frontmatter_valid:
        reasons.append("invalid or unterminated YAML frontmatter")

    total_text_bytes = 0
    walked_files = 0
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        kept_directories = []
        for directory_name in sorted(directory_names):
            child = current_path / directory_name
            if directory_name in _SKIPPED_DIRECTORIES:
                if directory_name not in {
                    ".git",
                    ".hg",
                    ".svn",
                    ".openclaw",
                    "__pycache__",
                    ".pytest_cache",
                    ".mypy_cache",
                    ".ruff_cache",
                }:
                    complete = False
                    reasons.append(
                        f"uninspected dependency/runtime directory: "
                        f"{child.relative_to(root).as_posix()}"
                    )
                continue
            if child.is_symlink():
                relative = child.relative_to(root).as_posix()
                entries.append(
                    SkillFileEntry(
                        path=relative,
                        sha256=hashlib.sha256(os.readlink(child).encode("utf-8")).hexdigest(),
                        size=0,
                        kind="symlink",
                        mode=0,
                    )
                )
                complete = False
                reasons.append(f"symlink included: {relative}")
                continue
            kept_directories.append(directory_name)
        directory_names[:] = kept_directories

        for file_name in sorted(file_names):
            path = current_path / file_name
            relative = path.relative_to(root).as_posix()
            walked_files += 1
            if walked_files > max_files:
                complete = False
                reasons.append(f"file limit exceeded ({max_files})")
                break
            if path.is_symlink():
                entries.append(
                    SkillFileEntry(
                        path=relative,
                        sha256=hashlib.sha256(os.readlink(path).encode("utf-8")).hexdigest(),
                        size=0,
                        kind="symlink",
                        mode=0,
                    )
                )
                complete = False
                reasons.append(f"symlink included: {relative}")
                continue
            if not path.is_file():
                continue
            size = path.stat().st_size
            mode = stat.S_IMODE(path.stat().st_mode)
            if size > 16 * 1024 * 1024:
                digest = hashlib.sha256(
                    f"oversized:{relative}:{size}".encode("utf-8")
                ).hexdigest()
                entries.append(
                    SkillFileEntry(
                        path=relative,
                        sha256=digest,
                        size=size,
                        kind="oversized",
                        mode=mode,
                    )
                )
                complete = False
                reasons.append(f"oversized file not inspected: {relative}")
                continue
            with path.open("rb") as handle:
                data = handle.read(16 * 1024 * 1024 + 1)
            if len(data) > 16 * 1024 * 1024:
                complete = False
                reasons.append(f"oversized file changed during inspection: {relative}")
                entries.append(
                    SkillFileEntry(
                        path=relative,
                        sha256=hashlib.sha256(
                            f"changed-while-reading:{relative}".encode("utf-8")
                        ).hexdigest(),
                        size=max(size, len(data)),
                        kind="oversized",
                        mode=mode,
                    )
                )
                continue
            size = len(data)
            digest = hashlib.sha256(data).hexdigest()
            content, text_ok = _read_text(data, max_file_bytes)
            suffix = path.suffix.casefold()
            hash_only_asset = not text_ok and suffix in _HASH_ONLY_ASSET_SUFFIXES
            kind = (
                "text"
                if content is not None
                else ("binary_asset" if hash_only_asset else "binary")
            )
            if not text_ok and not hash_only_asset:
                complete = False
                reasons.append(f"non-UTF-8 or truncated file: {relative}")
            if content is not None:
                total_text_bytes += len(content.encode("utf-8", errors="replace"))
                if total_text_bytes > max_total_bytes:
                    complete = False
                    reasons.append(f"text inspection limit exceeded ({max_total_bytes} bytes)")
                    content = None
            entries.append(
                SkillFileEntry(
                    path=relative,
                    sha256=digest,
                    size=size,
                    kind=kind,
                    mode=mode,
                    content=content,
                )
            )
        if walked_files > max_files:
            break

    content_hash = _bundle_hash(entries)
    if description == "":
        complete = False
        reasons.append("missing declared description")
    return SkillBundle(
        name=name,
        description=description,
        path=str(root),
        content_hash=content_hash,
        markdown=markdown,
        files=tuple(entries),
        complete=complete,
        incomplete_reason="; ".join(dict.fromkeys(reasons)),
    )


def build_virtual_skill_bundle(
    name: Any,
    description: Any,
    proposal_content: Any,
    support_files: Any = None,
    *,
    max_file_bytes: int = 256 * 1024,
) -> SkillBundle:
    """Build a bundle from a Workshop proposal before OpenClaw saves it."""

    content = str(proposal_content or "")
    normalized_name = _normalize_skill_name(name)
    normalized_description = str(description or "").strip()
    if not content.strip():
        raise SkillBundleError("proposal_content is empty")

    files: List[SkillFileEntry] = [
        SkillFileEntry(
            path="SKILL.md",
            sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            size=len(content.encode("utf-8")),
            kind="text",
            mode=0o644,
            content=content[:max_file_bytes],
        )
    ]
    complete = len(content.encode("utf-8")) <= max_file_bytes
    reasons: List[str] = [] if complete else ["SKILL.md exceeds inspection limit"]

    if isinstance(support_files, list):
        for item in support_files:
            if not isinstance(item, Mapping):
                complete = False
                reasons.append("malformed support file entry")
                continue
            relative = str(item.get("path") or "").replace("\\", "/").strip()
            if (
                not relative
                or relative.startswith("/")
                or ".." in Path(relative).parts
            ):
                complete = False
                reasons.append(f"unsafe support file path: {relative or '<empty>'}")
                continue
            file_content = str(item.get("content") or "")
            encoded = file_content.encode("utf-8")
            files.append(
                SkillFileEntry(
                    path=relative,
                    sha256=hashlib.sha256(encoded).hexdigest(),
                    size=len(encoded),
                    kind="text",
                    mode=0o644,
                    content=file_content[:max_file_bytes],
                )
            )
            if len(encoded) > max_file_bytes:
                complete = False
                reasons.append(f"support file exceeds inspection limit: {relative}")

    return SkillBundle(
        name=normalized_name,
        description=normalized_description,
        path=f"proposal:{normalized_name}",
        content_hash=_bundle_hash(files),
        markdown=content,
        files=tuple(files),
        complete=complete,
        incomplete_reason="; ".join(reasons),
    )


def _expanded_roots(roots: Iterable[str]) -> List[Path]:
    result: List[Path] = []
    for value in roots:
        path = Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve()
        if path not in result:
            result.append(path)
    return result


def find_skill_path(name: str, roots: Iterable[str]) -> Optional[Path]:
    normalized = _normalize_skill_name(name)
    for root in _expanded_roots(roots):
        direct = root / normalized
        if (direct / "SKILL.md").is_file() or direct.is_symlink():
            return direct
        nested = root / "skills" / normalized
        if (nested / "SKILL.md").is_file() or nested.is_symlink():
            return nested
        if root.is_dir():
            try:
                for child in root.iterdir():
                    if child.name.casefold() != normalized or not child.is_dir():
                        continue
                    if (child / "SKILL.md").is_file():
                        return child
            except OSError:
                continue
    return None


def resolve_skill_candidate(candidate: str, roots: Iterable[str]) -> Optional[Path]:
    expanded = Path(os.path.expandvars(os.path.expanduser(candidate)))
    possible = [expanded]
    if not expanded.is_absolute():
        possible.extend(root / expanded for root in _expanded_roots(roots))
    for path in possible:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved.is_file() and resolved.name == "SKILL.md":
            return resolved.parent
        if (resolved / "SKILL.md").is_file():
            return resolved
    if candidate.casefold().endswith("skill.md"):
        return find_skill_path(Path(candidate).parent.name, roots)
    return None


class SkillReviewStore:
    """SQLite store for the current Skill inventory and review history."""

    def __init__(self, db_path: str):
        self.db_path = os.path.expanduser(db_path)
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS skill_registry (
                    name TEXT PRIMARY KEY COLLATE NOCASE,
                    skill_path TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    model_verdict TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    markdown TEXT NOT NULL,
                    inspected_at REAL NOT NULL,
                    inspector_model TEXT NOT NULL DEFAULT '',
                    override_verdict TEXT,
                    override_reason TEXT NOT NULL DEFAULT '',
                    overridden_by TEXT NOT NULL DEFAULT '',
                    overridden_at REAL,
                    last_seen_at REAL NOT NULL,
                    review_valid INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS skill_review_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_name TEXT NOT NULL,
                    skill_path TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    model_verdict TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    markdown TEXT NOT NULL,
                    inspected_at REAL NOT NULL,
                    inspector_model TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_skill_history_name
                    ON skill_review_history(skill_name, inspected_at DESC);
                CREATE TABLE IF NOT EXISTS skill_active_sessions (
                    session_id TEXT NOT NULL,
                    skill_name TEXT NOT NULL COLLATE NOCASE,
                    skill_path TEXT NOT NULL,
                    activated_at REAL NOT NULL,
                    PRIMARY KEY (session_id, skill_name)
                );
                CREATE INDEX IF NOT EXISTS idx_skill_active_session
                    ON skill_active_sessions(session_id, activated_at DESC);
                """
            )
            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(skill_registry)"
                ).fetchall()
            }
            if "review_valid" not in columns:
                connection.execute(
                    "ALTER TABLE skill_registry "
                    "ADD COLUMN review_valid INTEGER NOT NULL DEFAULT 1"
                )

    @staticmethod
    def _record(connection: sqlite3.Connection, row: sqlite3.Row) -> Dict[str, Any]:
        record = dict(row)
        record["effective_verdict"] = (
            record.get("override_verdict") or record.get("model_verdict") or "unsafe"
        )
        try:
            record["details"] = json.loads(record.get("details_json") or "{}")
        except (TypeError, ValueError):
            record["details"] = {}
        record["overridden"] = bool(record.get("override_verdict"))
        record["review_valid"] = bool(record.get("review_valid", 1))
        return record

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM skill_registry WHERE name = ? COLLATE NOCASE",
                (_normalize_skill_name(name),),
            ).fetchone()
            return self._record(connection, row) if row else None

    def save(
        self,
        bundle: SkillBundle,
        verdict: SkillVerdict,
        *,
        inspector_model: str = "",
    ) -> Dict[str, Any]:
        now = time.time()
        with self._connect() as connection:
            previous = connection.execute(
                "SELECT * FROM skill_registry WHERE name = ? COLLATE NOCASE",
                (bundle.name,),
            ).fetchone()
            clear_override = bool(
                previous and previous["content_hash"] != bundle.content_hash
            )
            connection.execute(
                """
                INSERT INTO skill_registry (
                    name, skill_path, content_hash, model_verdict, risk_level,
                    reason, details_json, markdown, inspected_at, inspector_model,
                    override_verdict, override_reason, overridden_by, overridden_at,
                    last_seen_at, review_valid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '', '', NULL, ?, 1)
                ON CONFLICT(name) DO UPDATE SET
                    skill_path = excluded.skill_path,
                    content_hash = excluded.content_hash,
                    model_verdict = excluded.model_verdict,
                    risk_level = excluded.risk_level,
                    reason = excluded.reason,
                    details_json = excluded.details_json,
                    markdown = excluded.markdown,
                    inspected_at = excluded.inspected_at,
                    inspector_model = excluded.inspector_model,
                    override_verdict = CASE
                        WHEN skill_registry.content_hash = excluded.content_hash
                        THEN skill_registry.override_verdict
                        ELSE NULL
                    END,
                    override_reason = CASE
                        WHEN skill_registry.content_hash = excluded.content_hash
                        THEN skill_registry.override_reason
                        ELSE ''
                    END,
                    overridden_by = CASE
                        WHEN skill_registry.content_hash = excluded.content_hash
                        THEN skill_registry.overridden_by
                        ELSE ''
                    END,
                    overridden_at = CASE
                        WHEN skill_registry.content_hash = excluded.content_hash
                        THEN skill_registry.overridden_at
                        ELSE NULL
                    END,
                    last_seen_at = excluded.last_seen_at,
                    review_valid = 1
                """,
                (
                    bundle.name,
                    bundle.path,
                    bundle.content_hash,
                    verdict.verdict,
                    verdict.risk_level,
                    verdict.reason,
                    json.dumps(verdict.details, ensure_ascii=False),
                    bundle.markdown,
                    now,
                    inspector_model,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO skill_review_history (
                    skill_name, skill_path, content_hash, model_verdict,
                    risk_level, reason, details_json, markdown, inspected_at,
                    inspector_model
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bundle.name,
                    bundle.path,
                    bundle.content_hash,
                    verdict.verdict,
                    verdict.risk_level,
                    verdict.reason,
                    json.dumps(verdict.details, ensure_ascii=False),
                    bundle.markdown,
                    now,
                    inspector_model,
                ),
            )
            row = connection.execute(
                "SELECT * FROM skill_registry WHERE name = ? COLLATE NOCASE",
                (bundle.name,),
            ).fetchone()
            result = self._record(connection, row)
            result["override_cleared"] = clear_override
            return result

    def touch(self, name: str, skill_path: Optional[str] = None) -> None:
        with self._connect() as connection:
            if skill_path:
                connection.execute(
                    """
                    UPDATE skill_registry
                    SET last_seen_at = ?, skill_path = ?
                    WHERE name = ? COLLATE NOCASE
                    """,
                    (
                        time.time(),
                        str(skill_path),
                        _normalize_skill_name(name),
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE skill_registry
                    SET last_seen_at = ?
                    WHERE name = ? COLLATE NOCASE
                    """,
                    (time.time(), _normalize_skill_name(name)),
                )

    def mark_unavailable(self, name: str, reason: str) -> Optional[Dict[str, Any]]:
        """Invalidate a prior approval when its bundle can no longer be verified."""

        normalized = _normalize_skill_name(name)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT name FROM skill_registry WHERE name = ? COLLATE NOCASE",
                (normalized,),
            ).fetchone()
            if not row:
                return None
            now = time.time()
            details = json.dumps(
                {"incomplete_review": True, "error": reason},
                ensure_ascii=False,
            )
            connection.execute(
                """
                UPDATE skill_registry
                SET model_verdict = 'unsafe',
                    risk_level = 'high',
                    reason = ?,
                    details_json = ?,
                    inspected_at = ?,
                    override_verdict = NULL,
                    override_reason = '',
                    overridden_by = '',
                    overridden_at = NULL,
                    review_valid = 0
                WHERE name = ? COLLATE NOCASE
                """,
                (reason, details, now, normalized),
            )
            updated = connection.execute(
                "SELECT * FROM skill_registry WHERE name = ? COLLATE NOCASE",
                (normalized,),
            ).fetchone()
            return self._record(connection, updated)

    def remember_active(self, session_id: str, name: str, path: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO skill_active_sessions (
                    session_id, skill_name, skill_path, activated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(session_id, skill_name) DO UPDATE SET
                    skill_path = excluded.skill_path,
                    activated_at = excluded.activated_at
                """,
                (
                    str(session_id)[:512],
                    _normalize_skill_name(name),
                    str(path),
                    time.time(),
                ),
            )
            connection.execute(
                """
                DELETE FROM skill_active_sessions
                WHERE rowid NOT IN (
                    SELECT rowid FROM skill_active_sessions
                    ORDER BY activated_at DESC LIMIT 4096
                )
                """
            )

    def active_for(self, session_id: str) -> Dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT skill_name, skill_path
                FROM skill_active_sessions
                WHERE session_id = ?
                ORDER BY activated_at DESC
                """,
                (str(session_id)[:512],),
            ).fetchall()
            return {row["skill_name"]: row["skill_path"] for row in rows}

    def forget_active(self, session_id: str, name: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                DELETE FROM skill_active_sessions
                WHERE session_id = ? AND skill_name = ? COLLATE NOCASE
                """,
                (str(session_id)[:512], _normalize_skill_name(name)),
            )

    def set_override(
        self,
        name: str,
        verdict: Optional[str],
        *,
        reason: str,
        actor: str,
    ) -> Optional[Dict[str, Any]]:
        normalized: Optional[str]
        if verdict is None or str(verdict).strip() == "":
            normalized = None
        else:
            candidate = str(verdict).strip().casefold()
            if candidate in _SAFE_WORDS:
                normalized = "safe"
            elif candidate in _UNSAFE_WORDS:
                normalized = "unsafe"
            else:
                raise ValueError("override verdict must be safe, unsafe, or null")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT name FROM skill_registry WHERE name = ? COLLATE NOCASE",
                (_normalize_skill_name(name),),
            ).fetchone()
            if not row:
                return None
            connection.execute(
                """
                UPDATE skill_registry
                SET override_verdict = ?, override_reason = ?,
                    overridden_by = ?, overridden_at = ?
                WHERE name = ? COLLATE NOCASE
                """,
                (
                    normalized,
                    str(reason or ""),
                    str(actor or "dashboard"),
                    time.time() if normalized else None,
                    _normalize_skill_name(name),
                ),
            )
            updated = connection.execute(
                "SELECT * FROM skill_registry WHERE name = ? COLLATE NOCASE",
                (_normalize_skill_name(name),),
            ).fetchone()
            return self._record(connection, updated)

    def list(self) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM skill_registry ORDER BY name COLLATE NOCASE"
            ).fetchall()
            return [self._record(connection, row) for row in rows]

    def stats(self) -> Dict[str, int]:
        items = self.list()
        model_safe = sum(item["model_verdict"] == "safe" for item in items)
        model_unsafe = sum(item["model_verdict"] == "unsafe" for item in items)
        effective_safe = sum(item["effective_verdict"] == "safe" for item in items)
        effective_unsafe = sum(item["effective_verdict"] == "unsafe" for item in items)
        return {
            "total": len(items),
            "model_safe": model_safe,
            "model_unsafe": model_unsafe,
            "safe": effective_safe,
            "unsafe": effective_unsafe,
            "overridden": sum(bool(item["overridden"]) for item in items),
        }


def parse_judge_verdict(value: Any) -> SkillVerdict:
    """Parse a strict or lightly wrapped judge response without trusting it."""

    payload = value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text)
        try:
            payload = json.loads(text)
        except ValueError:
            decoder = json.JSONDecoder()
            payload = None
            start = text.find("{")
            while start >= 0:
                try:
                    candidate, _ = decoder.raw_decode(text[start:])
                except ValueError:
                    candidate = None
                if isinstance(candidate, Mapping):
                    payload = candidate
                    break
                start = text.find("{", start + 1)
            if payload is None:
                raise ValueError("judge response did not contain a JSON object")
    if not isinstance(payload, Mapping):
        raise ValueError("judge response must be a JSON object")

    reason = str(
        payload.get("summary")
        or payload.get("reason")
        or "The Skill judge did not provide a reason."
    ).strip()
    risk_level = str(payload.get("risk_level") or "").strip()
    details = dict(payload)
    details.pop("verdict", None)
    return SkillVerdict(
        verdict=str(payload.get("verdict") or "UNSAFE"),
        risk_level=risk_level,
        reason=reason,
        details=details,
        source="judge",
    )


class SkillInspector:
    """Review coordinator shared by the gateway and control endpoints."""

    def __init__(
        self,
        store: SkillReviewStore,
        roots: Iterable[str],
        *,
        max_files: int = 256,
        max_file_bytes: int = 256 * 1024,
        max_total_bytes: int = 1024 * 1024,
    ):
        self.store = store
        self.roots = _expanded_roots(roots)
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self._locks: Dict[str, asyncio.Lock] = {}

    def bundle(self, path: str | Path) -> SkillBundle:
        return build_skill_bundle(
            path,
            max_files=self.max_files,
            max_file_bytes=self.max_file_bytes,
            max_total_bytes=self.max_total_bytes,
        )

    def virtual_bundle(
        self,
        name: str,
        description: str,
        content: str,
        support_files: Any = None,
    ) -> SkillBundle:
        return build_virtual_skill_bundle(
            name,
            description,
            content,
            support_files,
            max_file_bytes=self.max_file_bytes,
        )

    def find(self, name: str) -> Optional[Path]:
        return find_skill_path(name, self.roots)

    def resolve(self, candidate: str) -> Optional[Path]:
        return resolve_skill_candidate(candidate, self.roots)

    async def review(
        self,
        bundle: SkillBundle,
        judge,
        *,
        inspector_model: str = "",
        force: bool = False,
    ) -> SkillReview:
        lock = self._locks.setdefault(bundle.name, asyncio.Lock())
        async with lock:
            current = self.store.get(bundle.name)
            if (
                not force
                and current
                and current.get("content_hash") == bundle.content_hash
                and current.get("review_valid", True)
            ):
                self.store.touch(bundle.name, bundle.path)
                current["skill_path"] = bundle.path
                current["last_seen_at"] = time.time()
                return SkillReview(current, bundle, cached=True, hash_changed=False)

            hash_changed = bool(
                current and current.get("content_hash") != bundle.content_hash
            )
            if not bundle.complete:
                verdict = SkillVerdict(
                    verdict="unsafe",
                    risk_level="high",
                    reason=(
                        "The Skill bundle could not be fully inspected: "
                        f"{bundle.incomplete_reason}"
                    ),
                    details={"intent_alignment": {"aligned": False}},
                    source="fail_closed",
                )
            else:
                try:
                    verdict = await judge(bundle)
                    if not isinstance(verdict, SkillVerdict):
                        verdict = parse_judge_verdict(verdict)
                except Exception as exc:
                    # Do not persist transport/parse failures as a permanent
                    # verdict. The denial is safe for this attempt and the next
                    # invocation can retry when the judge recovers.
                    return SkillReview(
                        {
                            "name": bundle.name,
                            "skill_path": bundle.path,
                            "content_hash": bundle.content_hash,
                            "model_verdict": "unsafe",
                            "effective_verdict": "unsafe",
                            "risk_level": "high",
                            "reason": f"Skill judge unavailable: {exc}",
                            "details": {"judge_error": str(exc)},
                            "override_verdict": None,
                            "overridden": False,
                            "inspected_at": time.time(),
                            "last_seen_at": time.time(),
                        },
                        bundle,
                        cached=False,
                        hash_changed=hash_changed,
                    )

            record = self.store.save(
                bundle,
                verdict,
                inspector_model=inspector_model,
            )
            return SkillReview(
                record,
                bundle,
                cached=False,
                hash_changed=hash_changed,
            )

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        return self.store.get(name)

    def list(self) -> List[Dict[str, Any]]:
        return self.store.list()

    def stats(self) -> Dict[str, int]:
        return self.store.stats()

    def override(
        self,
        name: str,
        verdict: Optional[str],
        *,
        reason: str,
        actor: str,
    ) -> Optional[Dict[str, Any]]:
        return self.store.set_override(
            name,
            verdict,
            reason=reason,
            actor=actor,
        )

    def mark_unavailable(self, name: str, reason: str) -> Optional[Dict[str, Any]]:
        return self.store.mark_unavailable(name, reason)

    def remember_active(self, session_id: str, name: str, path: str) -> None:
        self.store.remember_active(session_id, name, path)

    def active_for(self, session_id: str) -> Dict[str, str]:
        return self.store.active_for(session_id)

    def forget_active(self, session_id: str, name: str) -> None:
        self.store.forget_active(session_id, name)
