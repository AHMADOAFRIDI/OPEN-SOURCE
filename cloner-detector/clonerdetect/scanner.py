"""File scanning engine: static + binary (strings) analysis."""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from .rules import Rule, detect_family

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "dist", "build",
    ".idea", ".vscode",
}

MAX_LINES_PER_RULE = 20
BINARY_STRINGS_MIN = 6
_TEXT_CHUNK = 8192

_SEVERITY_LEVEL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Match:
    rule: Rule
    lines: List[Optional[int]] = field(default_factory=list)
    count: int = 0
    sample: str = ""

    def describe(self) -> str:
        where = ", ".join(str(l) for l in self.lines[:5]) if self.lines else "-"
        more = f" ... ({self.count} total)" if len(self.lines) < self.count else ""
        return f"{where}{more}"


@dataclass
class FileResult:
    path: str
    size: int = 0
    binary: bool = False
    truncated: bool = False
    score: int = 0
    verdict: str = "CLEAN"
    family: Optional[str] = None
    matches: List[Match] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def flagged(self) -> bool:
        return self.verdict != "CLEAN"

    @property
    def critical_count(self) -> int:
        return sum(1 for m in self.matches if m.rule.severity == "critical")


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def extract_strings(data: bytes, min_len: int = BINARY_STRINGS_MIN) -> str:
    """Printable-ASCII runs extracted from arbitrary binary payloads."""
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    return "\n".join(run.decode("latin-1", "replace") for run in runs)


def scan_text(text: str, rules: Sequence[Rule],
              min_severity: str = "info") -> List[Match]:
    """Scan text; returns one Match per rule that fired."""
    min_level = _SEVERITY_LEVEL.get(min_severity, 0)
    active = [r for r in rules if _SEVERITY_LEVEL.get(r.severity, 0) >= min_level]
    matches: List[Match] = []
    for rule in active:
        lines: List[Optional[int]] = []
        count = 0
        sample = ""
        for lineno, line in enumerate(text.splitlines(), 1):
            if rule.match(line):
                count += 1
                if len(lines) < MAX_LINES_PER_RULE:
                    lines.append(lineno)
                if not sample:
                    sample = line.strip()[:180]
        if count:
            matches.append(Match(rule=rule, lines=lines, count=count, sample=sample))
    return matches


def _compute_verdict(score: int, matches: Sequence[Match]) -> str:
    crit = sum(1 for m in matches if m.rule.severity == "critical")
    if crit >= 2 or (crit >= 1 and score >= 60):
        return "DEFINITIVE"
    if crit >= 1 or score >= 50:
        return "LIKELY"
    if score >= 20:
        return "SUSPICIOUS"
    return "CLEAN"


def _analyze(content: bytes, rules: Sequence[Rule],
             min_severity: str, truncated: bool) -> FileResult:
    binary = _is_binary(content[: _TEXT_CHUNK])
    if binary:
        text = extract_strings(content)
    else:
        text = content.decode("utf-8", "replace")
    matches = scan_text(text, rules, min_severity)
    score = min(100, sum(m.rule.weight for m in matches))
    verdict = _compute_verdict(score, matches)
    family = None
    if verdict in ("DEFINITIVE", "LIKELY"):
        family = detect_family([m.rule.id for m in matches])
    return FileResult(
        path="", size=len(content), binary=binary, truncated=truncated,
        score=score, verdict=verdict, family=family, matches=matches,
    )


def _read_limited(path: str, max_bytes: int):
    size = os.path.getsize(path)
    truncated = size > max_bytes
    with open(path, "rb") as fh:
        content = fh.read(max_bytes)
    return content, truncated


def _iter_files(paths: Sequence[str],
                exclude: Sequence[str]) -> List[str]:
    """Collect files to scan (deterministic order, skips VCS/deps dirs)."""
    found: List[str] = []
    seen = set()
    for raw in paths:
        p = os.path.abspath(os.path.expanduser(raw))
        if os.path.isfile(p):
            key = os.path.realpath(p)
            if key not in seen:
                seen.add(key)
                found.append(p)
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(
                d for d in dirs
                if d not in SKIP_DIRS and not _excluded(os.path.join(root, d), exclude)
            )
            for name in sorted(files):
                fp = os.path.join(root, name)
                if _excluded(fp, exclude):
                    continue
                key = os.path.realpath(fp)
                if key in seen:
                    continue
                seen.add(key)
                found.append(fp)
    return sorted(found)


def _excluded(path: str, exclude: Sequence[str]) -> bool:
    if not exclude:
        return False
    low = path.lower()
    return any(e.lower() in low for e in exclude if e)


def scan_paths(
    paths: Sequence[str],
    rules: Sequence[Rule],
    *,
    min_severity: str = "info",
    max_size_mb: float = 10.0,
    threads: int = 0,
    binary: bool = True,
    exclude: Sequence[str] = (),
    progress: Optional[Callable[[int, int], None]] = None,
) -> List[FileResult]:
    if isinstance(paths, str):
        paths = (paths,)
    if isinstance(exclude, str):
        exclude = (exclude,)
    files = _iter_files(paths, exclude)
    if threads <= 0:
        threads = min(8, os.cpu_count() or 4)
    max_bytes = int(max_size_mb * 1024 * 1024)

    results: List[FileResult] = []

    def scan_one(fp: str) -> FileResult:
        try:
            content, truncated = _read_limited(fp, max_bytes)
        except (OSError, PermissionError, IsADirectoryError) as exc:
            return FileResult(path=fp, error=str(exc))
        if not binary and _is_binary(content[: _TEXT_CHUNK]):
            return FileResult(path=fp, size=len(content), verdict="SKIPPED",
                              error="binary file (use --binary to scan)")
        res = _analyze(content, rules, min_severity, truncated)
        res.path = fp
        return res

    if threads == 1:
        for i, fp in enumerate(files, 1):
            results.append(scan_one(fp))
            if progress:
                progress(i, len(files))
    else:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            for i, res in enumerate(pool.map(scan_one, files), 1):
                results.append(res)
                if progress:
                    progress(i, len(files))
    return results
