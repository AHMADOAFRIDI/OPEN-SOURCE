"""Log / traffic-dump scanning with per-source heuristics."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .rules import Rule

_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_UA_RE = re.compile(r"\"(Mozilla|Dalvik|okhttp|FBAndroid)[^\"]*\"")

AUTH_REQUEST_PATTERNS = (
    re.compile(r"(?:b-)?graph\.facebook\.com/auth/login", re.IGNORECASE),
    re.compile(r"mbasic\.facebook\.com", re.IGNORECASE),
    re.compile(r"facebook\.com/(?:x/)?checkpoint", re.IGNORECASE),
)


@dataclass
class LogHit:
    line_no: int
    source_ip: str
    rule: Rule
    url: str = ""
    sample: str = ""


@dataclass
class IpStats:
    ip: str
    hits: int = 0
    auth_requests: int = 0
    uas: List[str] = field(default_factory=list)
    verdict: str = ""

    @property
    def distinct_uas(self) -> int:
        return len(set(self.uas))


def _is_auth_request(line: str) -> bool:
    return any(p.search(line) for p in AUTH_REQUEST_PATTERNS)


def _extract_ua(line: str) -> Optional[str]:
    m = _UA_RE.search(line)
    return m.group(0) if m else None


def parse_log_lines(lines: Sequence[str], rules: Sequence[Rule],
                    start_line: int = 1) -> List[LogHit]:
    hits: List[LogHit] = []
    for offset, line in enumerate(lines):
        line_no = start_line + offset
        ip_match = _IP_RE.match(line.strip())
        source_ip = ip_match.group(1) if ip_match else "-"
        url_match = _URL_RE.search(line)
        url = url_match.group(0) if url_match else ""
        for rule in rules:
            if rule.match(line):
                hits.append(LogHit(
                    line_no=line_no, source_ip=source_ip, rule=rule,
                    url=url, sample=line.strip()[:200],
                ))
    return hits


def build_ip_stats(hits: Sequence[LogHit],
                   auth_requests: Dict[str, int]) -> List[IpStats]:
    per_ip: Dict[str, IpStats] = {}
    for h in hits:
        stats = per_ip.setdefault(h.source_ip, IpStats(ip=h.source_ip))
        stats.hits += 1
    for ip, count in auth_requests.items():
        stats = per_ip.setdefault(ip, IpStats(ip=ip))
        stats.auth_requests = count
    for h in hits:
        stats = per_ip.get(h.source_ip)
        if stats is not None:
            ua = _extract_ua(h.sample)
            if ua and ua not in stats.uas:
                stats.uas.append(ua)
    out = list(per_ip.values())
    for stats in out:
        if stats.auth_requests >= 8:
            stats.verdict = "LIKELY CREDENTIAL-STUFFING"
        elif stats.auth_requests >= 3:
            stats.verdict = "ELEVATED AUTH ACTIVITY"
        else:
            stats.verdict = "NO PATTERN"
    return sorted(out, key=lambda s: (-s.auth_requests, -s.hits, s.ip))


def count_auth_requests(lines: Sequence[str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for line in lines:
        if not _is_auth_request(line):
            continue
        ip_match = _IP_RE.match(line.strip())
        ip = ip_match.group(1) if ip_match else "-"
        counts[ip] = counts.get(ip, 0) + 1
    return counts


def read_log_source(path: str) -> List[str]:
    if path == "-":
        import sys
        return sys.stdin.read().splitlines()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()
