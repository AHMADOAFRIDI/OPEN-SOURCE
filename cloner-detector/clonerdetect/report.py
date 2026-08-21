"""Report rendering: human-readable tables and structured JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from . import TOOL_NAME, __version__
from .logscan import IpStats, LogHit
from .scanner import FileResult
from .ui import (Table, bold, cyan, divider, grey, green, red, style_severity,
                 style_verdict, yellow)

MAX_DETAIL_MATCHES = 12


# ---------------------------------------------------------------------------
# scan rendering
# ---------------------------------------------------------------------------

def render_scan_summary(results: Sequence[FileResult]) -> str:
    flagged = [r for r in results if r.flagged]
    definitive = sum(1 for r in flagged if r.verdict == "DEFINITIVE")
    likely = sum(1 for r in flagged if r.verdict == "LIKELY")
    suspicious = sum(1 for r in flagged if r.verdict == "SUSPICIOUS")
    errors = sum(1 for r in results if r.error)
    lines = [
        bold("SCAN SUMMARY"),
        f"  Files scanned : {len(results)}",
        f"  Flagged       : {len(flagged)}   "
        f"[definitive {definitive} | likely {likely} | suspicious {suspicious}]",
    ]
    if errors:
        lines.append(f"  Read errors   : {errors}")
    return "\n".join(lines)


def render_scan_table(results: Sequence[FileResult]) -> str:
    flagged = sorted(
        [r for r in results if r.flagged],
        key=lambda r: (-r.score, r.path),
    )
    if not flagged:
        return green("  No indicators found - nothing flagged.")
    rows = []
    for r in flagged:
        rows.append([
            r.path,
            f"{r.size // 1024} KB",
            f"{r.score}/100",
            r.verdict,
            str(len(r.matches)),
            r.family or "-",
        ])
    table = Table(
        ["PATH", "SIZE", "SCORE", "VERDICT", "SIGNALS", "FAMILY"],
        rows, max_col=56,
    )
    out = []
    for r in flagged:
        verdict = style_verdict(r.verdict)
        out.append(verdict + "  " + bold(r.path))
    return "\n".join(out)


def render_scan_details(results: Sequence[FileResult],
                        verbose: bool = False) -> str:
    flagged = sorted(
        [r for r in results if r.flagged],
        key=lambda r: (-r.score, r.path),
    )
    if not flagged:
        return ""
    blocks = []
    for r in flagged:
        head = (
            f"{divider('─', '')}\n"
            f"{bold(r.path)}   score {r.score}/100  [{style_verdict(r.verdict)}]"
        )
        if r.family:
            head += f"  {cyan(r.family)}"
        if r.binary:
            head += f"  {grey('[binary payload]')}"
        if r.truncated:
            head += f"  {grey('[truncated]')}"
        lines = [head]
        shown = r.matches if verbose else r.matches[:MAX_DETAIL_MATCHES]
        for m in shown:
            sev = style_severity(m.rule.severity)
            lines.append(f"  {sev} {cyan(m.rule.id)}  {m.rule.name}")
            lines.append(f"      lines: {m.describe()}")
            if m.sample:
                lines.append(f"      sample: {grey(m.sample)}")
        if not verbose and len(r.matches) > MAX_DETAIL_MATCHES:
            lines.append(grey(
                f"  ... {len(r.matches) - MAX_DETAIL_MATCHES} more signals "
                f"(re-run with -v for all)"))
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _file_result_to_dict(r: FileResult) -> Dict[str, Any]:
    return {
        "path": r.path,
        "size_bytes": r.size,
        "binary": r.binary,
        "truncated": r.truncated,
        "score": r.score,
        "verdict": r.verdict,
        "family": r.family,
        "error": r.error,
        "matches": [
            {
                "rule_id": m.rule.id,
                "rule_name": m.rule.name,
                "category": m.rule.category,
                "severity": m.rule.severity,
                "weight": m.rule.weight,
                "lines": m.lines,
                "count": m.count,
                "sample": m.sample,
            }
            for m in r.matches
        ],
    }


def scan_to_json(results: Sequence[FileResult]) -> Dict[str, Any]:
    flagged = [r for r in results if r.flagged]
    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "kind": "filescan",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "files_scanned": len(results),
            "flagged": len(flagged),
            "definitive": sum(1 for r in flagged if r.verdict == "DEFINITIVE"),
            "likely": sum(1 for r in flagged if r.verdict == "LIKELY"),
            "suspicious": sum(1 for r in flagged if r.verdict == "SUSPICIOUS"),
            "clean": sum(1 for r in results if r.verdict == "CLEAN"),
        },
        "results": [_file_result_to_dict(r) for r in results],
    }


# ---------------------------------------------------------------------------
# logscan rendering
# ---------------------------------------------------------------------------

def render_log_summary(hits: Sequence[LogHit],
                       ip_stats: Sequence[IpStats]) -> str:
    lines = [
        bold("LOG SCAN SUMMARY"),
        f"  Lines scanned : (see detail)",
        f"  Flagged lines : {len(hits)}",
        f"  Sources       : {len(ip_stats)}",
    ]
    return "\n".join(lines)


def render_ip_table(ip_stats: Sequence[IpStats]) -> str:
    flagged = [s for s in ip_stats if s.auth_requests or s.hits]
    if not flagged:
        return green("  No suspicious sources found.")
    rows = [
        [s.ip, str(s.auth_requests), str(s.hits), str(s.distinct_uas), s.verdict]
        for s in flagged
    ]
    return Table(
        ["SOURCE IP", "AUTH REQS", "FLAG LINES", "DISTINCT UAS", "ASSESSMENT"],
        rows, max_col=32,
    ).render()


def render_log_hits(hits: Sequence[LogHit], limit: int = 40) -> str:
    if not hits:
        return ""
    shown = hits[:limit]
    rows = [
        [str(h.line_no), h.source_ip, h.rule.id, h.rule.severity.upper(),
         h.url[:48] or "-"]
        for h in shown
    ]
    out = [Table(["LINE", "IP", "RULE", "SEV", "URL"], rows, max_col=48).render()]
    if len(hits) > limit:
        out.append(grey(f"  ... {len(hits) - limit} more flagged lines"))
    return "\n".join(out)


def logscan_to_json(hits: Sequence[LogHit],
                    ip_stats: Sequence[IpStats]) -> Dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "kind": "logscan",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "flagged_lines": len(hits),
            "sources": len(ip_stats),
            "stuffing_sources": sum(
                1 for s in ip_stats if s.verdict == "LIKELY CREDENTIAL-STUFFING"),
        },
        "sources": [
            {
                "ip": s.ip,
                "auth_requests": s.auth_requests,
                "flagged_lines": s.hits,
                "distinct_uas": s.distinct_uas,
                "assessment": s.verdict,
                "uas": s.uas[:10],
            }
            for s in ip_stats
        ],
        "hits": [
            {
                "line_no": h.line_no,
                "source_ip": h.source_ip,
                "rule_id": h.rule.id,
                "rule_name": h.rule.name,
                "severity": h.rule.severity,
                "url": h.url,
                "sample": h.sample,
            }
            for h in hits
        ],
    }


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

def write_output(path: Optional[str], content: str) -> None:
    if not path or path == "-":
        print(content)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def dumps(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)
