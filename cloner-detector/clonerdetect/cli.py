"""Command-line interface for ClonerHunter."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import TOOL_NAME, TOOL_TAGLINE, __version__
from .logscan import (IpStats, LogHit, build_ip_stats, count_auth_requests,
                      parse_log_lines, read_log_source)
from .report import (dumps, logscan_to_json, render_ip_table, render_log_hits,
                     render_log_summary, render_scan_details, render_scan_summary,
                     scan_to_json, write_output)
from .rules import (Rule, SEVERITY_ORDER, load_rules, rules_sorted)
from .scanner import FileResult, scan_paths
from .ui import (Table, banner, bold, cyan, divider, enable_color, green, grey,
                 progressbar, red, yellow)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _fail(msg: str) -> int:
    print(red(f"error: {msg}"), file=sys.stderr)
    return 2


def _print_banner(quiet: bool) -> None:
    if quiet:
        return
    print(banner(__version__, TOOL_TAGLINE))
    print()


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as exc:
        return _fail(str(exc))

    _print_banner(args.quiet or args.json)

    if not args.json:
        print(grey(f"  targets        : {', '.join(args.paths)}"))
        print(grey(f"  rules          : {len(rules)} signatures loaded"
                   + (f" (+ {args.rules})" if args.rules else "")))
        print(grey(f"  min severity   : {args.min_severity}"))
        print(grey(f"  binary scan    : {'on' if args.binary else 'off'}"))
        print(divider())

    if args.quiet or args.json:
        progress = None
    else:
        progress = lambda done, total: print(
            "\r  " + progressbar(done, total), end="", flush=True
        )

    results = scan_paths(
        args.paths,
        rules,
        min_severity=args.min_severity,
        max_size_mb=args.max_size,
        threads=args.threads,
        binary=args.binary,
        exclude=args.exclude or (),
        progress=progress,
    )
    if progress:
        print()

    if args.json:
        write_output(args.out, dumps(scan_to_json(results)))
        return 1 if any(r.flagged for r in results) else 0

    print(render_scan_summary(results))
    print()
    print(divider())
    print(bold("FLAGGED FILES"))
    print()
    table_rows = []
    for r in sorted(
        [x for x in results if x.flagged], key=lambda x: (-x.score, x.path)
    ):
        table_rows.append([
            r.path, f"{r.size // 1024} KB", f"{r.score}/100",
            r.verdict, str(len(r.matches)),
        ])
    if table_rows:
        print(Table(["PATH", "SIZE", "SCORE", "VERDICT", "SIGNALS"],
                    table_rows, max_col=56).render())
    else:
        print(green("  No indicators found - all scanned files are clean."))
    print()
    details = render_scan_details(results, verbose=args.verbose)
    if details:
        print(bold("DETAILS"))
        print(details)
        print()

    for r in results:
        if r.error:
            print(yellow(f"  [!] {r.path}: {r.error}"))
    return 1 if any(r.flagged for r in results) else 0


# ---------------------------------------------------------------------------
# logscan
# ---------------------------------------------------------------------------

def cmd_logscan(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as exc:
        return _fail(str(exc))

    _print_banner(args.quiet or args.json)

    all_hits: List[LogHit] = []
    all_counts: dict = {}
    total_lines = 0
    for src in args.sources:
        try:
            lines = read_log_source(src)
        except OSError as exc:
            return _fail(f"cannot read {src}: {exc}")
        hits = parse_log_lines(lines, rules)
        for h in hits:
            all_hits.append(h)
        counts = count_auth_requests(lines)
        for ip, n in counts.items():
            all_counts[ip] = all_counts.get(ip, 0) + n
        total_lines += len(lines)

    ip_stats: List[IpStats] = build_ip_stats(all_hits, all_counts)

    if args.json:
        write_output(args.out, dumps(logscan_to_json(all_hits, ip_stats)))
        flagged = [s for s in ip_stats if s.verdict.startswith("LIKELY")]
        return 1 if flagged else 0

    if not args.json:
        print(grey(f"  sources        : {', '.join(args.sources)}"))
        print(grey(f"  lines scanned  : {total_lines}"))
        print(grey(f"  flagged lines  : {len(all_hits)}"))
        print(divider())
        print(bold("SOURCE ASSESSMENT"))
    print()
    print(render_ip_table(ip_stats))
    if all_hits:
        print()
        print(bold("FLAGGED LINES"))
        print()
        print(render_log_hits(all_hits, limit=args.limit))
        print()

    stuffing = [s for s in ip_stats if s.verdict.startswith("LIKELY")]
    if stuffing:
        print(red(
            f"  credential-stuffing pattern detected from "
            f"{len(stuffing)} source(s)."))
    else:
        print(green("  no credential-stuffing pattern detected."))
    return 1 if stuffing else 0


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def cmd_rules(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as exc:
        return _fail(str(exc))

    _print_banner(args.quiet or args.json)
    rules = rules_sorted(rules)

    if args.json:
        payload = {
            "tool": TOOL_NAME,
            "version": __version__,
            "kind": "rules",
            "count": len(rules),
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "category": r.category,
                    "severity": r.severity,
                    "weight": r.weight,
                    "description": r.description,
                    "patterns": r.patterns,
                }
                for r in rules
            ],
        }
        write_output(args.out, dumps(payload))
        return 0

    rows = [
        [r.id, r.category, r.severity.upper(), str(r.weight), r.name]
        for r in rules
    ]
    print(bold(f"SIGNATURE DATABASE  ({len(rules)} rules)"))
    print()
    print(Table(["ID", "CATEGORY", "SEVERITY", "WEIGHT", "NAME"],
                rows, max_col=44).render())
    print()
    if args.verbose:
        for r in rules:
            print(f"  {cyan(r.id)}  {grey(r.description)}")
    return 0


# ---------------------------------------------------------------------------
# selfcheck
# ---------------------------------------------------------------------------

def cmd_selfcheck(args: argparse.Namespace) -> int:
    _print_banner(args.quiet or args.json)
    print(bold("SELF-CHECK"))
    print()

    from .rules import load_rules as _lr
    from .scanner import scan_paths as _sp

    checks = [
        ("rules compile (all regexes valid)", lambda: len(_lr()) > 20),
        ("fixture: cloner sample flagged", lambda: _verdict_of(
            _sp([str(FIXTURE_DIR / "cloner_sample.txt")], _lr()),
            ("DEFINITIVE", "LIKELY"))),
        ("fixture: clean sample stays clean", lambda: _verdict_of(
            _sp([str(FIXTURE_DIR / "clean_sample.txt")], _lr()),
            ("CLEAN",))),
        ("fixture: embedded binary payload flagged", lambda: _verdict_of(
            _sp([str(FIXTURE_DIR / "payload.bin")], _lr()),
            ("DEFINITIVE", "LIKELY", "SUSPICIOUS"))),
    ]
    if (FIXTURE_DIR / "http_attack.log").exists():
        checks.append(("fixture: log heuristic flags a source",
                       lambda: _log_flagged()))

    ok = True
    for name, fn in checks:
        try:
            passed = bool(fn())
        except Exception as exc:  # pragma: no cover - defensive
            passed = False
            detail = f" ({exc})"
        else:
            detail = ""
        mark = green("[PASS]") if passed else red("[FAIL]")
        print(f"  {mark} {name}{detail}")
        ok = ok and passed
    print()
    if ok:
        print(green(bold("  all checks passed.")))
        return 0
    print(red(bold("  some checks failed.")))
    return 1


def _verdict_of(results: List[FileResult], expected: tuple) -> bool:
    if not results:
        return False
    verdicts = {r.verdict for r in results if not r.error}
    return bool(verdicts & set(expected))


def _log_flagged() -> bool:
    from .logscan import build_ip_stats, count_auth_requests, parse_log_lines
    from .rules import load_rules as _lr

    lines = (FIXTURE_DIR / "http_attack.log").read_text(
        encoding="utf-8").splitlines()
    hits = parse_log_lines(lines, _lr())
    stats = build_ip_stats(hits, count_auth_requests(lines))
    return any(s.verdict.startswith("LIKELY") for s in stats)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _add_common(sub: argparse.ArgumentParser) -> None:
    """Allow global flags to be given after the subcommand as well."""
    sub.add_argument("--no-color", action="store_true",
                     default=argparse.SUPPRESS,
                     help="disable ANSI colours")
    sub.add_argument("--json", action="store_true",
                     default=argparse.SUPPRESS,
                     help="emit machine-readable JSON")
    sub.add_argument("-o", "--out", metavar="FILE",
                     default=argparse.SUPPRESS,
                     help="write output to FILE ('-' for stdout)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clonerdetect",
        description=(
            f"{TOOL_NAME} {__version__} - {TOOL_TAGLINE}. "
            "Detection only: scans files and logs for signatures of "
            "credential-stuffing toolkits; it never sends traffic to any "
            "target or touches live accounts."
        ),
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {__version__}")
    parser.add_argument("--no-color", action="store_true", default=False,
                        help="disable ANSI colours")
    parser.add_argument("--json", action="store_true", default=False,
                        help="emit machine-readable JSON")
    parser.add_argument("-o", "--out", metavar="FILE", default=None,
                        help="write output to FILE ('-' for stdout)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser(
        "scan", help="scan files/directories for cloner signatures")
    _add_common(p_scan)
    p_scan.add_argument("paths", nargs="+", metavar="PATH",
                        help="files or directories to scan")
    p_scan.add_argument("--rules", metavar="FILE",
                        help="merge extra signatures from a JSON rules file")
    p_scan.add_argument("--min-severity", default="info",
                        choices=list(SEVERITY_ORDER),
                        help="only report rules at/above this severity")
    p_scan.add_argument("--max-size", type=float, default=10.0, metavar="MB",
                        help="skip reading files larger than MB megabytes "
                             "(scan the first MB) [default: 10]")
    p_scan.add_argument("--threads", type=int, default=0, metavar="N",
                        help="worker threads [default: min(8, cpu count)]")
    p_scan.add_argument("--no-binary", dest="binary", action="store_false",
                        help="do not scan binary payloads (pyc/so/apk/jar...)")
    p_scan.add_argument("--exclude", action="append", metavar="SUBSTR",
                        help="skip paths containing this substring "
                             "(repeatable)")
    p_scan.add_argument("-v", "--verbose", action="store_true",
                        help="show every matched signal, not just the top 12")
    p_scan.add_argument("-q", "--quiet", action="store_true",
                        help="suppress banner and progress")
    p_scan.set_defaults(func=cmd_scan)

    p_log = sub.add_parser(
        "logscan", help="scan HTTP access logs / traffic dumps")
    _add_common(p_log)
    p_log.add_argument("sources", nargs="+", metavar="FILE",
                       help="log files ('-' for stdin)")
    p_log.add_argument("--rules", metavar="FILE",
                       help="merge extra signatures from a JSON rules file")
    p_log.add_argument("--limit", type=int, default=40, metavar="N",
                       help="max flagged lines to display [default: 40]")
    p_log.add_argument("-q", "--quiet", action="store_true",
                       help="suppress banner")
    p_log.set_defaults(func=cmd_logscan)

    p_rules = sub.add_parser("rules", help="list the signature database")
    _add_common(p_rules)
    p_rules.add_argument("--rules", metavar="FILE",
                         help="also load a custom rules JSON file")
    p_rules.add_argument("-v", "--verbose", action="store_true",
                         help="print rule descriptions")
    p_rules.add_argument("-q", "--quiet", action="store_true",
                         help="suppress banner")
    p_rules.set_defaults(func=cmd_rules)

    p_self = sub.add_parser("selfcheck", help="run bundled verification fixtures")
    _add_common(p_self)
    p_self.add_argument("-q", "--quiet", action="store_true",
                        help="suppress banner")
    p_self.set_defaults(func=cmd_selfcheck)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    enable_color(not args.no_color and not getattr(args, "json", False))
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(yellow("\ninterrupted."), file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
