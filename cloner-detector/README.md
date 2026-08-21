# ClonerHunter

**Defensive scanner for Termux / Facebook "cloning" toolkits.**

ClonerHunter detects credential-stuffing and account-takeover tooling (the
"Facebook cloner / cracker" script family) by fingerprinting its code,
tokens, endpoints, spoofed headers and behavioural patterns. It reads files
and logs only — it **never sends traffic to any target**, never contacts
Facebook, and never touches live accounts.

- **Zero dependencies** — Python 3.8+ standard library only. Works on Linux,
  macOS, Windows and Termux.
- **Static scanning** — text files, plus binary payloads (`.pyc`, `.so`,
  `.apk`, `.jar`, `.exe`…) via embedded-string extraction.
- **40 built-in signatures** — leaked first-party tokens, legacy endpoints,
  spoofed headers, device-login flow fields, password-template guessing
  logic, IP-rotation evasion advice, menu labels, family markers.
- **Risk scoring** — per-file score (0–100) and verdicts:
  `CLEAN / SUSPICIOUS / LIKELY / DEFINITIVE`, plus probable family tagging.
- **Log analysis** — feed it HTTP access logs or traffic dumps; it flags
  signature lines and applies per-source heuristics
  (`LIKELY CREDENTIAL-STUFFING`, `ELEVATED AUTH ACTIVITY`).
- **JSON output** for automation, custom rules via JSON, self-check
  fixtures, and a test suite.

---

## Quick start

```bash
cd cloner-detector
python3 run.py scan /path/to/check
python3 run.py scan ~/storage/downloads ~/termux-home      # Termux style
python3 run.py scan . --json -o report.json                # machine readable
python3 run.py logscan access.log                          # HTTP log analysis
python3 run.py rules                                       # show the signature DB
python3 run.py selfcheck                                   # verify the engine
```

### Scanning this very repository

```bash
python3 run.py scan .. --exclude cloner-detector
```

`AHMAD0.py` in the repo root is a textbook specimen of the tool family and
is flagged `DEFINITIVE` with its family identified.

---

## Commands

### `scan`

```
usage: clonerdetect scan [-h] [--rules FILE] [--min-severity {info,low,medium,high,critical}]
                         [--max-size MB] [--threads N] [--no-binary]
                         [--exclude SUBSTR] [-v] [-q] PATH [PATH ...]
```

| Flag | Meaning |
|---|---|
| `--min-severity` | only report rules at/above this level (default `info`) |
| `--max-size` | read at most N MB of each file (default 10) |
| `--threads` | parallel workers (default `min(8, CPUs)`) |
| `--no-binary` | skip binary payload scanning |
| `--exclude` | skip any path containing the substring (repeatable) |
| `-v` | show every matched signal (default caps at 12 per file) |
| `-q` | suppress banner and progress bar |

Exit codes: `0` = nothing flagged, `1` = findings, `2` = error — handy in CI:

```bash
python3 run.py scan downloads/ -q && echo "clean" || echo "findings"
```

> Note: the scanner's own signature database intentionally contains the
> leaked-token strings it detects. When scanning a tree that includes this
> project, exclude it with `--exclude cloner-detector`.

### `logscan`

```
usage: clonerdetect logscan [-h] [--rules FILE] [--limit N] FILE [FILE ...]
```

Accepts Apache/nginx-style logs (or any line-oriented dump containing URLs).
Detects lines carrying cloner signatures, and aggregates per source IP:
request counts to the legacy auth endpoints, distinct user-agent rotation,
and a credential-stuffing assessment. Use `-` to read stdin:

```bash
cat access.log* | python3 run.py logscan -
```

### `rules`

Lists the full signature database (id, category, severity, weight, name);
`-v` adds descriptions. `--json` exports it.

### `selfcheck`

Runs the bundled fixtures (cloner sample, clean sample, embedded binary
payload, attack log) through the engine and reports PASS/FAIL per check.

---

## Example output

```
  ╔══════════════════════════════════════════════════════════════════╗
  ║ SCAN SUMMARY                                                      ║
  ║   Files scanned : 3                                               ║
  ║   Flagged       : 1   [definitive 1 | likely 0 | suspicious 0]    ║
  ╚══════════════════════════════════════════════════════════════════╝

┌───────────────────────────┬────────┬─────────┬────────────┬─────────┐
│ PATH                      │ SIZE   │ SCORE   │ VERDICT    │ SIGNALS │
├───────────────────────────┼────────┼─────────┼────────────┼─────────┤
│ AHMAD0.py                 │ 36 KB  │ 100/100 │ DEFINITIVE │ 24      │
└───────────────────────────┴────────┴─────────┴────────────┴─────────┘

  ─────────────────────────────────────────────────────────────
  AHMAD0.py   score 100/100  [DEFINITIVE]  Termux Facebook cloner (AHMAD0 / Hannan-404 style)
    [CRITICAL] TOK-FB4A-1  Leaked Facebook-Android (FB4A) app token
        lines: 1, 12 ... (2 total)
        sample: "access_token":"350685531728|62f8ce9f74b12f84c123cc23437a4a32"
    ...
```

## Extending with custom rules

Create a JSON file and pass `--rules my_rules.json` to any command:

```json
[
  {
    "id": "TEAM-001",
    "name": "our internal test marker",
    "description": "flags files tagged with our pentest marker",
    "severity": "high",
    "category": "custom",
    "weight": 12,
    "patterns": ["INTERNAL-PENTEST-MARKER", "re:session_key\\s*=\\s*['\"]"]
  }
]
```

Pattern entries starting with `re:` are compiled as regex
(case-insensitive); all others are literal substrings.

## Testing

```bash
cd cloner-detector
python3 -m unittest discover -s tests -v
```

## How detection works (short version)

The tool family authenticates through a retired Facebook Android-app
"device login" flow using leaked first-party app tokens, rotates spoofed
mobile user-agents and carrier headers, expands per-victim password
templates (`first123`, `last123`, …) in 30 parallel workers, harvests
session cookies, and advises IP rotation via aeroplane mode. Every layer
of that design has a distinct fingerprint, which is exactly what
ClonerHunter's signatures capture — statically (the code says it outright)
and in traffic (the same endpoints, headers and UAs appear in logs).

## Scope & disclaimer

Detection software for defenders, researchers and educators. It performs
no network activity against any third party. Use of the results to attack
or take over accounts without authorisation is illegal in most
jurisdictions. This project exists to make the *defensive* side of this
cat-and-mouse game measurable — not to assist the offensive one.
