"""Signature database for ClonerHunter.

Each rule fingerprints one indicator of the Termux/Facebook "cloning"
(credential-stuffing) tool family. Rules are declarative so users can
extend them via a JSON file without touching code:

    [
      {
        "id": "CUSTOM-1",
        "name": "my custom rule",
        "description": "what it detects",
        "severity": "high",            // info|low|medium|high|critical
        "category": "custom",          // any string
        "weight": 12,                  // optional; default derived from severity
        "patterns": ["literal", "re[gx]"] // mixed; list entries starting with
                                            // "re:" are treated as regex
      }
    ]

All regex patterns are compiled with re.IGNORECASE.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_WEIGHTS = {"info": 1, "low": 2, "medium": 6, "high": 12, "critical": 25}


@dataclass
class Rule:
    id: str
    name: str
    category: str
    severity: str
    weight: int
    description: str
    patterns: List[str] = field(default_factory=list)
    _compiled: List[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        for pat in self.patterns:
            if pat.startswith("re:"):
                self._compiled.append(re.compile(pat[3:], re.IGNORECASE))
            else:
                self._compiled.append(re.compile(re.escape(pat)))

    def match(self, text: str) -> bool:
        return any(p.search(text) for p in self._compiled)


def _mk(rid: str, name: str, category: str, severity: str, description: str,
        *patterns: str, weight: Optional[int] = None) -> Rule:
    return Rule(
        id=rid,
        name=name,
        category=category,
        severity=severity,
        weight=weight if weight is not None else DEFAULT_WEIGHTS[severity],
        description=description,
        patterns=list(patterns),
    )


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------

RULES: List[Rule] = [
    # ---- leaked credentials / tokens --------------------------------
    _mk("TOK-FB4A-1", "Leaked Facebook-Android (FB4A) app token",
        "token", "critical",
        "The publicly-circulated Facebook-for-Android app token pair "
        "(350685531728|62f8ce9f...) used by cloning tools since ~2018. "
        "Its use is a definitive indicator of this tool family.",
        "350685531728|62f8ce9f74b12f84c123cc23437a4a32"),
    _mk("TOK-FB4A-APIKEY", "Leaked FB4A api_key",
        "token", "critical",
        "The public api_key 882a8490... shipped with the FB4A device-login "
        "flow abused by these tools.",
        "882a8490361da98702bf97a021ddc14d"),
    _mk("TOK-APPID", "FB4A application id (350685531728)",
        "token", "critical",
        "Facebook-for-Android app id used by legacy cloning tools.",
        "350685531728"),
    _mk("TOK-FBLITE-1", "Circulated Facebook-Android-Lite token",
        "token", "high",
        "Another publicly-circulated first-party token pair seen in clones "
        "of this tool family.",
        "124024574287414|84a456d620314b6e92a16d8ff1c792dc"),
    _mk("TOK-PIPE-GENERIC", "Hardcoded appid|secret token pair",
        "token", "medium",
        "Generic app-token shape (10-16 digit app id, pipe, 32 hex chars).",
        r"re:\b\d{10,16}\|[0-9a-f]{32}\b", weight=6),
    _mk("TOK-INLINE", "Inline access_token assigned near code",
        "token", "medium",
        "access_token hardcoded next to an assignment or dict key.",
        r"re:access_token[\"']?\s*[:=]\s*[\"']?[0-9]{6,}", weight=6),

    # ---- endpoints ---------------------------------------------------
    _mk("NET-BGRAPH", "Traffic to b-graph.facebook.com",
        "endpoint", "critical",
        "The legacy device-login endpoint (b-graph.facebook.com) used by "
        "cloning tools; not part of any documented public API.",
        "b-graph.facebook.com"),
    _mk("NET-AUTHLOGIN", "POST graph.facebook.com/auth/login",
        "endpoint", "critical",
        "Direct call to the legacy /auth/login device flow with password "
        "in the request body.",
        r"re:(?:b-)?graph\.facebook\.com/auth/login"),
    _mk("NET-MBASIC-APPS", "mbasic apps-settings scraping",
        "endpoint", "high",
        "Scraping mbasic.facebook.com/settings/apps - the cookie/checkpoint "
        "harvesting page used by these tools (mbasic itself was retired in "
        "Dec 2024).",
        r"re:mbasic\.facebook\.com/settings/apps"),
    _mk("NET-CHECKPOINT", "Checkpoint page automation",
        "endpoint", "medium",
        "Automated interaction with Facebook checkpoint pages.",
        r"re:facebook\.com/(?:x/)?checkpoint", weight=8),

    # ---- auth flow fields ---------------------------------------------
    _mk("AUTH-DBLP", "Legacy device-based-login password flow",
        "auth", "critical",
        "credentials_type=device_based_login_password - the retired FB4A "
        "device login flow that this tool family exploited.",
        "device_based_login_password"),
    _mk("AUTH-DBL", "device_based_login source marker",
        "auth", "high",
        "source=device_based_login login requests.",
        r"re:device_based_login(?!_password)"),
    _mk("AUTH-GSC", "generate_session_cookies=1",
        "auth", "high",
        "Requesting session cookies directly from the login response - "
        "used for cookie theft.",
        "generate_session_cookies"),
    _mk("AUTH-FB4A", "Legacy Fb4aAuthHandler caller class",
        "auth", "high",
        "Impersonating the old Facebook-for-Android auth handler.",
        "Fb4aAuthHandler"),
    _mk("AUTH-CPL", "cpl / family_device_id spoof fields",
        "auth", "medium",
        "Checkpoint-protected-login and device-graph spoofing parameters.",
        "family_device_id", weight=7),
    _mk("AUTH-SKEY", "session_key success marker",
        "auth", "medium",
        "Looking for session_key in login responses (success detection of "
        "the legacy flow).",
        "session_key", weight=8),
    _mk("AUTH-SCOOK", "session_cookies extraction",
        "auth", "medium",
        "Parsing session_cookies from the login response body.",
        r"re:(?<!generate_)session_cookies", weight=8),
    _mk("AUTH-COOKIESYNTH", "Synthesised sb= cookie prefix",
        "auth", "high",
        "Fabricating Facebook cookies by prepending a random sb= value to "
        "harvested session cookies.",
        "sb={ssbb}", r"re:b64encode\(os\.urandom\(18\)\)", weight=12),

    # ---- spoofed headers ----------------------------------------------
    _mk("HDR-NETHNI", "X-FB-Net-HNI carrier spoofing",
        "header", "high",
        "Spoofing mobile-network HNI codes (e.g. 45204 - Vietnam) to fake "
        "carrier identity.",
        "X-FB-Net-HNI"),
    _mk("HDR-SIMHNI", "X-FB-SIM-HNI SIM spoofing",
        "header", "high",
        "Spoofing SIM-card HNI codes.",
        "X-FB-SIM-HNI", weight=10),
    _mk("HDR-SESSID", "x-fb-session-id fabrication",
        "header", "medium",
        "Hardcoded/forged internal session identifiers.",
        "x-fb-session-id", weight=6),
    _mk("HDR-CONNTOK", "x-fb-connection-token",
        "header", "medium",
        "Forged connection token header.",
        "x-fb-connection-token", weight=6),
    _mk("HDR-FRIENDLY", "X-FB-Friendly-Name graphservice tag",
        "header", "medium",
        "Internal request analytics tagging used to look like first-party "
        "app traffic.",
        "X-FB-Friendly-Name", weight=6),
    _mk("HDR-TIGON", "X-Tigon-Is-Retry header",
        "header", "low",
        "Internal retry marker header.",
        "X-Tigon-Is-Retry", weight=3),
    _mk("HDR-CLIENTIP", "X-FB-Client-IP: True",
        "header", "low",
        "Claiming a client IP - used to bypass IP-based checks.",
        "X-FB-Client-IP", weight=3),

    # ---- user agents ----------------------------------------------------
    _mk("UA-DALVIK", "Dalvik Android user-agent list",
        "ua", "medium",
        "Bundled lists of Dalvik user-agents (generic Android UA spam).",
        r"re:Dalvik/2\.1\.0 \(Linux; U; Android", weight=7),
    _mk("UA-FBAN", "Facebook in-app UA tags",
        "ua", "low",
        "First-party app UA markers ([FBAN/..., FBAV/...).",
        "[FBAN/", "FBAV/", weight=3),
    _mk("UA-ORCA", "Messenger in-app browser UA",
        "ua", "medium",
        "Orca (Messenger) in-app browser user-agent used to look like "
        "legit messenger traffic.",
        "FB_IAB/Orca-Android", weight=7),

    # ---- code behaviour / family signatures ------------------------------
    _mk("CODE-PWTMPL", "first/last password template mutation",
        "behavior", "critical",
        "Expanding per-victim password templates (first123, last123, "
        "firstlast...) - the core guessing strategy of this tool family.",
        r"re:\.replace\(\s*[\"']first[\"']\s*,",
        "firstlast first123 last123"),
    _mk("CODE-POOL30", "30-worker credential pool",
        "behavior", "medium",
        "Hardcoded 30-thread worker pool for parallel login attempts.",
        r"re:max_workers\s*=\s*30", weight=7),
    _mk("CODE-SDCARD", "Result dump to /sdcard (Termux/Android)",
        "behavior", "high",
        "Writing harvested credentials to /sdcard - characteristic of "
        "Termux-based mobile tooling.",
        "/sdcard/"),
    _mk("CODE-OKFILE", "OK/CP hit-file naming",
        "behavior", "high",
        "Writing hits to files named *-OK.txt / *-CP.txt (OK = cracked "
        "password, CP = checkpoint).",
        "AHMADO-OK", "AHMADO-CP",
        r"re:/[A-Za-z0-9_-]*OK\.txt", r"re:/[A-Za-z0-9_-]*CP\.txt",
        weight=10),
    _mk("CODE-AEROPLANE", "Aeroplane-mode IP rotation advice",
        "behavior", "high",
        "Instruction to toggle aeroplane mode to rotate IPs while "
        "credential-stuffing - an explicit evasion technique.",
        r"re:aero\s*plane|air\s*plane", weight=14),
    _mk("CODE-GITPULL", "Self-updating git pull at import",
        "behavior", "low",
        "Executing git pull / deleting marker files at import time.",
        r"re:os\.system\([\"']git pull", "git pull -q", weight=3),
    _mk("CODE-CLEAR", "Termux clear-screen banner pattern",
        "behavior", "low",
        "Shelling out to clear/rm from Python (typical Termux banner code).",
        r"re:os\.system\([\"']clear[\"']\)", weight=2),
    _mk("CODE-CHECKBRANCH", "Checkpoint branching on login response",
        "behavior", "medium",
        "Branching on checkpoint/checkpoint_required in the login response.",
        "checkpoint_required",
        r"re:elif\s+[\"']checkpoint[\"']\s+in\s+response", weight=8),
    _mk("CODE-CPACC", "CP/OK hit accounting variables",
        "behavior", "low",
        "Trackers for cracked (okacc) and checkpointed (cpacc) accounts.",
        "cpacc", "okacc", weight=2),
    _mk("MENU-CLONING", "'CLONING' menu labels",
        "menu", "critical",
        "Menu entries offering FILE CLONING / RANDOM CLONING / GMAIL "
        "CLONING - direct admission of purpose.",
        "FILE CLONING", "RANDOM CLONING", "GMAIL CLONING", "PAK RANDOM CLONING"),
    _mk("FAM-HANNAN", "Hannan-404 family marker",
        "family", "medium",
        "String referencing the Hannan-404 tool family that this script "
        "family descends from.",
        "Hannan-404", "Hannan", ".Hannan", weight=6),
    _mk("FAM-AHMAD", "AHMAD0/AHMADO family marker",
        "family", "low",
        "References to the AHMAD0/AHMADO branding of this tool family.",
        "AHMAD0", "AHMADO", weight=2),
]

_RULES_BY_ID = {r.id: r for r in RULES}

# Rules whose presence strongly identifies the tool family (used to tag a
# detected file with a probable family name).
FAMILY_SIGNATURE_IDS = {
    "TOK-FB4A-1", "TOK-FB4A-APIKEY", "TOK-APPID", "NET-BGRAPH",
    "NET-AUTHLOGIN", "AUTH-DBLP", "AUTH-FB4A", "CODE-PWTMPL",
    "CODE-AEROPLANE", "CODE-SDCARD", "MENU-CLONING", "FAM-HANNAN",
    "AUTH-COOKIESYNTH", "HDR-NETHNI", "CODE-OKFILE",
}

FAMILY_LABEL = "Termux Facebook cloner (AHMAD0 / Hannan-404 style)"


def detect_family(matched_ids: List[str]) -> Optional[str]:
    hits = [i for i in matched_ids if i in FAMILY_SIGNATURE_IDS]
    if len(hits) >= 3:
        return FAMILY_LABEL
    if len(hits) >= 2:
        return "Possible cloner-family variant"
    return None


def load_rules(extra_path: Optional[str] = None) -> List[Rule]:
    """Return built-in rules, optionally merged with a user rules JSON."""
    rules = list(RULES)
    if extra_path:
        with open(extra_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, list):
            raise ValueError(f"Rules file {extra_path}: expected a JSON list")
        for i, entry in enumerate(raw):
            if not isinstance(entry, dict):
                raise ValueError(f"Rules file {extra_path}: entry #{i} is not an object")
            rid = entry.get("id")
            if not rid:
                raise ValueError(f"Rules file {extra_path}: entry #{i} missing 'id'")
            if rid in _RULES_BY_ID:
                raise ValueError(f"Rules file {extra_path}: duplicate id {rid!r}")
            severity = entry.get("severity", "medium")
            if severity not in SEVERITY_ORDER:
                raise ValueError(f"Rules file {extra_path}: bad severity {severity!r} for {rid}")
            weight = entry.get("weight", DEFAULT_WEIGHTS[severity])
            rules.append(Rule(
                id=rid,
                name=entry.get("name", rid),
                category=entry.get("category", "custom"),
                severity=severity,
                weight=int(weight),
                description=entry.get("description", "Custom rule"),
                patterns=[str(p) for p in entry.get("patterns", [])],
            ))
    # Sanity: unique ids, valid regexes (Rule.compile raises on bad regex).
    seen = set()
    for r in rules:
        if r.id in seen:
            raise ValueError(f"Duplicate rule id {r.id!r}")
        seen.add(r.id)
    return rules


def rules_sorted(rules: List[Rule]) -> List[Rule]:
    return sorted(
        rules,
        key=lambda r: (SEVERITY_ORDER[r.severity], r.category, r.id),
        reverse=True,
    )
