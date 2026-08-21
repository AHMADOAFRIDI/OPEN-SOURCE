"""Unit tests for ClonerHunter (stdlib unittest - no dependencies)."""

import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
sys.path.insert(0, str(PROJECT))

from clonerdetect.logscan import (build_ip_stats, count_auth_requests,  # noqa: E402
                                  parse_log_lines)
from clonerdetect.report import logscan_to_json, scan_to_json  # noqa: E402
from clonerdetect.rules import RULES, load_rules  # noqa: E402
from clonerdetect.scanner import scan_paths  # noqa: E402

FIX = PROJECT / "fixtures"


class TestRules(unittest.TestCase):
    def test_ids_unique(self):
        ids = [r.id for r in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_rules_compile_and_match(self):
        for r in RULES:
            self.assertTrue(r.match("x") is False or True)  # no exception
            self.assertIsInstance(r.weight, int)
            self.assertTrue(r.weight > 0)

    def test_custom_rules_load_and_validate(self):
        extra = FIX / "custom_rules.json"
        extra.write_text(json.dumps([
            {"id": "X-1", "patterns": ["totallyfakeindicator"],
             "severity": "high", "description": "test"},
        ]))
        try:
            rules = load_rules(str(extra))
            self.assertGreater(len(rules), len(RULES))
            custom = [r for r in rules if r.id == "X-1"]
            self.assertTrue(custom and custom[0].match("a totallyfakeindicator here"))
        finally:
            extra.unlink()

    def test_duplicate_custom_id_rejected(self):
        extra = FIX / "bad_rules.json"
        extra.write_text(json.dumps([
            {"id": RULES[0].id, "patterns": ["x"], "severity": "low"},
        ]))
        try:
            with self.assertRaises(ValueError):
                load_rules(str(extra))
        finally:
            extra.unlink()


class TestScanner(unittest.TestCase):
    def test_cloner_sample_definitive(self):
        results = scan_paths([str(FIX / "cloner_sample.txt")], RULES)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertIn(r.verdict, ("DEFINITIVE", "LIKELY"))
        self.assertGreater(r.score, 50)
        ids = {m.rule.id for m in r.matches}
        for expected in ("TOK-FB4A-1", "NET-BGRAPH", "AUTH-DBLP",
                         "CODE-PWTMPL", "MENU-CLONING"):
            self.assertIn(expected, ids, f"expected rule {expected} to fire")
        self.assertIsNotNone(r.family)

    def test_clean_sample_clean(self):
        results = scan_paths([str(FIX / "clean_sample.txt")], RULES)
        self.assertEqual(results[0].verdict, "CLEAN")
        self.assertEqual(results[0].matches, [])

    def test_binary_payload_flagged(self):
        results = scan_paths([str(FIX / "payload.bin")], RULES)
        r = results[0]
        self.assertTrue(r.binary)
        self.assertIn(r.verdict, ("DEFINITIVE", "LIKELY", "SUSPICIOUS"))
        ids = {m.rule.id for m in r.matches}
        self.assertIn("TOK-FB4A-1", ids)

    def test_no_binary_skips_payload(self):
        results = scan_paths([str(FIX / "payload.bin")], RULES, binary=False)
        self.assertEqual(results[0].verdict, "SKIPPED")

    def test_min_severity_filters(self):
        results = scan_paths([str(FIX / "clean_sample.txt")], RULES,
                             min_severity="critical")
        self.assertEqual(results[0].matches, [])

    def test_scores_bounded(self):
        results = scan_paths([str(FIX / "cloner_sample.txt")], RULES)
        self.assertLessEqual(results[0].score, 100)

    def test_scan_json_serializable(self):
        results = scan_paths([str(FIX / "cloner_sample.txt")], RULES)
        payload = scan_to_json(results)
        self.assertIsInstance(json.dumps(payload), str)


class TestLogScan(unittest.TestCase):
    def setUp(self):
        self.lines = (FIX / "http_attack.log").read_text(
            encoding="utf-8").splitlines()

    def test_hits_found(self):
        hits = parse_log_lines(self.lines, RULES)
        self.assertGreaterEqual(len(hits), 3)
        ids = {h.rule.id for h in hits}
        self.assertIn("NET-BGRAPH", ids)

    def test_stuffing_source_flagged(self):
        hits = parse_log_lines(self.lines, RULES)
        counts = count_auth_requests(self.lines)
        stats = build_ip_stats(hits, counts)
        attackers = [s for s in stats
                     if s.verdict == "LIKELY CREDENTIAL-STUFFING"]
        self.assertTrue(attackers)
        self.assertEqual(attackers[0].ip, "203.0.113.7")
        self.assertGreaterEqual(attackers[0].auth_requests, 8)

    def test_benign_source_not_flagged(self):
        hits = parse_log_lines(self.lines, RULES)
        stats = build_ip_stats(hits, count_auth_requests(self.lines))
        # A source with no signals simply does not appear in the stats.
        benign = next((s for s in stats if s.ip == "203.0.113.9"), None)
        self.assertIsNone(benign)

    def test_logscan_json_serializable(self):
        hits = parse_log_lines(self.lines, RULES)
        stats = build_ip_stats(hits, count_auth_requests(self.lines))
        self.assertIsInstance(json.dumps(logscan_to_json(hits, stats)), str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
