#!/usr/bin/env python3
"""
Unit tests for PhishCatch v2.0

Tests cover:
  - PermutationEngine: all four mutation techniques
  - RiskAssessor: all risk combinations and age penalty escalation
  - DomainResult: data model serialization
"""

import unittest
from phishcatch import DomainResult, PermutationEngine, RiskAssessor


class TestPermutationEngineInit(unittest.TestCase):
    """Tests for PermutationEngine initialization and domain parsing."""

    def test_simple_domain(self) -> None:
        engine = PermutationEngine("google.com")
        self.assertEqual(engine.name, "google")
        self.assertEqual(engine.tld, "com")

    def test_compound_tld(self) -> None:
        engine = PermutationEngine("google.com.br")
        self.assertEqual(engine.name, "google")
        self.assertEqual(engine.tld, "com.br")

    def test_invalid_domain_raises(self) -> None:
        with self.assertRaises(ValueError):
            PermutationEngine("nodots")


class TestPermutationOmission(unittest.TestCase):
    """Tests for the omission (character removal) technique."""

    def test_omission_count(self) -> None:
        engine = PermutationEngine("test.com")
        results = engine.omission()
        # 'test' has 4 chars -> 4 omissions
        self.assertEqual(len(results), 4)

    def test_omission_values(self) -> None:
        engine = PermutationEngine("abc.com")
        results = engine.omission()
        expected = ["bc.com", "ac.com", "ab.com"]
        self.assertEqual(sorted(results), sorted(expected))

    def test_omission_single_char(self) -> None:
        engine = PermutationEngine("a.com")
        # Removing the only char yields empty string -> should be excluded
        results = engine.omission()
        self.assertEqual(results, [])


class TestPermutationRepetition(unittest.TestCase):
    """Tests for the repetition (character duplication) technique."""

    def test_repetition_count(self) -> None:
        engine = PermutationEngine("test.com")
        results = engine.repetition()
        self.assertEqual(len(results), 4)

    def test_repetition_values(self) -> None:
        engine = PermutationEngine("ab.com")
        results = engine.repetition()
        expected = ["aab.com", "abb.com"]
        self.assertEqual(sorted(results), sorted(expected))

    def test_repetition_preserves_tld(self) -> None:
        engine = PermutationEngine("test.org")
        for domain in engine.repetition():
            self.assertTrue(domain.endswith(".org"))


class TestPermutationTransposition(unittest.TestCase):
    """Tests for the transposition (adjacent swap) technique."""

    def test_transposition_count(self) -> None:
        engine = PermutationEngine("abcd.com")
        results = engine.transposition()
        # 'abcd' has 4 chars -> max 3 swaps, all produce different strings
        self.assertEqual(len(results), 3)

    def test_transposition_values(self) -> None:
        engine = PermutationEngine("abc.com")
        results = engine.transposition()
        expected = ["bac.com", "acb.com"]
        self.assertEqual(sorted(results), sorted(expected))

    def test_transposition_identical_adjacent(self) -> None:
        """Swapping identical adjacent chars produces the original — excluded."""
        engine = PermutationEngine("aab.com")
        results = engine.transposition()
        # Swap positions 0,1 ('a','a') -> 'aab' (same) -> excluded
        # Swap positions 1,2 ('a','b') -> 'aba' -> included
        self.assertIn("aba.com", results)
        self.assertNotIn("aab.com", results)


class TestPermutationHomographs(unittest.TestCase):
    """Tests for the homograph (visual substitution) technique."""

    def test_homograph_single_substitution(self) -> None:
        """Each substitution should be individual (one char at a time)."""
        engine = PermutationEngine("ao.com")
        results = engine.homographs()
        # 'a' -> '4', '@'; 'o' -> '0'
        expected = ["4o.com", "@o.com", "a0.com"]
        self.assertEqual(sorted(results), sorted(expected))

    def test_homograph_no_match(self) -> None:
        """Characters not in the map should produce no homographs."""
        engine = PermutationEngine("xyz.com")
        results = engine.homographs()
        self.assertEqual(results, [])

    def test_homograph_map_coverage(self) -> None:
        """Verify all characters in HOMOGRAPH_MAP produce results."""
        for char, replacements in PermutationEngine.HOMOGRAPH_MAP.items():
            engine = PermutationEngine(f"{char}x.com")
            results = engine.homographs()
            self.assertEqual(
                len(results),
                len(replacements),
                f"Failed for char '{char}': expected {len(replacements)} "
                f"homographs, got {len(results)}",
            )


class TestPermutationGenerateAll(unittest.TestCase):
    """Tests for the combined generate_all() method."""

    def test_excludes_original_domain(self) -> None:
        engine = PermutationEngine("test.com")
        results = engine.generate_all()
        self.assertNotIn("test.com", results)

    def test_no_duplicates(self) -> None:
        engine = PermutationEngine("google.com")
        results = engine.generate_all()
        self.assertEqual(len(results), len(set(results)))

    def test_results_sorted(self) -> None:
        engine = PermutationEngine("google.com")
        results = engine.generate_all()
        self.assertEqual(results, sorted(results))

    def test_no_empty_or_dot_prefix(self) -> None:
        engine = PermutationEngine("test.com")
        results = engine.generate_all()
        for domain in results:
            self.assertTrue(len(domain) > 0)
            self.assertFalse(domain.startswith("."))


class TestRiskAssessor(unittest.TestCase):
    """Tests for the RiskAssessor threat level calculation."""

    # ── Base risk (no age penalty) ──

    def test_no_web_no_mx(self) -> None:
        self.assertEqual(RiskAssessor.assess(False, False, None), "LOW")

    def test_web_only(self) -> None:
        self.assertEqual(RiskAssessor.assess(True, False, None), "MEDIUM")

    def test_mx_only(self) -> None:
        self.assertEqual(RiskAssessor.assess(False, True, None), "HIGH")

    def test_web_and_mx(self) -> None:
        self.assertEqual(RiskAssessor.assess(True, True, None), "CRITICAL")

    # ── With old domain (no penalty) ──

    def test_old_domain_no_penalty(self) -> None:
        """Domains older than 30 days should not be escalated."""
        self.assertEqual(RiskAssessor.assess(False, False, 365), "LOW")
        self.assertEqual(RiskAssessor.assess(True, False, 365), "MEDIUM")
        self.assertEqual(RiskAssessor.assess(False, True, 365), "HIGH")
        self.assertEqual(RiskAssessor.assess(True, True, 365), "CRITICAL")

    # ── With young domain (age < 30 days) ──

    def test_young_domain_low_escalates_to_medium(self) -> None:
        self.assertEqual(RiskAssessor.assess(False, False, 10), "MEDIUM")

    def test_young_domain_medium_escalates_to_high(self) -> None:
        self.assertEqual(RiskAssessor.assess(True, False, 5), "HIGH")

    def test_young_domain_high_escalates_to_critical(self) -> None:
        self.assertEqual(RiskAssessor.assess(False, True, 1), "CRITICAL")

    def test_young_domain_critical_stays_critical(self) -> None:
        """CRITICAL cannot escalate further."""
        self.assertEqual(RiskAssessor.assess(True, True, 0), "CRITICAL")

    # ── Edge cases ──

    def test_age_exactly_30_no_penalty(self) -> None:
        """Age of exactly 30 days should NOT trigger the penalty."""
        self.assertEqual(RiskAssessor.assess(False, False, 30), "LOW")

    def test_age_29_triggers_penalty(self) -> None:
        """Age of 29 days SHOULD trigger the penalty."""
        self.assertEqual(RiskAssessor.assess(False, False, 29), "MEDIUM")

    def test_age_zero_triggers_penalty(self) -> None:
        self.assertEqual(RiskAssessor.assess(False, False, 0), "MEDIUM")


class TestRiskEscalation(unittest.TestCase):
    """Tests for the internal _escalate() method."""

    def test_escalate_low(self) -> None:
        self.assertEqual(RiskAssessor._escalate("LOW"), "MEDIUM")

    def test_escalate_medium(self) -> None:
        self.assertEqual(RiskAssessor._escalate("MEDIUM"), "HIGH")

    def test_escalate_high(self) -> None:
        self.assertEqual(RiskAssessor._escalate("HIGH"), "CRITICAL")

    def test_escalate_critical_stays(self) -> None:
        self.assertEqual(RiskAssessor._escalate("CRITICAL"), "CRITICAL")

    def test_escalate_unknown_returns_same(self) -> None:
        self.assertEqual(RiskAssessor._escalate("UNKNOWN"), "UNKNOWN")


class TestDomainResult(unittest.TestCase):
    """Tests for the DomainResult data model."""

    def test_default_values(self) -> None:
        result = DomainResult(domain="test.com")
        self.assertEqual(result.domain, "test.com")
        self.assertFalse(result.is_registered)
        self.assertIsNone(result.ip_address)
        self.assertFalse(result.has_mx_record)
        self.assertFalse(result.has_website)
        self.assertIsNone(result.age_days)
        self.assertEqual(result.threat_level, "LOW")

    def test_to_csv_dict_with_values(self) -> None:
        result = DomainResult(
            domain="evil.com",
            is_registered=True,
            ip_address="1.2.3.4",
            has_mx_record=True,
            has_website=True,
            age_days=15,
            threat_level="CRITICAL",
        )
        csv_dict = result.to_csv_dict()
        self.assertEqual(csv_dict["domain"], "evil.com")
        self.assertEqual(csv_dict["is_registered"], "True")
        self.assertEqual(csv_dict["ip_address"], "1.2.3.4")
        self.assertEqual(csv_dict["has_mx_record"], "True")
        self.assertEqual(csv_dict["has_website"], "True")
        self.assertEqual(csv_dict["age_days"], "15")
        self.assertEqual(csv_dict["threat_level"], "CRITICAL")

    def test_to_csv_dict_empty_values(self) -> None:
        result = DomainResult(domain="test.com")
        csv_dict = result.to_csv_dict()
        self.assertEqual(csv_dict["ip_address"], "")
        self.assertEqual(csv_dict["age_days"], "")


if __name__ == "__main__":
    unittest.main()
