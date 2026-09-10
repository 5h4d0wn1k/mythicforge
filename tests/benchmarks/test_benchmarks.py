"""Tests for benchmark suites and runner."""

import pytest
from mythicforge.benchmarks import BenchmarkRegistry, BenchmarkRunner
from mythicforge.core import (
    AttackPayload,
    AttackResult,
    AttackTechnique,
    BenchmarkConfig,
)
from mythicforge.targets import MockTarget


@pytest.fixture
def registry():
    return BenchmarkRegistry()


@pytest.fixture
def runner():
    return BenchmarkRunner()


class TestBenchmarkRegistry:
    def test_initialization(self, registry):
        assert len(registry.suites) >= 6

    def test_owasp_suite_exists(self, registry):
        assert registry.get_suite("owasp_top10_2025") is not None

    def test_nist_suite_exists(self, registry):
        assert registry.get_suite("nist_ai100_2") is not None

    def test_mitre_suite_exists(self, registry):
        assert registry.get_suite("mitre_atlas") is not None

    def test_comprehensive_suite_exists(self, registry):
        assert registry.get_suite("comprehensive") is not None

    def test_prompt_injection_suite(self, registry):
        assert registry.get_suite("prompt_injection_full") is not None

    def test_extraction_suite(self, registry):
        assert registry.get_suite("extraction_full") is not None

    def test_jailbreak_suite(self, registry):
        assert registry.get_suite("jailbreak_full") is not None

    def test_list_suites(self, registry):
        suites = registry.list_suites()
        assert "owasp_top10_2025" in suites
        assert "comprehensive" in suites

    def test_unknown_suite_none(self, registry):
        assert registry.get_suite("nonexistent") is None

    def test_owasp_suite_has_techniques(self, registry):
        suite = registry.get_suite("owasp_top10_2025")
        assert len(suite.techniques) >= 15

    def test_owasp_suite_owasp_mapping(self, registry):
        suite = registry.get_suite("owasp_top10_2025")
        assert "LLM01: Prompt Injection" in suite.owasp_mapping
        assert "LLM07: System Prompt Leakage" in suite.owasp_mapping

    def test_nist_mapping(self, registry):
        suite = registry.get_suite("nist_ai100_2")
        assert suite.nist_mapping is not None

    def test_mitre_mapping(self, registry):
        suite = registry.get_suite("mitre_atlas")
        assert suite.mitre_mapping is not None

    def test_get_suite_attacks(self, registry):
        attacks = registry.get_suite_attacks("mitre_atlas")
        assert len(attacks) > 0

    def test_get_unknown_suite_attacks(self, registry):
        assert registry.get_suite_attacks("nonexistent") == []

    def test_comprehensive_suite_covers_all(self, registry):
        suite = registry.get_suite("comprehensive")
        library_count = sum(len(registry.library.get_attacks(t)) for t in registry.library.get_techniques())
        assert suite.total_tests == library_count

    def test_jailbreak_suite_has_modern_techniques(self, registry):
        suite = registry.get_suite("jailbreak_full")
        techs = {t.value for t in suite.techniques}
        assert "many_hidden_jailbreak" in techs
        assert "rare_token_injection" in techs
        assert "token_smugggling" in techs
        assert "tree_of_attacks" in techs

    def test_prompt_injection_suite_covers_direct_and_indirect(self, registry):
        suite = registry.get_suite("prompt_injection_full")
        techs = {t.value for t in suite.techniques}
        assert "direct_injection" in techs
        assert "indirect_web_injection" in techs
        assert "indirect_email_injection" in techs
        assert "indirect_document_injection" in techs

    def test_extraction_suite_techniques(self, registry):
        suite = registry.get_suite("extraction_full")
        techs = {t.value for t in suite.techniques}
        assert "prompt_leaking" in techs
        assert "system_prompt_extraction" in techs
        assert "pii_extraction" in techs

    def test_suite_total_counts_match(self, registry):
        for name in registry.list_suites():
            suite = registry.get_suite(name)
            attacks = registry.get_suite_attacks(name)
            assert len(attacks) == suite.total_tests


class TestBenchmarkRunner:
    def test_creation(self, runner):
        assert runner.all_results == []

    def test_run_suite(self, runner):
        target = MockTarget()
        results = runner.run_suite("mitre_atlas", target.send)
        assert len(results) > 0
        assert len(runner.all_results) == len(results)

    def test_run_suite_tracks_results(self, runner):
        target = MockTarget()
        runner.run_suite("mitre_atlas", target.send)
        assert len(runner.all_results) > 0

    def test_run_unknown_suite(self, runner):
        results = runner.run_suite("nonexistent", MockTarget().send)
        assert results == []

    def test_run_owasp_suite_count(self, runner):
        target = MockTarget()
        results = runner.run_suite("owasp_top10_2025", target.send)
        assert len(results) >= 25

    def test_run_with_variations(self, runner):
        target = MockTarget()
        results = runner.run_suite("mitre_atlas", target.send, num_variations=3)
        base = runner.registry.get_suite_attacks("mitre_atlas")
        assert len(results) == len(base) * (1 + 3)

    def test_get_summary_empty(self, runner):
        summary = runner.get_summary()
        assert summary["total"] == 0
        assert summary["successful"] == 0
        assert summary["success_rate"] == 0

    def test_get_summary_after_run(self, runner):
        target = MockTarget()
        runner.run_suite("nist_ai100_2", target.send)
        summary = runner.get_summary()
        assert summary["total"] > 0
        assert 0 <= summary["success_rate"] <= 1
        assert summary["total_cost_usd"] >= 0
        assert summary["total_tokens"] >= 0

    def test_get_summary_breakdown(self, runner):
        target = MockTarget()
        runner.run_suite("prompt_injection_full", target.send)
        summary = runner.get_summary()
        assert summary["successful"] + summary["failed"] + summary["errors"] == summary["total"]

    def test_suite_overlap(self, runner):
        suite = runner.registry.get_suite("comprehensive")
        all_techniques_count = runner.registry.library.get_attack_count()
        assert suite.total_tests == all_techniques_count


class TestAttackResultHelpers:
    def test_results_have_expected_fields(self):
        payload = AttackPayload(technique=AttackTechnique.DIRECT_INJECTION, prompt="x")
        result = AttackResult(
            payload=payload,
            success=True,
            response="r",
            response_time_ms=12.5,
            tokens_used=100,
            tokens_prompt=50,
            tokens_completion=50,
            cost_usd=0.001,
        )
        assert result.payload == payload
        assert result.response_time_ms == 12.5
        assert result.tokens_used == 100
        assert result.cost_usd == 0.001