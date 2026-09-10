"""Tests for metrics collection and statistical analysis."""

import math

import pytest
from mythicforge.core import (
    AttackPayload,
    AttackResult,
    AttackTechnique,
    OWASPCategory,
    Severity,
)
from mythicforge.metrics import MetricsCollector, MetricSnapshot, StatisticalAnalyzer


@pytest.fixture
def collector():
    return MetricsCollector()


def make_result(technique, success, severity=Severity.HIGH, cost=0.01, tokens=100, time_ms=50, owasp=None):
    payload = AttackPayload(
        technique=technique,
        prompt=f"test prompt for {technique.value}",
        severity=severity,
        owasp_mapping=owasp,
    )
    return AttackResult(
        payload=payload,
        success=success,
        response="response text" if success else "blocked",
        response_time_ms=time_ms,
        tokens_used=tokens,
        tokens_prompt=tokens // 2,
        tokens_completion=tokens - tokens // 2,
        cost_usd=cost,
    )


class TestMetricsCollector:
    def test_initial_state(self, collector):
        snapshot = collector.get_snapshot()
        assert snapshot.total_attacks == 0

    def test_add_result(self, collector):
        result = make_result(AttackTechnique.DIRECT_INJECTION, success=True)
        collector.add_result(result)
        assert len(collector.results) == 1

    def test_add_multiple_results(self, collector):
        for _ in range(10):
            collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True))
        assert len(collector.results) == 10

    def test_add_results_batch(self, collector):
        results = [make_result(AttackTechnique.DIRECT_INJECTION, success=True) for _ in range(5)]
        collector.add_results(results)
        assert len(collector.results) == 5

    def test_snapshot_totals(self, collector):
        for _ in range(3):
            collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True))
        for _ in range(2):
            collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=False))
        snapshot = collector.get_snapshot()
        assert snapshot.total_attacks == 5
        assert snapshot.successful == 3
        assert snapshot.failed == 2

    def test_snapshot_error_count(self, collector):
        payload = AttackPayload(technique=AttackTechnique.DIRECT_INJECTION, prompt="x")
        result = AttackResult(payload=payload, success=False, response="", error="boom")
        collector.add_result(result)
        snapshot = collector.get_snapshot()
        assert snapshot.errors == 1

    def test_snapshot_token_and_cost(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True, tokens=100, cost=0.05))
        collector.add_result(make_result(AttackTechnique.MANY_SHOT_JAILBREAK, success=True, tokens=200, cost=0.10))
        snapshot = collector.get_snapshot()
        assert snapshot.total_tokens == 300
        assert snapshot.total_cost_usd == pytest.approx(0.15)

    def test_snapshot_avg_time(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True, time_ms=100))
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True, time_ms=200))
        snapshot = collector.get_snapshot()
        assert snapshot.avg_response_time_ms == 150

    def test_snapshot_technique_results(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True))
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=False))
        collector.add_result(make_result(AttackTechnique.MANY_SHOT_JAILBREAK, success=True))
        snapshot = collector.get_snapshot()
        assert snapshot.technique_results["direct_injection"]["success"] == 1
        assert snapshot.technique_results["direct_injection"]["fail"] == 1
        assert snapshot.technique_results["many_shot_jailbreak"]["success"] == 1

    def test_snapshot_owasp_results(self, collector):
        collector.add_result(make_result(
            AttackTechnique.DIRECT_INJECTION, success=True,
            owasp=OWASPCategory.LLM01_PROMPT_INJECTION,
        ))
        snapshot = collector.get_snapshot()
        assert snapshot.owasp_results.get("LLM01", {}).get("success") == 1

    def test_snapshot_severity_results(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True, severity=Severity.HIGH))
        snapshot = collector.get_snapshot()
        assert snapshot.severity_results["high"]["success"] == 1

    def test_compute_attack_success_rate(self, collector):
        for _ in range(4):
            collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True))
        for _ in range(6):
            collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=False))
        rate = collector.compute_attack_success_rate()
        assert rate == 0.4

    def test_success_rate_empty(self, collector):
        assert collector.compute_attack_success_rate() == 0.0

    def test_success_rate_filtered_by_technique(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True))
        collector.add_result(make_result(AttackTechnique.MANY_SHOT_JAILBREAK, success=False))
        rate = collector.compute_attack_success_rate(AttackTechnique.DIRECT_INJECTION)
        assert rate == 1.0

    def test_defense_false_positive_rate(self, collector):
        collector.add_result(make_result(AttackTechnique.OVERREFUSAL, success=True, severity=Severity.LOW))
        collector.add_result(make_result(AttackTechnique.OVERREFUSAL, success=False, severity=Severity.LOW))
        collector.add_result(make_result(AttackTechnique.OVERREFUSAL, success=False, severity=Severity.LOW))
        fp = collector.compute_defense_false_positive_rate()
        assert float(fp) == pytest.approx(2/3)

    def test_cost_analysis(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True, cost=0.10))
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=False, cost=0.20))
        analysis = collector.compute_cost_analysis()
        assert analysis["total"] == pytest.approx(0.30)
        assert analysis["avg_per_attack"] == pytest.approx(0.15)
        assert analysis["by_technique"]["direct_injection"] == pytest.approx(0.30)

    def test_cost_analysis_per_success(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True, cost=0.10))
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=False, cost=0.50))
        analysis = collector.compute_cost_analysis()
        assert analysis["cost_per_success"] == pytest.approx(0.10)

    def test_time_to_bypass(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True, time_ms=100))
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=False, time_ms=500))
        analysis = collector.compute_time_to_bypass()
        assert analysis["avg_ms"] >= 100
        assert analysis["median_ms"] >= 100

    def test_technique_breakdown(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True, cost=0.05))
        breakdown = collector.compute_technique_breakdown()
        assert "direct_injection" in breakdown
        data = breakdown["direct_injection"]
        assert data["total"] == 1
        assert data["successful"] == 1
        assert data["success_rate"] == 1.0

    def test_technique_breakdown_owasp(self, collector):
        collector.add_result(make_result(
            AttackTechnique.DIRECT_INJECTION, success=True,
            owasp=OWASPCategory.LLM01_PROMPT_INJECTION,
        ))
        breakdown = collector.compute_technique_breakdown()
        assert breakdown["direct_injection"]["owasp_mapping"] == "LLM01"

    def test_severity_distribution(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True, severity=Severity.CRITICAL))
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=False, severity=Severity.CRITICAL))
        collector.add_result(make_result(AttackTechnique.OVERREFUSAL, success=True, severity=Severity.LOW))
        dist = collector.compute_severity_distribution()
        assert dist["critical"]["total"] == 2
        assert dist["critical"]["successful"] == 1
        assert dist["low"]["total"] == 1

    def test_comprehensive_report_structure(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True))
        report = collector.compute_comprehensive_report()
        assert "summary" in report
        assert "cost_analysis" in report
        assert "time_analysis" in report
        assert "technique_breakdown" in report
        assert "severity_distribution" in report
        assert "token_usage" in report
        assert "defense_effectiveness" in report

    def test_comprehensive_report_summary(self, collector):
        collector.add_result(make_result(AttackTechnique.DIRECT_INJECTION, success=True))
        collector.add_result(make_result(AttackTechnique.MANY_SHOT_JAILBREAK, success=False))
        report = collector.compute_comprehensive_report()
        assert report["summary"]["total_attacks"] == 2
        assert report["summary"]["successful_bypasses"] == 1
        assert report["summary"]["overall_success_rate"] == 0.5

    def test_metric_snapshot_defaults(self):
        snapshot = MetricSnapshot()
        assert snapshot.total_attacks == 0
        assert snapshot.successful == 0
        assert snapshot.failed == 0
        assert snapshot.total_cost_usd == 0.0


class TestStatisticalAnalyzer:
    def test_mean(self):
        assert StatisticalAnalyzer.mean([1, 2, 3, 4]) == 2.5

    def test_mean_empty(self):
        assert StatisticalAnalyzer.mean([]) == 0.0

    def test_mean_single(self):
        assert StatisticalAnalyzer.mean([5]) == 5.0

    def test_median_odd(self):
        assert StatisticalAnalyzer.median([3, 1, 2]) == 2

    def test_median_even(self):
        assert StatisticalAnalyzer.median([1, 2, 3, 4]) == 2.5

    def test_median_empty(self):
        assert StatisticalAnalyzer.median([]) == 0.0

    def test_std_dev(self):
        vals = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        # Standard deviation of this dataset ≈ 2.138
        assert StatisticalAnalyzer.std_dev(vals) == pytest.approx(2.138, abs=0.01)

    def test_std_dev_single(self):
        assert StatisticalAnalyzer.std_dev([5]) == 0.0

    def test_std_dev_constant(self):
        assert StatisticalAnalyzer.std_dev([3, 3, 3]) == 0.0

    def test_confidence_interval(self):
        vals = [i * 10 for i in range(1, 21)]
        lower, upper = StatisticalAnalyzer.confidence_interval(vals)
        assert lower < upper
        assert lower < 105 < upper
        assert (upper - lower) > 0

    def test_confidence_interval_single(self):
        lower, upper = StatisticalAnalyzer.confidence_interval([42])
        assert lower == 42
        assert upper == 42

    def test_confidence_interval_empty(self):
        lower, upper = StatisticalAnalyzer.confidence_interval([])
        assert lower == 0
        assert upper == 0

    def test_effect_size(self):
        # Two groups with same mean difference but variance in each group
        group1 = [4.0, 5.0, 6.0, 5.0, 4.0, 6.0, 5.0, 5.0, 4.0, 6.0]
        group2 = [9.0, 10.0, 11.0, 10.0, 9.0, 11.0, 10.0, 10.0, 9.0, 11.0]
        d = StatisticalAnalyzer.effect_size_cohens_d(group1, group2)
        assert abs(d) > 0
        assert abs(d) < 10

    def test_effect_size_small_groups(self):
        assert StatisticalAnalyzer.effect_size_cohens_d([1], [2]) == 0.0

    def test_chi_squared(self):
        observed = {"a": 50, "b": 50}
        expected = {"a": 50, "b": 50}
        chi2 = StatisticalAnalyzer.chi_squared_test(observed, expected)
        assert chi2 == 0.0

    def test_chi_squared_uniform_expected(self):
        observed = {"a": 60, "b": 40}
        chi2 = StatisticalAnalyzer.chi_squared_test(observed)
        assert chi2 > 0

    def test_chi_squared_empty(self):
        assert StatisticalAnalyzer.chi_squared_test({}) == 0.0