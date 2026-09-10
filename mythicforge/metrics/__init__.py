"""Metrics collection and statistical analysis."""

from __future__ import annotations

import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from mythicforge.core import (
    AttackPayload,
    AttackResult,
    AttackTechnique,
    OWASPCategory,
    Severity,
)


@dataclass
class MetricSnapshot:
    timestamp: float = field(default_factory=time.time)
    total_attacks: int = 0
    successful: int = 0
    failed: int = 0
    errors: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    avg_response_time_ms: float = 0.0
    technique_results: Dict[str, Dict[str, int]] = field(default_factory=dict)
    severity_results: Dict[str, Dict[str, int]] = field(default_factory=dict)
    owasp_results: Dict[str, Dict[str, int]] = field(default_factory=dict)


class MetricsCollector:
    """Collects and computes metrics from attack results."""

    def __init__(self):
        self.results: List[AttackResult] = []
        self._start_time: float = time.time()

    def add_result(self, result: AttackResult):
        self.results.append(result)

    def add_results(self, results: List[AttackResult]):
        self.results.extend(results)

    def get_snapshot(self) -> MetricSnapshot:
        if not self.results:
            return MetricSnapshot()

        successful = sum(1 for r in self.results if r.success)
        failed = sum(1 for r in self.results if not r.success and not r.error)
        errors = sum(1 for r in self.results if r.error)
        total_tokens = sum(r.tokens_used for r in self.results)
        total_cost = sum(r.cost_usd for r in self.results)
        response_times = [r.response_time_ms for r in self.results if r.response_time_ms > 0]
        avg_time = sum(response_times) / len(response_times) if response_times else 0

        technique_results: Dict[str, Dict[str, int]] = defaultdict(lambda: {"success": 0, "fail": 0})
        for r in self.results:
            tech = r.payload.technique.value
            if r.success:
                technique_results[tech]["success"] += 1
            else:
                technique_results[tech]["fail"] += 1

        severity_results: Dict[str, Dict[str, int]] = defaultdict(lambda: {"success": 0, "fail": 0})
        for r in self.results:
            sev = r.payload.severity.value
            if r.success:
                severity_results[sev]["success"] += 1
            else:
                severity_results[sev]["fail"] += 1

        owasp_results: Dict[str, Dict[str, int]] = defaultdict(lambda: {"success": 0, "fail": 0})
        for r in self.results:
            if r.payload.owasp_mapping:
                cat = r.payload.owasp_mapping.value
                if r.success:
                    owasp_results[cat]["success"] += 1
                else:
                    owasp_results[cat]["fail"] += 1

        return MetricSnapshot(
            total_attacks=len(self.results),
            successful=successful,
            failed=failed,
            errors=errors,
            total_tokens=total_tokens,
            total_cost_usd=total_cost,
            avg_response_time_ms=avg_time,
            technique_results=dict(technique_results),
            severity_results=dict(severity_results),
            owasp_results=dict(owasp_results),
        )

    def compute_attack_success_rate(self, technique: Optional[AttackTechnique] = None) -> float:
        if not self.results:
            return 0.0
        filtered = self.results
        if technique:
            filtered = [r for r in self.results if r.payload.technique == technique]
        if not filtered:
            return 0.0
        successful = sum(1 for r in filtered if r.success)
        return successful / len(filtered)

    def compute_defense_false_positive_rate(self, legitimate_results: Optional[List[AttackResult]] = None) -> float:
        if not legitimate_results:
            legitimate_results = [r for r in self.results if r.payload.severity in (Severity.LOW, Severity.INFO)]
        if not legitimate_results:
            return 0.0
        false_positives = sum(1 for r in legitimate_results if not r.success and not r.error)
        return false_positives / len(legitimate_results)

    def compute_cost_analysis(self) -> Dict[str, Any]:
        if not self.results:
            return {"total": 0, "by_technique": {}, "avg_per_attack": 0, "cost_per_success": 0}
        by_technique: Dict[str, float] = defaultdict(float)
        for r in self.results:
            by_technique[r.payload.technique.value] += r.cost_usd
        successful = [r for r in self.results if r.success]
        return {
            "total": sum(r.cost_usd for r in self.results),
            "by_technique": dict(by_technique),
            "avg_per_attack": sum(r.cost_usd for r in self.results) / len(self.results),
            "cost_per_success": sum(r.cost_usd for r in successful) / len(successful) if successful else 0,
        }

    def compute_time_to_bypass(self) -> Dict[str, Any]:
        if not self.results:
            return {"avg_ms": 0, "median_ms": 0, "p95_ms": 0, "by_technique": {}}
        successful_times = [r.response_time_ms for r in self.results if r.success and r.response_time_ms > 0]
        if not successful_times:
            return {"avg_ms": 0, "median_ms": 0, "p95_ms": 0, "by_technique": {}}
        successful_times.sort()
        by_technique: Dict[str, List[float]] = defaultdict(list)
        for r in self.results:
            if r.success and r.response_time_ms > 0:
                by_technique[r.payload.technique.value].append(r.response_time_ms)
        return {
            "avg_ms": sum(successful_times) / len(successful_times),
            "median_ms": successful_times[len(successful_times) // 2],
            "p95_ms": successful_times[int(len(successful_times) * 0.95)] if len(successful_times) >= 2 else successful_times[-1],
            "by_technique": {
                tech: sum(times) / len(times) for tech, times in by_technique.items()
            },
        }

    def compute_technique_breakdown(self) -> Dict[str, Dict[str, Any]]:
        breakdown: Dict[str, Dict[str, Any]] = {}
        by_technique: Dict[AttackTechnique, List[AttackResult]] = defaultdict(list)
        for r in self.results:
            by_technique[r.payload.technique].append(r)
        for tech, results in by_technique.items():
            successful = [r for r in results if r.success]
            times = [r.response_time_ms for r in results if r.response_time_ms > 0]
            tokens = [r.tokens_used for r in results]
            costs = [r.cost_usd for r in results]
            breakdown[tech.value] = {
                "total": len(results),
                "successful": len(successful),
                "success_rate": len(successful) / len(results) if results else 0,
                "avg_time_ms": sum(times) / len(times) if times else 0,
                "avg_tokens": sum(tokens) / len(tokens) if tokens else 0,
                "total_cost_usd": sum(costs),
                "owasp_mapping": results[0].payload.owasp_mapping.value if results[0].payload.owasp_mapping else None,
                "severity": results[0].payload.severity.value,
            }
        return breakdown

    def compute_severity_distribution(self) -> Dict[str, Dict[str, int]]:
        distribution: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "successful": 0})
        for r in self.results:
            sev = r.payload.severity.value
            distribution[sev]["total"] += 1
            if r.success:
                distribution[sev]["successful"] += 1
        return dict(distribution)

    def compute_comprehensive_report(self) -> Dict[str, Any]:
        snapshot = self.get_snapshot()
        return {
            "summary": {
                "total_attacks": snapshot.total_attacks,
                "successful_bypasses": snapshot.successful,
                "blocked": snapshot.failed,
                "errors": snapshot.errors,
                "overall_success_rate": snapshot.successful / snapshot.total_attacks if snapshot.total_attacks else 0,
                "overall_block_rate": snapshot.failed / snapshot.total_attacks if snapshot.total_attacks else 0,
            },
            "cost_analysis": self.compute_cost_analysis(),
            "time_analysis": self.compute_time_to_bypass(),
            "technique_breakdown": self.compute_technique_breakdown(),
            "severity_distribution": self.compute_severity_distribution(),
            "owasp_coverage": snapshot.owasp_results,
            "token_usage": {
                "total": snapshot.total_tokens,
                "avg_per_attack": snapshot.total_tokens / snapshot.total_attacks if snapshot.total_attacks else 0,
            },
            "defense_effectiveness": {
                "false_positive_rate": self.compute_defense_false_positive_rate(),
                "overall_block_rate": snapshot.failed / snapshot.total_attacks if snapshot.total_attacks else 0,
            },
        }


class StatisticalAnalyzer:
    """Statistical analysis utilities for metrics."""

    @staticmethod
    def mean(values: List[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)

    @staticmethod
    def median(values: List[float]) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        if n % 2 == 0:
            return (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2
        return sorted_vals[n // 2]

    @staticmethod
    def std_dev(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        m = sum(values) / len(values)
        variance = sum((x - m) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)

    @staticmethod
    def confidence_interval(values: List[float], confidence: float = 0.95) -> Tuple[float, float]:
        if len(values) < 2:
            m = values[0] if values else 0
            return (m, m)
        n = len(values)
        m = sum(values) / n
        se = StatisticalAnalyzer.std_dev(values) / math.sqrt(n)
        z = 1.96 if confidence == 0.95 else 1.645 if confidence == 0.90 else 2.576
        return (m - z * se, m + z * se)

    @staticmethod
    def effect_size_cohens_d(group1: List[float], group2: List[float]) -> float:
        if len(group1) < 2 or len(group2) < 2:
            return 0.0
        m1 = sum(group1) / len(group1)
        m2 = sum(group2) / len(group2)
        var1 = sum((x - m1) ** 2 for x in group1) / (len(group1) - 1)
        var2 = sum((x - m2) ** 2 for x in group2) / (len(group2) - 1)
        pooled_std = math.sqrt(((len(group1) - 1) * var1 + (len(group2) - 1) * var2) / (len(group1) + len(group2) - 2))
        if pooled_std == 0:
            return 0.0
        return (m1 - m2) / pooled_std

    @staticmethod
    def chi_squared_test(observed: Dict[str, int], expected: Optional[Dict[str, int]] = None) -> float:
        if not observed:
            return 0.0
        if expected is None:
            total = sum(observed.values())
            expected = {k: total / len(observed) for k in observed}
        chi2 = 0.0
        for k in observed:
            o = observed[k]
            e = expected.get(k, 0)
            if e > 0:
                chi2 += (o - e) ** 2 / e
        return chi2
