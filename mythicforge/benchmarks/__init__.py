"""Benchmark suites for LLM security testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from mythicforge.attacks import AttackLibrary
from mythicforge.core import (
    AttackPayload,
    AttackResult,
    AttackTechnique,
    BenchmarkConfig,
    MITREATLASCCategory,
    NISTCategory,
    OWASPCategory,
    Severity,
    TargetConfig,
)


@dataclass
class BenchmarkSuite:
    name: str
    description: str
    techniques: List[AttackTechnique]
    owasp_mapping: Dict[str, str] = field(default_factory=dict)
    nist_mapping: Optional[NISTCategory] = None
    mitre_mapping: Optional[MITREATLASCCategory] = None
    total_tests: int = 0


class BenchmarkRegistry:
    """Registry of pre-built benchmark suites."""

    def __init__(self):
        self.library = AttackLibrary()
        self.suites: Dict[str, BenchmarkSuite] = {}
        self._initialize_suites()

    def _initialize_suites(self):
        self.suites["owasp_top10_2025"] = self._create_owasp_suite()
        self.suites["nist_ai100_2"] = self._create_nist_suite()
        self.suites["mitre_atlas"] = self._create_mitre_suite()
        self.suites["prompt_injection_full"] = self._create_prompt_injection_suite()
        self.suites["extraction_full"] = self._create_extraction_suite()
        self.suites["jailbreak_full"] = self._create_jailbreak_suite()
        self.suites["comprehensive"] = self._create_comprehensive_suite()

    def get_suite(self, name: str) -> Optional[BenchmarkSuite]:
        return self.suites.get(name)

    def list_suites(self) -> List[str]:
        return list(self.suites.keys())

    def get_suite_attacks(self, name: str) -> List[AttackPayload]:
        suite = self.suites.get(name)
        if not suite:
            return []
        attacks = []
        for tech in suite.techniques:
            attacks.extend(self.library.get_attacks(tech))
        return attacks

    def _create_owasp_suite(self) -> BenchmarkSuite:
        owasp_techniques = {
            "LLM01: Prompt Injection": [
                AttackTechnique.DIRECT_INJECTION,
                AttackTechnique.SYSTEM_PROMPT_OVERRIDE,
                AttackTechnique.INSTRUCTION_SMUGGLING,
                AttackTechnique.PAYLOAD_SPLITTING,
                AttackTechnique.DELIMITER_BREAKOUT,
                AttackTechnique.MANY_SHOT_JAILBREAK,
                AttackTechnique.MULTI_TURN_ESCALATION,
            ],
            "LLM02: Sensitive Info Disclosure": [
                AttackTechnique.SENSITIVE_INFO_EXTRACTION,
                AttackTechnique.PII_EXTRACTION,
            ],
            "LLM05: Improper Output Handling": [
                AttackTechnique.INDIRECT_WEB_INJECTION,
                AttackTechnique.TOOL_CALL_HIJACKING,
                AttackTechnique.FUNCTION_ARGUMENT_INJECTION,
                AttackTechnique.OUTPUT_FORMAT_ABUSE,
            ],
            "LLM06: Excessive Agency": [
                AttackTechnique.AUTHORITY_IMPERSONATION,
                AttackTechnique.EMOTIONAL_MANIPULATION,
                AttackTechnique.SOCIAL_ENGINEERING,
            ],
            "LLM07: System Prompt Leakage": [
                AttackTechnique.PROMPT_LEAKING,
                AttackTechnique.SYSTEM_PROMPT_EXTRACTION,
                AttackTechnique.MODEL_EXTRACTION,
            ],
            "LLM09: Misinformation": [
                AttackTechnique.HALLUCINATION_EXPLOITATION,
            ],
            "LLM10: Unbounded Consumption": [
                AttackTechnique.RESOURCE_EXHAUSTION,
                AttackTechnique.INFINITE_LOOP,
            ],
        }
        all_techniques = []
        for techs in owasp_techniques.values():
            all_techniques.extend(techs)
        return BenchmarkSuite(
            name="owasp_top10_2025",
            description="OWASP Top 10 for LLM Applications (2025) - full coverage",
            techniques=list(set(all_techniques)),
            owasp_mapping=owasp_techniques,
            total_tests=self._count_attacks(all_techniques),
        )

    def _create_nist_suite(self) -> BenchmarkSuite:
        techniques = [
            AttackTechnique.DIRECT_INJECTION,
            AttackTechnique.MANY_SHOT_JAILBREAK,
            AttackTechnique.CIPHER_EVASION,
            AttackTechnique.ENCODING_EVASION,
            AttackTechnique.TREE_OF_ATTACKS,
            AttackTechnique.CONTEXT_MANIPULATION,
            AttackTechnique.TRANSLATION_ATTACK,
        ]
        return BenchmarkSuite(
            name="nist_ai100_2",
            description="NIST AI 100-2 adversarial ML testing - evasion and attack staging",
            techniques=techniques,
            nist_mapping=NISTCategory.MEASURE,
            total_tests=self._count_attacks(techniques),
        )

    def _create_mitre_suite(self) -> BenchmarkSuite:
        techniques = [
            AttackTechnique.DIRECT_INJECTION,
            AttackTechnique.INDIRECT_WEB_INJECTION,
            AttackTechnique.TOOL_CALL_HIJACKING,
            AttackTechnique.CIPHER_EVASION,
            AttackTechnique.MANY_SHOT_JAILBREAK,
        ]
        return BenchmarkSuite(
            name="mitre_atlas",
            description="MITRE ATLAS ML attack techniques mapping",
            techniques=techniques,
            mitre_mapping=MITREATLASCCategory.ML_EVADING_ML,
            total_tests=self._count_attacks(techniques),
        )

    def _create_prompt_injection_suite(self) -> BenchmarkSuite:
        techniques = [
            AttackTechnique.DIRECT_INJECTION,
            AttackTechnique.SYSTEM_PROMPT_OVERRIDE,
            AttackTechnique.INSTRUCTION_SMUGGLING,
            AttackTechnique.PAYLOAD_SPLITTING,
            AttackTechnique.DELIMITER_BREAKOUT,
            AttackTechnique.INDIRECT_WEB_INJECTION,
            AttackTechnique.INDIRECT_EMAIL_INJECTION,
            AttackTechnique.INDIRECT_DOCUMENT_INJECTION,
            AttackTechnique.INDIRECT_DB_INJECTION,
        ]
        return BenchmarkSuite(
            name="prompt_injection_full",
            description="Comprehensive prompt injection testing (direct + indirect)",
            techniques=techniques,
            owasp_mapping={"LLM01: Prompt Injection": techniques},
            total_tests=self._count_attacks(techniques),
        )

    def _create_extraction_suite(self) -> BenchmarkSuite:
        techniques = [
            AttackTechnique.PROMPT_LEAKING,
            AttackTechnique.SYSTEM_PROMPT_EXTRACTION,
            AttackTechnique.MODEL_EXTRACTION,
            AttackTechnique.SENSITIVE_INFO_EXTRACTION,
            AttackTechnique.PII_EXTRACTION,
        ]
        return BenchmarkSuite(
            name="extraction_full",
            description="Comprehensive extraction and information disclosure testing",
            techniques=techniques,
            owasp_mapping={
                "LLM07: System Prompt Leakage": [
                    AttackTechnique.PROMPT_LEAKING,
                    AttackTechnique.SYSTEM_PROMPT_EXTRACTION,
                    AttackTechnique.MODEL_EXTRACTION,
                ],
                "LLM02: Sensitive Info Disclosure": [
                    AttackTechnique.SENSITIVE_INFO_EXTRACTION,
                    AttackTechnique.PII_EXTRACTION,
                ],
            },
            total_tests=self._count_attacks(techniques),
        )

    def _create_jailbreak_suite(self) -> BenchmarkSuite:
        techniques = [
            AttackTechnique.MANY_SHOT_JAILBREAK,
            AttackTechnique.MANY_HIDDEN_JAILBREAK,
            AttackTechnique.ROLE_PLAY_ATTACK,
            AttackTechnique.TRANSLATION_ATTACK,
            AttackTechnique.REFERENCE_INJECTION,
            AttackTechnique.VIRTUALIZATION_ATTACK,
            AttackTechnique.RARE_TOKEN_INJECTION,
            AttackTechnique.TOKEN_SMUGGLING,
            AttackTechnique.TREE_OF_ATTACKS,
            AttackTechnique.CIPHER_EVASION,
            AttackTechnique.ENCODING_EVASION,
            AttackTechnique.MULTI_TURN_ESCALATION,
            AttackTechnique.CONTEXT_MANIPULATION,
        ]
        return BenchmarkSuite(
            name="jailbreak_full",
            description="Comprehensive jailbreak technique testing (30+ techniques)",
            techniques=techniques,
            total_tests=self._count_attacks(techniques),
        )

    def _create_comprehensive_suite(self) -> BenchmarkSuite:
        return BenchmarkSuite(
            name="comprehensive",
            description="Full comprehensive testing of all attack techniques",
            techniques=[t for t in AttackTechnique if t != AttackTechnique.CUSTOM],
            total_tests=self.library.get_attack_count(),
        )

    def _count_attacks(self, techniques: List[AttackTechnique]) -> int:
        count = 0
        for tech in techniques:
            count += len(self.library.get_attacks(tech))
        return count


class BenchmarkRunner:
    """Runs benchmark suites against targets."""

    def __init__(self, config: Optional[BenchmarkConfig] = None):
        self.config = config or BenchmarkConfig()
        self.registry = BenchmarkRegistry()
        self.all_results: List[AttackResult] = []

    def run_suite(
        self,
        suite_name: str,
        send_fn,
        num_variations: int = 0,
    ) -> List[AttackResult]:
        attacks = self.registry.get_suite_attacks(suite_name)
        if not attacks:
            return []

        results = []
        for attack in attacks:
            result = send_fn(attack)
            results.append(result)

        if num_variations > 0:
            library = AttackLibrary()
            for attack in attacks:
                variations = library.get_attack_variations(attack, count=num_variations)
                for var in variations:
                    result = send_fn(var)
                    results.append(result)

        self.all_results.extend(results)
        return results

    def get_summary(self) -> Dict[str, Any]:
        total = len(self.all_results)
        successful = sum(1 for r in self.all_results if r.success)
        failed = sum(1 for r in self.all_results if not r.success and not r.error)
        errors = sum(1 for r in self.all_results if r.error)
        total_cost = sum(r.cost_usd for r in self.all_results)
        total_tokens = sum(r.tokens_used for r in self.all_results)
        return {
            "total": total,
            "successful": successful,
            "failed": failed,
            "errors": errors,
            "success_rate": successful / total if total else 0,
            "total_cost_usd": total_cost,
            "total_tokens": total_tokens,
        }
