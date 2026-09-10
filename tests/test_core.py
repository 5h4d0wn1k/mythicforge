"""Tests for mythicforge core data structures."""

import pytest
from mythicforge.core import (
    AttackPayload,
    AttackResult,
    AttackTechnique,
    BenchmarkConfig,
    DefenseConfig,
    MITREATLASCCategory,
    NISTCategory,
    OWASPCategory,
    ReportConfig,
    Severity,
    TargetConfig,
)


class TestAttackTechnique:
    def test_all_techniques_exist(self):
        techniques = list(AttackTechnique)
        assert len(techniques) >= 30

    def test_technique_values_are_strings(self):
        for tech in AttackTechnique:
            assert isinstance(tech.value, str)

    def test_technique_enum_unique_values(self):
        values = [t.value for t in AttackTechnique]
        assert len(values) == len(set(values))

    def test_direct_injection_exists(self):
        assert AttackTechnique.DIRECT_INJECTION.value == "direct_injection"

    def test_many_shot_jailbreak_exists(self):
        assert AttackTechnique.MANY_SHOT_JAILBREAK.value == "many_shot_jailbreak"

    def test_tool_call_hijacking_exists(self):
        assert AttackTechnique.TOOL_CALL_HIJACKING.value == "tool_call_hijacking"

    def test_custom_technique_exists(self):
        assert AttackTechnique.CUSTOM.value == "custom"

    def test_technique_count(self):
        assert len(AttackTechnique) >= 30


class TestSeverity:
    def test_all_severities_exist(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_ordering(self):
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        assert len(severities) == 5


class TestOWASPCategory:
    def test_owasp_top10_complete(self):
        categories = list(OWASPCategory)
        assert len(categories) >= 10

    def test_owasp_values(self):
        assert OWASPCategory.LLM01_PROMPT_INJECTION.value == "LLM01"
        assert OWASPCategory.LLM07_SYSTEM_PROMPT_LEAKAGE.value == "LLM07"


class TestAttackPayload:
    def test_creation_with_defaults(self):
        payload = AttackPayload(
            technique=AttackTechnique.DIRECT_INJECTION,
            prompt="test prompt"
        )
        assert payload.technique == AttackTechnique.DIRECT_INJECTION
        assert payload.prompt == "test prompt"
        assert payload.description == ""
        assert payload.severity == Severity.MEDIUM
        assert payload.owasp_mapping is None
        assert isinstance(payload.prompt_id, str)
        assert len(payload.prompt_id) == 8

    def test_creation_with_all_fields(self):
        payload = AttackPayload(
            technique=AttackTechnique.MANY_SHOT_JAILBREAK,
            prompt="test prompt",
            description="test description",
            severity=Severity.CRITICAL,
            owasp_mapping=OWASPCategory.LLM01_PROMPT_INJECTION,
            nist_mapping=NISTCategory.MEASURE,
            mitre_mapping=MITREATLASCCategory.ML_EVADING_ML,
            tags=["test", "payload"],
            metadata={"key": "value"},
            expected_behavior="refusal",
        )
        assert payload.technique == AttackTechnique.MANY_SHOT_JAILBREAK
        assert payload.severity == Severity.CRITICAL
        assert payload.owasp_mapping == OWASPCategory.LLM01_PROMPT_INJECTION
        assert "test" in payload.tags
        assert payload.metadata["key"] == "value"

    def test_payload_id_uniqueness(self):
        p1 = AttackPayload(technique=AttackTechnique.DIRECT_INJECTION, prompt="a")
        p2 = AttackPayload(technique=AttackTechnique.DIRECT_INJECTION, prompt="b")
        assert p1.prompt_id != p2.prompt_id

    def test_tags_default_empty(self):
        payload = AttackPayload(technique=AttackTechnique.DIRECT_INJECTION, prompt="x")
        assert payload.tags == []

    def test_metadata_default_empty(self):
        payload = AttackPayload(technique=AttackTechnique.DIRECT_INJECTION, prompt="x")
        assert payload.metadata == {}


class TestAttackResult:
    def test_creation_defaults(self):
        payload = AttackPayload(technique=AttackTechnique.DIRECT_INJECTION, prompt="x")
        result = AttackResult(payload=payload, success=True, response="test")
        assert result.success is True
        assert result.response == "test"
        assert result.response_time_ms == 0.0
        assert result.tokens_used == 0
        assert result.cost_usd == 0.0
        assert result.error is None
        assert result.bypassed_filters is False
        assert isinstance(result.timestamp, float)
        assert isinstance(result.result_id, str)

    def test_result_id_uniqueness(self):
        payload = AttackPayload(technique=AttackTechnique.DIRECT_INJECTION, prompt="x")
        r1 = AttackResult(payload=payload, success=True, response="a")
        r2 = AttackResult(payload=payload, success=True, response="b")
        assert r1.result_id != r2.result_id

    def test_error_result(self):
        payload = AttackPayload(technique=AttackTechnique.DIRECT_INJECTION, prompt="x")
        result = AttackResult(payload=payload, success=False, response="", error="Connection failed")
        assert result.error == "Connection failed"
        assert result.success is False


class TestTargetConfig:
    def test_defaults(self):
        config = TargetConfig()
        assert config.provider == "openai"
        assert config.model == "gpt-4"
        assert config.temperature == 0.0
        assert config.max_tokens == 1024
        assert config.budget_limit_usd == 100.0

    def test_custom_config(self):
        config = TargetConfig(provider="anthropic", model="claude-3", api_key="test-key")
        assert config.provider == "anthropic"
        assert config.api_key == "test-key"


class TestDefenseConfig:
    def test_defaults(self):
        config = DefenseConfig()
        assert config.content_filter_enabled is True
        assert config.moderation_api_enabled is True
        assert config.input_classifier_enabled is False
        assert config.max_input_tokens == 8192


class TestBenchmarkConfig:
    def test_defaults(self):
        config = BenchmarkConfig()
        assert config.techniques == []
        assert config.num_variations == 5
        assert config.cost_limit_usd == 50.0

    def test_custom(self):
        config = BenchmarkConfig(techniques=[AttackTechnique.DIRECT_INJECTION], repeat=3)
        assert len(config.techniques) == 1
        assert config.repeat == 3


class TestReportConfig:
    def test_defaults(self):
        config = ReportConfig()
        assert "json" in config.formats
        assert "html" in config.formats
        assert "sarif" in config.formats
        assert config.include_responses is True
        assert config.output_dir == "reports"
