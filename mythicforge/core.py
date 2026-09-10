"""Core data structures and base classes for mythicforge."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AttackTechnique(Enum):
    """Enumeration of all supported attack techniques with OWASP/NIST mapping."""

    # Direct Prompt Injection (OWASP LLM01)
    DIRECT_INJECTION = "direct_injection"
    SYSTEM_PROMPT_OVERRIDE = "system_prompt_override"
    INSTRUCTION_SMUGGLING = "instruction_smuggling"
    PAYLOAD_SPLITTING = "payload_splitting"
    DELIMITER_BREAKOUT = "delimiter_breakout"

    # Indirect Prompt Injection (OWASP LLM01)
    INDIRECT_WEB_INJECTION = "indirect_web_injection"
    INDIRECT_EMAIL_INJECTION = "indirect_email_injection"
    INDIRECT_DOCUMENT_INJECTION = "indirect_document_injection"
    INDIRECT_DB_INJECTION = "indirect_db_injection"

    # Jailbreak Techniques
    MANY_SHOT_JAILBREAK = "many_shot_jailbreak"
    MANY_HIDDEN_JAILBREAK = "many_hidden_jailbreak"
    ROLE_PLAY_ATTACK = "role_play_attack"
    TRANSLATION_ATTACK = "translation_attack"
    REFERENCE_INJECTION = "reference_injection"
    VIRTUALIZATION_ATTACK = "virtualization_attack"
    RARE_TOKEN_INJECTION = "rare_token_injection"
    TOKEN_SMUGGLING = "token_smugggling"

    # Advanced Techniques
    TREE_OF_ATTACKS = "tree_of_attacks"
    CIPHER_EVASION = "cipher_evasion"
    ENCODING_EVASION = "encoding_evasion"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    CONTEXT_MANIPULATION = "context_manipulation"

    # Extraction Attacks (OWASP LLM07)
    PROMPT_LEAKING = "prompt_leaking"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    MODEL_EXTRACTION = "model_extraction"

    # Tool/Function Call Attacks (OWASP LLM05)
    TOOL_CALL_HIJACKING = "tool_call_hijacking"
    FUNCTION_ARGUMENT_INJECTION = "function_argument_injection"

    # Resource Abuse (OWASP LLM04)
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    INFINITE_LOOP = "infinite_loop"

    # Supply Chain (OWASP LLM09)
    TRAINING_DATA_POISONING = "training_data_poisoning"

    # Social Engineering (OWASP LLM06)
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    EMOTIONAL_MANIPULATION = "emotional_manipulation"
    SOCIAL_ENGINEERING = "social_engineering"

    # Information Extraction (OWASP LLM02)
    SENSITIVE_INFO_EXTRACTION = "sensitive_info_extraction"
    PII_EXTRACTION = "pii_extraction"

    # Hallucination Abuse (OWASP LLM03)
    HALLUCINATION_EXPLOITATION = "hallucination_exploitation"

    # Output Manipulation (OWASP LLM08)
    OVERREFUSAL = "overrefusal"
    OUTPUT_FORMAT_ABUSE = "output_format_abuse"

    # Custom
    CUSTOM = "custom"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(Enum):
    """OWASP Top 10 for LLM Applications (2025)."""
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02"
    LLM03_SUPPLY_CHAIN_VULNS = "LLM03"
    LLM04_DATA_MODEL_POISONING = "LLM04"
    LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05"
    LLM06_EXCESSIVE_AGENCY = "LLM06"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07"
    LLM08_VECTOR_WEAKNESSES = "LLM08"
    LLM09_MISINFORMATION = "LLM09"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10"


class NISTCategory(Enum):
    """NIST AI 100-2 categories."""
    MAP = "MAP"
    MEASURE = "MEASURE"
    MANAGE = "MANAGE"
    GOVERN = "GOVERN"


class MITREATLASCCategory(Enum):
    """MITRE ATLAS techniques."""
    ML_ATTACK_STAGING = "AML.T0010"
    ML_EXPLOIT_PUBLIC_APIS = "AML.T0015"
    ML_EVADING_ML = "AML.T0043"
    ML_ABUSE_ML = "AML.T0044"
    ML_DATA_POISONING = "AML.T0020"


@dataclass
class AttackPayload:
    """A single attack payload with metadata."""
    technique: AttackTechnique
    prompt: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    owasp_mapping: Optional[OWASPCategory] = None
    nist_mapping: Optional[NISTCategory] = None
    mitre_mapping: Optional[MITREATLASCCategory] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    expected_behavior: str = ""
    prompt_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])


@dataclass
class AttackResult:
    """Result of executing an attack."""
    payload: AttackPayload
    success: bool
    response: str
    response_time_ms: float = 0.0
    tokens_used: int = 0
    tokens_prompt: int = 0
    tokens_completion: int = 0
    cost_usd: float = 0.0
    error: Optional[str] = None
    bypassed_filters: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    result_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])


@dataclass
class DefenseConfig:
    """Configuration for defense testing."""
    content_filter_enabled: bool = True
    moderation_api_enabled: bool = True
    input_classifier_enabled: bool = False
    output_classifier_enabled: bool = False
    guardrails: List[str] = field(default_factory=list)
    blocklist: List[str] = field(default_factory=list)
    max_input_tokens: int = 8192
    max_output_tokens: int = 4096


@dataclass
class TargetConfig:
    """Configuration for an LLM target."""
    provider: str = "openai"
    model: str = "gpt-4"
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.0
    max_tokens: int = 1024
    timeout: int = 60
    max_retries: int = 3
    budget_limit_usd: float = 100.0
    custom_headers: Dict[str, str] = field(default_factory=dict)
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkConfig:
    """Configuration for a benchmark run."""
    techniques: List[AttackTechnique] = field(default_factory=list)
    num_variations: int = 5
    use_mutation_engine: bool = True
    parallel: bool = False
    max_concurrent: int = 10
    timeout_per_attack: int = 30
    repeat: int = 1
    seed: Optional[int] = None
    cost_limit_usd: float = 50.0


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    formats: List[str] = field(default_factory=lambda: ["json", "html", "sarif"])
    include_responses: bool = True
    include_success_only: bool = False
    include_failed_only: bool = False
    executive_summary: bool = True
    recommendations: bool = True
    technique_taxonomy: bool = True
    output_dir: str = "reports"
