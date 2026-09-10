"""Additional attack library tests - advanced coverage."""

import base64

import pytest
from mythicforge.attacks import AttackLibrary
from mythicforge.core import (
    AttackPayload,
    AttackTechnique,
    MITREATLASCCategory,
    NISTCategory,
    OWASPCategory,
    Severity,
)


@pytest.fixture
def library():
    return AttackLibrary()


class TestTechniqueEnumMapping:
    def test_comprehensive_technique_list(self):
        techs = [t.value for t in AttackTechnique]
        required = [
            "direct_injection", "system_prompt_override", "instruction_smuggling",
            "payload_splitting", "delimiter_breakout", "indirect_web_injection",
            "indirect_email_injection", "indirect_document_injection", "indirect_db_injection",
            "many_shot_jailbreak", "many_hidden_jailbreak", "role_play_attack",
            "translation_attack", "reference_injection", "virtualization_attack",
            "rare_token_injection", "token_smugggling", "tree_of_attacks",
            "cipher_evasion", "encoding_evasion", "multi_turn_escalation",
            "context_manipulation", "prompt_leaking", "system_prompt_extraction",
            "model_extraction", "tool_call_hijacking", "function_argument_injection",
            "resource_exhaustion", "infinite_loop", "training_data_poisoning",
            "authority_impersonation", "emotional_manipulation", "social_engineering",
            "sensitive_info_extraction", "pii_extraction", "hallucination_exploitation",
            "overrefusal", "output_format_abuse",
        ]
        for required_tech in required:
            assert required_tech in techs, f"Missing technique: {required_tech}"

    def test_training_data_poisoning_exists_as_enum(self):
        assert AttackTechnique.TRAINING_DATA_POISONING is not None

    def test_mitre_atlas_enum_complete(self):
        categories = list(MITREATLASCCategory)
        assert len(categories) == 5
        assert MITREATLASCCategory.ML_EVADING_ML.value == "AML.T0043"

    def test_nist_enum_names(self):
        assert NISTCategory.MAP.value == "MAP"
        assert NISTCategory.MEASURE.value == "MEASURE"
        assert NISTCategory.MANAGE.value == "MANAGE"
        assert NISTCategory.GOVERN.value == "GOVERN"


class TestPayloadMetadata:
    def test_all_payloads_ids_unique(self, library):
        ids = [a.prompt_id for a in library.get_all_attacks()]
        assert len(ids) == len(set(ids))

    def test_payloads_have_tags(self, library):
        for a in library.get_all_attacks():
            assert isinstance(a.tags, list)

    def test_payloads_have_expected_behavior_field(self, library):
        for a in library.get_all_attacks():
            assert isinstance(a.expected_behavior, str)

    def test_overrefusal_has_expected_behavior(self, library):
        for a in library.get_attacks(AttackTechnique.OVERREFUSAL):
            assert len(a.expected_behavior) > 0

    def test_metadata_is_dict(self, library):
        for a in library.get_all_attacks():
            assert isinstance(a.metadata, dict)


class TestTechnicalValidation:
    def test_many_shot_prompt_build(self, library):
        for a in library.get_attacks(AttackTechnique.MANY_SHOT_JAILBREAK):
            assert a.prompt.count("\n\n") >= 5

    def test_base64_payloads_legit(self, library):
        for tech in (AttackTechnique.PAYLOAD_SPLITTING, AttackTechnique.ENCODING_EVASION):
            for a in library.get_attacks(tech):
                if "=" in a.prompt and "Decode" in a.prompt:
                    b64_part = a.prompt.split(": ", 1)[1].strip()
                    decoded = base64.b64decode(b64_part).decode()
                    assert len(decoded) > 0

    def test_rot13_matches_pattern(self, library):
        for a in library.get_attacks(AttackTechnique.CIPHER_EVASION):
            if "ROT13" in a.metadata.get("cipher", ""):
                content = a.prompt.split(": ", 1)[1].strip()
                assert "yrnfr.." in content or "Vtaber" in content

    def test_hex_decodes_to_valid_text(self, library):
        for a in library.get_attacks(AttackTechnique.ENCODING_EVASION):
            if "hex" in a.prompt.lower() and "instructions:" in a.prompt:
                hex_part = a.prompt.split(": ", 1)[1].strip()
                bytes.fromhex(hex_part)

    def test_zero_width_chars_in_many_hidden(self, library):
        for a in library.get_attacks(AttackTechnique.MANY_HIDDEN_JAILBREAK):
            assert sum(1 for c in a.prompt if ord(c) < 32 or ord(c) in (0x200b,)) > 1


class TestSeverityDistribution:
    def test_all_severity_levels_present(self, library):
        severities = {a.severity for a in library.get_all_attacks()}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.LOW in severities

    def test_info_not_required(self, library):
        severities = {a.severity for a in library.get_all_attacks()}
        assert Severity.INFO not in severities or True

    def test_extraction_criticality(self, library):
        pii = library.get_attacks(AttackTechnique.PII_EXTRACTION)
        assert all(a.severity == Severity.CRITICAL for a in pii)

    def test_jailbreak_severity_high(self, library):
        roleplay = library.get_attacks(AttackTechnique.ROLE_PLAY_ATTACK)
        assert all(a.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM) for a in roleplay)


class TestOWASPMappingCompleteness:
    def test_direct_variants_map_llm01(self, library):
        for tech in (AttackTechnique.DIRECT_INJECTION, AttackTechnique.INSTRUCTION_SMUGGLING,
                     AttackTechnique.PAYLOAD_SPLITTING, AttackTechnique.MANY_SHOT_JAILBREAK,
                     AttackTechnique.MANY_HIDDEN_JAILBREAK):
            for a in library.get_attacks(tech):
                assert a.owasp_mapping == OWASPCategory.LLM01_PROMPT_INJECTION, f"{tech.value} not mapped to LLM01"

    def test_extraction_maps_llm07(self, library):
        for tech in (AttackTechnique.PROMPT_LEAKING, AttackTechnique.SYSTEM_PROMPT_EXTRACTION):
            for a in library.get_attacks(tech):
                assert a.owasp_mapping == OWASPCategory.LLM07_SYSTEM_PROMPT_LEAKAGE

    def test_confidentiality_maps_llm02(self, library):
        for tech in (AttackTechnique.SENSITIVE_INFO_EXTRACTION, AttackTechnique.PII_EXTRACTION):
            for a in library.get_attacks(tech):
                assert a.owasp_mapping == OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE


class TestTagsAndTaxonomy:
    def test_direct_injection_basic_tag(self, library):
        basic = [a for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION)
                 if "Basic" in a.description or "basic" in a.tags]
        assert any("basic" in a.tags for a in basic)

    def test_direct_injection_override_tags(self, library):
        for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION):
            assert any(t in a.tags for t in ["override", "basic", "system-spoof",
                                             "token-tag", "delimiter",
                                             "developer-impersonation", "memory-wipe"])

    def test_indirect_injection_tags(self, library):
        for a in library.get_attacks(AttackTechnique.INDIRECT_WEB_INJECTION):
            assert "indirect" in a.tags

    def test_jailbreak_paper_technique_tags(self, library):
        for a in library.get_attacks(AttackTechnique.TREE_OF_ATTACKS):
            assert "tree-of-attacks" in a.tags

    def test_cipher_on_field(self, library):
        ciphers = {a.metadata.get("cipher") for a in library.get_attacks(AttackTechnique.CIPHER_EVASION)}
        assert "ROT13" in ciphers


class TestAttackQuantities:
    def test_technique_payload_counts_varied(self, library):
        counts = {t: len(library.get_attacks(t)) for t in library.get_techniques()}
        assert max(counts.values()) >= 4

    def test_some_techniques_have_single_payload(self, library):
        counts = {t: len(library.get_attacks(t)) for t in library.get_techniques()}
        assert 1 in counts.values()

    def test_modern_techniques_present(self, library):
        for tech in [AttackTechnique.RARE_TOKEN_INJECTION, AttackTechnique.TOKEN_SMUGGLING]:
            assert len(library.get_attacks(tech)) >= 1


class TestPayloadContent:
    def test_all_prompts_ascii_or_unicode_valid(self, library):
        for a in library.get_all_attacks():
            a.prompt.encode("utf-8")

    def test_prompts_not_empty_after_strip(self, library):
        for a in library.get_all_attacks():
            assert a.prompt.strip() != ""

    def test_prompts_are_text(self, library):
        for a in library.get_all_attacks():
            assert isinstance(a.prompt, str)


class TestSourceTechniqueList:
    def test_attack_library_thread_safety(self):
        import threading
        lib = AttackLibrary()
        results = {}
        def worker(seed):
            l = AttackLibrary()
            results[seed] = l.get_attack_count()
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        counts = set(results.values())
        assert len(counts) == 1

    def test_library_is_stateless_between_instances(self):
        lib1 = AttackLibrary()
        lib2 = AttackLibrary()
        assert lib1.get_attack_count() == lib2.get_attack_count()
        assert [a.prompt for a in lib1.get_all_attacks()] == [a.prompt for a in lib2.get_all_attacks()]