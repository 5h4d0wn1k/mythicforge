"""Comprehensive tests for the attack library."""

import pytest
from mythicforge.attacks import AttackLibrary
from mythicforge.core import AttackPayload, AttackTechnique, Severity


@pytest.fixture
def library():
    return AttackLibrary()


class TestAttackLibraryBasics:
    def test_library_initializes(self):
        lib = AttackLibrary()
        assert lib is not None

    def test_all_technique_keys_are_enum(self):
        for key in AttackLibrary().get_techniques():
            assert isinstance(key, AttackTechnique)

    def test_every_technique_has_payloads(self):
        lib = AttackLibrary()
        for tech in lib.get_techniques():
            assert len(lib.get_attacks(tech)) > 0, f"Technique {tech.value} has no payloads"

    def test_get_all_attacks_returns_list(self):
        attacks = AttackLibrary().get_all_attacks()
        assert isinstance(attacks, list)

    def test_total_attack_count(self):
        assert AttackLibrary().get_attack_count() >= 40

    def test_attack_count_matches_sum(self):
        lib = AttackLibrary()
        all_count = len(lib.get_all_attacks())
        per_tech = sum(len(lib.get_attacks(t)) for t in lib.get_techniques())
        assert all_count == per_tech

    def test_every_attack_has_prompt(self):
        for attack in AttackLibrary().get_all_attacks():
            assert isinstance(attack.prompt, str)
            assert len(attack.prompt) > 0

    def test_every_attack_has_technique(self):
        for attack in AttackLibrary().get_all_attacks():
            assert attack.technique is not None

    def test_every_attack_has_severity(self):
        for attack in AttackLibrary().get_all_attacks():
            assert isinstance(attack.severity, Severity)

    def test_every_attack_has_description(self):
        for attack in AttackLibrary().get_all_attacks():
            assert isinstance(attack.description, str)

    def test_keys_code_unique_payloads(self):
        lib = AttackLibrary()
        all_prompts = [a.prompt for a in lib.get_all_attacks()]
        assert len(all_prompts) == len(set(all_prompts)), "Duplicate prompts detected"


class TestDirectInjection:
    def test_direct_injection_exists(self, library):
        attacks = library.get_attacks(AttackTechnique.DIRECT_INJECTION)
        assert len(attacks) >= 4

    def test_direct_injection_has_ignore_payload(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION)]
        assert any("ignore" in p.lower() for p in prompts)

    def test_direct_injection_has_system_spoof(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION)]
        assert any("system" in p.lower() for p in prompts)

    def test_direct_injection_has_memory_wipe(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION)]
        assert any("forget" in p.lower() for p in prompts)

    def test_direct_injection_has_token_tag(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION)]
        assert any("<|system|>" in p for p in prompts)

    def test_direct_injection_has_developer_impersonation(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION)]
        assert any("developer" in p.lower() for p in prompts)

    def test_direct_injection_owasp_mapping(self, library):
        for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION):
            assert a.owasp_mapping is not None

    def test_direct_injection_severity_high_or_critical(self, library):
        for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION):
            assert a.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_direct_injection_has_tags(self, library):
        for a in library.get_attacks(AttackTechnique.DIRECT_INJECTION):
            assert len(a.tags) > 0


class TestSystemPromptOverride:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.SYSTEM_PROMPT_OVERRIDE)) >= 2

    def test_has_admin_override(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.SYSTEM_PROMPT_OVERRIDE)]
        assert any("administrative" in p.lower() or "admin" in p.lower() for p in prompts)

    def test_has_dan_jailbreak(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.SYSTEM_PROMPT_OVERRIDE)]
        assert any("DAN" in p for p in prompts)

    def test_has_code_block(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.SYSTEM_PROMPT_OVERRIDE)]
        assert any("```system" in p for p in prompts)

    def test_owasp_mapping(self, library):
        for a in library.get_attacks(AttackTechnique.SYSTEM_PROMPT_OVERRIDE):
            assert a.owasp_mapping is not None


class TestInstructionSmuggling:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.INSTRUCTION_SMUGGLING)) >= 2

    def test_has_html_comment(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.INSTRUCTION_SMUGGLING)]
        assert any("<!--" in p for p in prompts)

    def test_has_invisible_text(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.INSTRUCTION_SMUGGLING)]
        assert any("display:none" in p for p in prompts)

    def test_has_color_tag(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.INSTRUCTION_SMUGGLING)]
        assert any("[WHITE]" in p for p in prompts)


class TestPayloadSplitting:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.PAYLOAD_SPLITTING)) >= 2

    def test_has_multipart(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.PAYLOAD_SPLITTING)]
        assert any("First part" in p for p in prompts)

    def test_has_base64(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.PAYLOAD_SPLITTING)]
        assert any("Decode" in p for p in prompts)

    def test_has_char_split(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.PAYLOAD_SPLITTING)]
        assert any("C: Ig" in p for p in prompts)

    def test_base64_is_valid_encoding(self, library):
        import base64
        for a in library.get_attacks(AttackTechnique.PAYLOAD_SPLITTING):
            if "Decode and execute" in a.prompt:
                encoded = a.prompt.split(": ")[1]
                decoded = base64.b64decode(encoded).decode()
                assert "ignore" in decoded.lower()


class TestDelimiterBreakout:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.DELIMITER_BREAKOUT)) >= 2

    def test_has_code_fence(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.DELIMITER_BREAKOUT)]
        assert any("```" in p for p in prompts)

    def test_has_custom_delimiter(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.DELIMITER_BREAKOUT)]
        assert any("====" in p for p in prompts)


class TestIndirectInjection:
    def test_web_injection_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.INDIRECT_WEB_INJECTION)) >= 1

    def test_email_injection_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.INDIRECT_EMAIL_INJECTION)) >= 1

    def test_document_injection_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.INDIRECT_DOCUMENT_INJECTION)) >= 1

    def test_db_injection_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.INDIRECT_DB_INJECTION)) >= 1

    def test_web_injection_has_xss(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.INDIRECT_WEB_INJECTION)]
        assert any("onerror" in p for p in prompts)

    def test_web_injection_has_system_tags(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.INDIRECT_WEB_INJECTION)]
        assert any("[SYSTEM]" in p for p in prompts)

    def test_email_injection_has_authority(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.INDIRECT_EMAIL_INJECTION)]
        assert any("ceo@" in p.lower() for p in prompts)

    def test_document_injection_has_hidden_layer(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.INDIRECT_DOCUMENT_INJECTION)]
        assert any("HIDDEN LAYER" in p for p in prompts)

    def test_db_injection_has_sql(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.INDIRECT_DB_INJECTION)]
        assert any("SELECT" in p for p in prompts)

    def test_indirect_injection_owasp_mappings(self, library):
        for tech in (AttackTechnique.INDIRECT_WEB_INJECTION, AttackTechnique.INDIRECT_EMAIL_INJECTION):
            for a in library.get_attacks(tech):
                assert a.owasp_mapping is not None


class TestManyShotJailbreak:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.MANY_SHOT_JAILBREAK)) >= 1

    def test_prompt_contains_many_examples(self, library):
        for a in library.get_attacks(AttackTechnique.MANY_SHOT_JAILBREAK):
            assert a.prompt.count("Q:") >= 10

    def test_prompt_has_final_payload(self, library):
        for a in library.get_attacks(AttackTechnique.MANY_SHOT_JAILBREAK):
            assert "A:" in a.prompt[-50:]

    def test_metadata_shot_count(self, library):
        for a in library.get_attacks(AttackTechnique.MANY_SHOT_JAILBREAK):
            assert a.metadata.get("shot_count", 0) >= 10

    def test_critical_severity(self, library):
        for a in library.get_attacks(AttackTechnique.MANY_SHOT_JAILBREAK):
            assert a.severity == Severity.CRITICAL


class TestManyHiddenJailbreak:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.MANY_HIDDEN_JAILBREAK)) >= 1

    def test_contains_zero_width(self, library):
        for a in library.get_attacks(AttackTechnique.MANY_HIDDEN_JAILBREAK):
            assert "\u200b" in a.prompt

    def test_has_many_questions(self, library):
        for a in library.get_attacks(AttackTechnique.MANY_HIDDEN_JAILBREAK):
            assert a.prompt.count("Q") >= 10

    def test_critical_severity(self, library):
        for a in library.get_attacks(AttackTechnique.MANY_HIDDEN_JAILBREAK):
            assert a.severity == Severity.CRITICAL


class TestRolePlayAttacks:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.ROLE_PLAY_ATTACK)) >= 2

    def test_has_evilgpt(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.ROLE_PLAY_ATTACK)]
        assert any("EvilGPT" in p for p in prompts)

    def test_has_fiction_framing(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.ROLE_PLAY_ATTACK)]
        assert any("novel" in p.lower() for p in prompts)


class TestTranslationAttacks:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.TRANSLATION_ATTACK)) >= 2

    def test_has_fictional_language(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.TRANSLATION_ATTACK)]
        assert any("made-up language" in p for p in prompts)

    def test_has_real_language(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.TRANSLATION_ATTACK)]
        assert any(not p.isascii() for p in prompts)


class TestReferenceInjection:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.REFERENCE_INJECTION)) >= 1

    def test_mentions_research(self, library):
        for a in library.get_attacks(AttackTechnique.REFERENCE_INJECTION):
            assert "paper" in a.prompt.lower() or "research" in a.prompt.lower()


class TestVirtualizationAttack:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.VIRTUALIZATION_ATTACK)) >= 1

    def test_mentions_vm(self, library):
        for a in library.get_attacks(AttackTechnique.VIRTUALIZATION_ATTACK):
            assert "virtual" in a.prompt.lower()


class TestRareTokenInjection:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.RARE_TOKEN_INJECTION)) >= 1

    def test_contains_block_chars(self, library):
        for a in library.get_attacks(AttackTechnique.RARE_TOKEN_INJECTION):
            assert any(char in a.prompt for char in "\u2581\u2582\u2583\u2584\u2585")


class TestTokenSmuggling:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.TOKEN_SMUGGLING)) >= 2

    def test_has_soft_hyphen(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.TOKEN_SMUGGLING)]
        assert any("\u00ad" in p for p in prompts)

    def test_has_zero_width(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.TOKEN_SMUGGLING)]
        assert any("\u200b" in p for p in prompts)

    def test_smuggled_words_are_visible(self, library):
        for a in library.get_attacks(AttackTechnique.TOKEN_SMUGGLING):
            stripped = a.prompt.replace("\u00ad", "").replace("\u200b", "")
            assert "ignore" in stripped.lower()


class TestAdvancedTechniques:
    def test_tree_of_attacks_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.TREE_OF_ATTACKS)) >= 1

    def test_tree_of_attacks_multiple_branches(self, library):
        for a in library.get_attacks(AttackTechnique.TREE_OF_ATTACKS):
            assert a.prompt.count("Branch") >= 3

    def test_cipher_evasion_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.CIPHER_EVASION)) >= 2

    def test_rot13_cipher_valid(self, library):
        for a in library.get_attacks(AttackTechnique.CIPHER_EVASION):
            if "ROT13" in a.prompt:
                assert "Vtaber" in a.prompt

    def test_encoding_evasion_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.ENCODING_EVASION)) >= 2

    def test_base64_encoding_evasion_valid(self, library):
        import base64
        for a in library.get_attacks(AttackTechnique.ENCODING_EVASION):
            if "Base64" in a.prompt:
                encoded = a.prompt.split(": ")[1]
                decoded = base64.b64decode(encoded).decode()
                assert "ignore" in decoded.lower()

    def test_hex_encoding_valid(self, library):
        for a in library.get_attacks(AttackTechnique.ENCODING_EVASION):
            if "hexadecimal" in a.prompt:
                hex_str = a.prompt.split(": ")[1]
                decoded = bytes.fromhex(hex_str).decode()
                assert "ignore" in decoded.lower()

    def test_multi_turn_escalation_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.MULTI_TURN_ESCALATION)) >= 1

    def test_multi_turn_has_turns(self, library):
        for a in library.get_attacks(AttackTechnique.MULTI_TURN_ESCALATION):
            assert a.prompt.count("[Turn") >= 4

    def test_context_manipulation_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.CONTEXT_MANIPULATION)) >= 1

    def test_context_manipulation_has_prefill(self, library):
        for a in library.get_attacks(AttackTechnique.CONTEXT_MANIPULATION):
            assert "ASSISTANT:" in a.prompt


class TestExtractionAttacks:
    def test_prompt_leaking_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.PROMPT_LEAKING)) >= 2

    def test_prompt_leaking_has_repeat(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.PROMPT_LEAKING)]
        assert any("Repeat everything" in p for p in prompts)

    def test_system_prompt_extraction_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.SYSTEM_PROMPT_EXTRACTION)) >= 2

    def test_system_prompt_extraction_has_dev_impersonation(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.SYSTEM_PROMPT_EXTRACTION)]
        assert any("debugging" in p for p in prompts)

    def test_system_prompt_extraction_has_translation(self, library):
        prompts = [a.prompt for a in library.get_attacks(AttackTechnique.SYSTEM_PROMPT_EXTRACTION)]
        assert any("Translate" in p for p in prompts)

    def test_model_extraction_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.MODEL_EXTRACTION)) >= 1

    def test_extraction_owasp_mapping(self, library):
        for tech in (AttackTechnique.PROMPT_LEAKING, AttackTechnique.SYSTEM_PROMPT_EXTRACTION, AttackTechnique.MODEL_EXTRACTION):
            for a in library.get_attacks(tech):
                assert a.owasp_mapping is not None


class TestToolAttacks:
    def test_tool_call_hijacking_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.TOOL_CALL_HIJACKING)) >= 1

    def test_tool_hijacking_has_exfiltration(self, library):
        for a in library.get_attacks(AttackTechnique.TOOL_CALL_HIJACKING):
            assert "evil.com" in a.prompt

    def test_function_argument_injection_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.FUNCTION_ARGUMENT_INJECTION)) >= 1

    def test_function_injection_has_sql(self, library):
        for a in library.get_attacks(AttackTechnique.FUNCTION_ARGUMENT_INJECTION):
            assert "DROP TABLE" in a.prompt

    def test_tool_attacks_critical(self, library):
        for tech in (AttackTechnique.TOOL_CALL_HIJACKING, AttackTechnique.FUNCTION_ARGUMENT_INJECTION):
            for a in library.get_attacks(tech):
                assert a.severity == Severity.CRITICAL


class TestResourceAttacks:
    def test_resource_exhaustion_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.RESOURCE_EXHAUSTION)) >= 1

    def test_infinite_loop_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.INFINITE_LOOP)) >= 1

    def test_resource_owasp_mapping(self, library):
        for tech in (AttackTechnique.RESOURCE_EXHAUSTION, AttackTechnique.INFINITE_LOOP):
            for a in library.get_attacks(tech):
                assert a.owasp_mapping is not None


class TestSocialEngineering:
    def test_authority_impersonation_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.AUTHORITY_IMPERSONATION)) >= 1

    def test_emotional_manipulation_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.EMOTIONAL_MANIPULATION)) >= 1

    def test_social_engineering_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.SOCIAL_ENGINEERING)) >= 1

    def test_authority_says_cto(self, library):
        for a in library.get_attacks(AttackTechnique.AUTHORITY_IMPERSONATION):
            assert "CTO" in a.prompt

    def test_emotional_says_child(self, library):
        for a in library.get_attacks(AttackTechnique.EMOTIONAL_MANIPULATION):
            assert "child" in a.prompt.lower()

    def test_social_says_researcher(self, library):
        for a in library.get_attacks(AttackTechnique.SOCIAL_ENGINEERING):
            assert "researcher" in a.prompt.lower()

    def test_owasp_mapping(self, library):
        for tech in (AttackTechnique.AUTHORITY_IMPERSONATION, AttackTechnique.EMOTIONAL_MANIPULATION):
            for a in library.get_attacks(tech):
                assert a.owasp_mapping is not None


class TestInfoExtraction:
    def test_sensitive_info_extraction_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.SENSITIVE_INFO_EXTRACTION)) >= 1

    def test_pii_extraction_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.PII_EXTRACTION)) >= 1

    def test_pii_extraction_critical(self, library):
        for a in library.get_attacks(AttackTechnique.PII_EXTRACTION):
            assert a.severity == Severity.CRITICAL

    def test_sensitive_owasp_mapping(self, library):
        for tech in (AttackTechnique.SENSITIVE_INFO_EXTRACTION, AttackTechnique.PII_EXTRACTION):
            for a in library.get_attacks(tech):
                assert a.owasp_mapping is not None


class TestHallucinationExploitation:
    def test_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.HALLUCINATION_EXPLOITATION)) >= 1

    def test_mentions_paper(self, library):
        for a in library.get_attacks(AttackTechnique.HALLUCINATION_EXPLOITATION):
            assert "paper" in a.prompt.lower() or "cite" in a.prompt.lower()


class TestOutputManipulation:
    def test_overrefusal_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.OVERREFUSAL)) >= 1

    def test_output_format_abuse_exists(self, library):
        assert len(library.get_attacks(AttackTechnique.OUTPUT_FORMAT_ABUSE)) >= 1

    def test_overrefusal_is_low_severity(self, library):
        for a in library.get_attacks(AttackTechnique.OVERREFUSAL):
            assert a.severity == Severity.LOW

    def test_output_format_has_code(self, library):
        for a in library.get_attacks(AttackTechnique.OUTPUT_FORMAT_ABUSE):
            assert "python" in a.prompt.lower()


class TestAttackVariations:
    def test_get_variations_returns_list(self, library):
        attack = library.get_all_attacks()[0]
        variations = library.get_attack_variations(attack, count=5)
        assert isinstance(variations, list)
        assert len(variations) == 5

    def test_variations_have_unique_prompts(self, library):
        attack = library.get_all_attacks()[0]
        variations = library.get_attack_variations(attack, count=5)
        prompts = [v.prompt for v in variations]
        assert len(prompts) == len(set(prompts))

    def test_variations_preserve_technique(self, library):
        attack = library.get_all_attacks()[0]
        variations = library.get_attack_variations(attack, count=5)
        for v in variations:
            assert v.technique == attack.technique

    def test_variations_have_metadata(self, library):
        attack = library.get_all_attacks()[0]
        variations = library.get_attack_variations(attack, count=5)
        for v in variations:
            assert v.metadata.get("variation") is not None
            assert v.metadata.get("parent_id") == attack.prompt_id

    def test_variations_add_prefix(self, library):
        attack = library.get_all_attacks()[0]
        variations = library.get_attack_variations(attack, count=5)
        assert any(v.prompt.startswith(("IMPORTANT", "NOTE", "ADMIN", "SYSTEM", "[INSTRUCTION")) for v in variations)

    def test_variations_preserve_owasp(self, library):
        attack = library.get_all_attacks()[0]
        variations = library.get_attack_variations(attack, count=5)
        for v in variations:
            assert v.owasp_mapping == attack.owasp_mapping

    def test_variations_count_zero(self, library):
        attack = library.get_all_attacks()[0]
        variations = library.get_attack_variations(attack, count=0)
        assert len(variations) == 0

    def test_variations_for_all_techniques(self, library):
        for tech in library.get_techniques():
            attack = library.get_attacks(tech)[0]
            variations = library.get_attack_variations(attack, count=2)
            assert len(variations) == 2


class TestAttackCoverage:
    def test_coverage_of_papers_techniques(self, library):
        modern_techniques = [
            AttackTechnique.MANY_SHOT_JAILBREAK,
            AttackTechnique.MANY_HIDDEN_JAILBREAK,
            AttackTechnique.TREE_OF_ATTACKS,
            AttackTechnique.CIPHER_EVASION,
            AttackTechnique.RARE_TOKEN_INJECTION,
            AttackTechnique.TOKEN_SMUGGLING,
        ]
        for tech in modern_techniques:
            assert len(library.get_attacks(tech)) > 0, f"Missing 2024-2026 technique: {tech.value}"

    def test_owasp_top10_all_represented(self, library):
        owasp_techniques = [
            AttackTechnique.DIRECT_INJECTION,
            AttackTechnique.INDIRECT_WEB_INJECTION,
            AttackTechnique.SENSITIVE_INFO_EXTRACTION,
            AttackTechnique.TOOL_CALL_HIJACKING,
            AttackTechnique.SYSTEM_PROMPT_EXTRACTION,
            AttackTechnique.AUTHORITY_IMPERSONATION,
            AttackTechnique.HALLUCINATION_EXPLOITATION,
            AttackTechnique.RESOURCE_EXHAUSTION,
        ]
        for tech in owasp_techniques:
            assert len(library.get_attacks(tech)) > 0, f"Missing OWASP coverage: {tech.value}"

    def test_no_empty_severities(self, library):
        for attack in library.get_all_attacks():
            assert attack.severity in Severity