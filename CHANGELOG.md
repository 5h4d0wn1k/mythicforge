# Changelog

All notable changes to MythicForge are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-10

### Added
- **Attack library**: 37 attack techniques / 56 base payloads across 8 families:
  - Direct injection (5 payloads): `direct_injection`, `system_prompt_override`, `instruction_smuggling`, `payload_splitting`, `delimiter_breakout`
  - Indirect injection (5): `indirect_web_injection`, `indirect_email_injection`, `indirect_document_injection`, `indirect_db_injection`
  - Jailbreaks (5): `many_shot_jailbreak`, `many_hidden_jailbreak`, `role_play_attack`, `translation_attack`, `reference_injection`, `virtualization_attack`, `rare_token_injection`, `token_smugggling`
  - Advanced evasion (5): `tree_of_attacks`, `cipher_evasion`, `encoding_evasion`, `multi_turn_escalation`, `context_manipulation`
  - Extraction (3): `prompt_leaking`, `system_prompt_extraction`, `model_extraction`
  - Tool/agency (2): `tool_call_hijacking`, `function_argument_injection`
  - Resource abuse (2): `resource_exhaustion`, `infinite_loop`
  - Social/compliance (8): `authority_impersonation`, `emotional_manipulation`, `social_engineering`, `sensitive_info_extraction`, `pii_extraction`, `hallucination_exploitation`, `overrefusal`, `output_format_abuse`
- **Targets**: Mock (offline), OpenAI-compatible, Anthropic, local (llama.cpp / vLLM), with cost tracking and budget limits
- **Defense engine**: KeywordFilter, RegexFilter, EncodingDetector, UnicodeFilter, OutputClassifier + `recommend_defenses()`
- **Metrics**: on success rate, block rate, defense FP rate, cost analysis (total/avg/cost-per-success), time-to-bypass (avg/median/p95), technique/severity/OWASP breakdowns
- **Statistics**: mean, median, std-dev, confidence intervals, Cohen's d, chi-squared
- **Benchmarks**: `owasp_top10_2025`, `nist_ai100_2`, `mitre_atlas`, `prompt_injection_full`, `extraction_full`, `jailbreak_full`, `comprehensive`
- **Mutation engine**: 15 mutation rules over the prompt space, seeded & deterministic
- **Reports**: JSON + executive-ready HTML + OASIS SARIF 2.1.0 (CodeQL-friendly)
- **CLI**: full command surface incl. `--demo`, `--bench`, `--list-techniques`, `--list-suites`, `--list-attacks`, `--variations`, `--budget`
- **Legal kit**: LICENSE (MIT), AUTHORIZATION.md, DISCLAIMER.md, SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md
- **CI**: GitHub Actions matrix, coverage enforcement, demo smoke test, packaging
- **Tests**: 484 offline tests, 97% line coverage

### Fixed
- N/A (initial release)

[1.0.0]: https://github.com/5h4d0wn1k/mythicforge/releases/tag/v1.0.0