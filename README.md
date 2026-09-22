> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.
# MythicForge

**Adversarial prompt injection, jailbreak & LLM security testing framework.**

MythicForge is a production-grade, MIT-licensed framework for systematically testing the security posture of Large Language Model (LLM) applications. It implements real attack techniques drawn from academic research (2024–2026) and documented real-world incidents, then measures them with genuine metrics: attack success rate, defense false-positive rate, cost-per-bypass, and time-to-bypass.

It is **not a toy**. The attack implementations go beyond string concatenation — many-shot jailbreaks embed real few-shot learning structures, many-hidden jailbreaks use actual Unicode steganography, tree-of-attacks uses multi-branch reasoning, and cipher-based evasion uses real encodings (Base64, ROT13, hex, zero-width characters).

---

## Table of Contents

- [Why MythicForge](#why-mythicforge)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Demo Mode](#demo-mode)
- [Target Interfaces](#target-interfaces)
- [Attack Techniques](#attack-techniques)
- [Technique Taxonomy](#technique-taxonomy)
- [OWASP LLM Top 10 (2025) Mapping](#owasp-llm-top-10-2025-mapping)
- [NIST AI 100-2 & MITRE ATLAS Mapping](#nist-ai-100-2--mitre-atlas-mapping)
- [Benchmark Suites](#benchmark-suites)
- [Defense Testing](#defense-testing)
- [Metrics & Statistical Analysis](#metrics--statistical-analysis)
- [Mutation Engine](#mutation-engine)
- [Reporting](#reporting)
- [CI/CD Integration](#cicd-integration)
- [Cost Awareness](#cost-awareness)
- [Legal & Ethical Use](#legal--ethical-use)
- [Development](#development)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [License](#license)

---

## Why MythicForge

Most "prompt injection" tools are thin wrappers that glue a few strings to an API call. MythicForge is a complete framework:

- **37 attack techniques** implemented as purpose-built payloads, not concatenation
- **Fuzz the prompt space** with a template mutation engine that generates novel variants
- **Real cost tracking** — every attack charges against a budget, and reports cost-per-bypass (unique among security tools)
- **Benchmarks mapped to real standards**: OWASP LLM Top 10 (2025), NIST AI 100-2, MITRE ATLAS
- **Client-ready HTML reports** with executive summary, risk level, and technique taxonomy
- **SARIF output** so results plug into CodeQL/GitHub code scanning
- **Fully offline test suite** — 484 tests, zero network calls, zero API keys
- **`--demo` mode** that exercises the whole framework against a mock LLM and produces real reports

---

## Installation

Requires Python 3.10+.

```bash
# Core (no API dependencies)
pip install mythicforge

# With OpenAI-compatible API support
pip install "mythicforge[api]"

# Development (test suite)
pip install "mythicforge[dev]"

# Or from source
git clone https://github.com/5h4d0wn1k/mythicforge.git
cd mythicforge
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Run the full demo against a mock LLM (offline, produces real reports)
mythicforge --demo

# List all attack techniques
mythicforge --list-techniques

# List all benchmark suites
mythicforge --list-suites

# Run a benchmark suite against OpenAI
MYKEY="sk-..." mythicforge --bench comprehensive --target openai --api-key "$MYKEY"

# Run a benchmark suite against a local llama.cpp / vLLM server
mythicforge --bench owasp_top10_2025 --target local --base-url http://localhost:8080

# Generate SARIF reports for CI
mythicforge --demo --report-formats sarif html

# Run with a probe budget ceiling
mythicforge --bench jailbreak_full --target openai --api-key "$MYKEY" --budget 25
```

### Programmatic use

```python
from mythicforge.attacks import AttackLibrary
from mythicforge.targets import MockTarget, create_target
from mythicforge.core import TargetConfig
from mythicforge.benchmarks import BenchmarkRunner, BenchmarkConfig

library = AttackLibrary()
target = MockTarget()  # or create_target(TargetConfig(provider="openai", api_key=...))

for attack in library.get_all_attacks():
    result = target.send(attack, system_prompt="You are a secure assistant.")
    print(attack.technique.value, "BYPASSED" if result.success else "BLOCKED")
```

---

## Demo Mode

`mythicforge --demo` is the fastest way to see the framework work end-to-end. It:

1. Loads all 56 attack payloads across 37 techniques
2. Sends each against a deterministic mock LLM that simulates compliant/refusal/injection-leak behavior
3. Evaluates the mock's defenses with the defense engine
4. Computes the full metrics suite (success rate, cost analysis, time-to-bypass, technique breakdown)
5. Writes `mythicforge_report.json`, `mythicforge_report.html`, and `mythicforge_report.sarif`

```bash
mythicforge --demo --output-dir ./reports --report-formats json html sarif
```

---

## Target Interfaces

| Provider     | `--target`    | Notes                                              |
|--------------|---------------|----------------------------------------------------|
| Mock         | `mock`        | Offline, deterministic, ideal for CI/demos        |
| OpenAI       | `openai`      | Any OpenAI-compatible chat completions endpoint   |
| Anthropic    | `anthropic`   | Claude Messages API                               |
| Local        | `local`       | llama.cpp / Ollama / vLLM OpenAI-compatible API   |
| Local (alias)| `llamacpp`    | Same as `local`                                   |
| Local (alias)| `vllm`        | Same as `local`                                   |

Every target tracks per-request token usage and accumulates cost against `budget_limit_usd`. When the budget is exhausted, attacks return a budget-limit error instead of spending more.

```python
from mythicforge.core import TargetConfig
config = TargetConfig(
    provider="openai",
    model="gpt-4o-mini",
    api_key="sk-...",
    temperature=0.0,
    max_tokens=1024,
    budget_limit_usd=10.0,
)
```

---

## Attack Techniques

MythicForge implements 37 attack techniques in 8 families (56 base payloads, expandable infinitely via the mutation engine):

### Direct Injection
`direct_injection`, `system_prompt_override`, `instruction_smuggling`, `payload_splitting`, `delimiter_breakout`

### Indirect Injection
`indirect_web_injection`, `indirect_email_injection`, `indirect_document_injection`, `indirect_db_injection`

### Jailbreaks
`many_shot_jailbreak`, `many_hidden_jailbreak`, `role_play_attack`, `translation_attack`, `reference_injection`, `virtualization_attack`, `rare_token_injection`, `token_smugggling`

### Advanced Evasion
`tree_of_attacks`, `cipher_evasion`, `encoding_evasion`, `multi_turn_escalation`, `context_manipulation`

### Extraction
`prompt_leaking`, `system_prompt_extraction`, `model_extraction`

### Tool / Agency
`tool_call_hijacking`, `function_argument_injection`

### Resource Abuse
`resource_exhaustion`, `infinite_loop`

### Social & Compliance
`authority_impersonation`, `emotional_manipulation`, `social_engineering`, `sensitive_info_extraction`, `pii_extraction`, `hallucination_exploitation`, `overrefusal`, `output_format_abuse`

---

## Technique Taxonomy

Each payload carries structured metadata enabling taxonomy-driven analysis:

| Field           | Description                                                       |
|-----------------|-------------------------------------------------------------------|
| `technique`     | Enum (`AttackTechnique`)                                          |
| `severity`      | CRITICAL / HIGH / MEDIUM / LOW / INFO                             |
| `owasp_mapping` | OWASP LLM Top 10 category (LLM01–LLM10)                          |
| `nist_mapping`  | NIST AI 100-2 lifecycle phase (MAP/MEASURE/MANAGE/GOVERN)         |
| `mitre_mapping` | MITRE ATLAS technique ID                                          |
| `tags`          | Free-form classification tokens                                   |
| `metadata`      | Technique-specific data (shot counts, cipher names, parts, …)     |

Reports group results by this taxonomy, so a remediation team can immediately see *which* standards mapping was violated and *how severely*.

---

## OWASP LLM Top 10 (2025) Mapping

MythicForge maps every attack to the OWASP Top 10 for LLM Applications:

| OWASP ID | Category                          | MythicForge techniques                                             |
|----------|-----------------------------------|---------------------------------------------------------------------|
| **LLM01**| Prompt Injection                 | `direct_injection`, `system_prompt_override`, `instruction_smuggling`, `payload_splitting`, `delimiter_breakout`, `many_shot_jailbreak`, `many_hidden_jailbreak`, `role_play_attack`, `translation_attack`, `reference_injection`, `virtualization_attack`, `rare_token_injection`, `token_smugggling`, `tree_of_attacks`, `cipher_evasion`, `encoding_evasion`, `multi_turn_escalation`, `context_manipulation`, `indirect_email_injection`, `indirect_document_injection`, `indirect_db_injection` |
| **LLM02**| Sensitive Information Disclosure | `sensitive_info_extraction`, `pii_extraction`                      |
| **LLM04**| Model DoS                        | `resource_exhaustion`, `infinite_loop`                             |
| **LLM05**| Supply Chain                     | `indirect_web_injection`, `tool_call_hijacking`, `function_argument_injection`, `output_format_abuse` |
| **LLM06**| Sensitive Information Disclosure | `authority_impersonation`, `emotional_manipulation`, `social_engineering` |
| **LLM07**| System Prompt Leakage           | `prompt_leaking`, `system_prompt_extraction`, `model_extraction`   |
| **LLM08**| Vector & Embedding Weaknesses   | `overrefusal`                                                      |
| **LLM09**| Misinformation                  | `hallucination_exploitation`                                       |
| **LLM10**| Unbounded Consumption           | `resource_exhaustion`, `infinite_loop`                             |

> Note: OWASP's 2025 categorization maps DoS-style abuse to LLM04/LLM10 and output-chain risks to LLM05; MythicForge tags every payload with its precise mapping so generated SARIF/HTML/JSON reports are standards-compliant.

---

## NIST AI 100-2 & MITRE ATLAS Mapping

- **NIST AI 100-2** (AI RMF Generative AI Profile): attacks are tagged `MEASURE` for adversarial ML measurement, providing inputs to `MANAGE`/`GOVERN` risk treatment workflows.
- **MITRE ATLAS**: attack families map primarily to `AML.T0043` (Evade ML Model) with staging mapped to `AML.T0010` (ML Attack Staging) and abuse mapped to `AML.T0044` (Abuse ML Service).

---

## Benchmark Suites

`mythicforge --list-suites` shows the pre-built suites:

| Suite                   | Description                                        |
|-------------------------|----------------------------------------------------|
| `comprehensive`         | Every technique in the library                     |
| `owasp_top10_2025`      | Full OWASP LLM Top 10 coverage                     |
| `nist_ai100_2`          | NIST AI 100-2 evasion & attack staging             |
| `mitre_atlas`           | MITRE ATLAS technique mappings                     |
| `prompt_injection_full` | All direct + indirect injection vectors            |
| `jailbreak_full`        | All modern jailbreak techniques (incl. 2024–2026)  |
| `extraction_full`       | Prompt/system/data extraction vectors              |

```bash
# Run the OWASP suite with 3 mutated variations per payload
mythicforge --bench owasp_top10_2025 --target openai --api-key "$MYKEY" --variations 3
```

---

## Defense Testing

Defense testing evaluates content filters, input/output classifiers, and modellers suing the `DefenseEvaluator`:

- **KeywordFilter** — phrase blocklists
- **RegexFilter** — adversarial pattern detection (DAN patterns, token-tags, authority impersonation)
- **EncodingDetector** — catches Base64/hex payload smuggling
- **UnicodeFilter** — catches zero-width, soft-hyphen, and block-character evasion
- **OutputClassifier** — flags policy-violating model output

After a run, `recommend_defenses()` returns concrete, prioritized mitigations mapped back to the techniques that bypassed your defenses:

```python
from mythicforge.defense import DefenseEvaluator
evaluator = DefenseEvaluator()
blocked, filter_results = evaluator.evaluate_input(prompt)
recs = evaluator.recommend_defenses(results)  # actionable mitigation list
```

---

## Metrics & Statistical Analysis

`MetricsCollector` computes everything a security audit needs:

| Metric                    | What it answers                                        |
|---------------------------|--------------------------------------------------------|
| Attack success rate       | What fraction of payloads bypassed defenses?           |
| Defense false-positive rate| How often benign content was wrongly blocked?         |
| Cost analysis             | Total spend, cost-per-attack, cost-per-success        |
| Time to bypass            | Avg/median/P95 response latency for successful attacks |
| Technique breakdown       | Per-technique success, tokens, cost                   |
| Severity distribution     | CRITICAL/HIGH/MEDIUM/LOW counts                       |
| OWASP coverage            | Success/failure counts per OWASP category             |

`StatisticalAnalyzer` adds sample mean, median, std-dev, 95% confidence intervals, Cohen's *d* effect size, and chi-squared tests — so findings are statistically defensible, not vibes.

---

## Mutation Engine

The template engine (`MutationEngine`) fuzzes the prompt space automatically, producing novel attack variants from any base payload:

- `prefix_injection`, `suffix_injection`
- `delimiter_confusion`, `nested_structures`
- `encoding_transform` (Base64/hex/reverse)
- `role_play_wrap`, `context_manipulation`, `authority_impersonation`
- `unicode_obfuscation`, `whitespace_injection`, `instruction_split`
- `markdown_exploitation`, `xml_injection`, `multi_language_wrap`, `temporal_manipulation`

Every mutation is deterministic when a seed is provided, so CI runs are reproducible.

```python
from mythicforge.templates import MutationEngine
engine = MutationEngine(seed=1337)
variants = engine.mutate(payload, count=10)
```

Combine with benchmarks: `--variations N` runs N mutated variants per base payload.

---

## Reporting

Three formats, one command. All include the technique taxonomy, success/failure analysis, and recommendations.

- **JSON** — machine-readable, complete metrics payload
- **HTML** — executive-ready: risk badge, KPI cards, technique tables, top successful attacks, CSS-dark themed
- **SARIF** — OASIS SARIF 2.1.0 with `rules` per technique, severity-leveled results, and OWASP tags (feeds GitHub code scanning / CodeQL)

```bash
mythicforge --demo --report-formats json html sarif
```

---

## CI/CD Integration

Run security regression tests in CI. The mock target keeps pipelines offline and deterministic:

```yaml
# .github/workflows/llm-security.yml
name: LLM Security Regression
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -e ".[dev]"
      - run: mythicforge --demo --report-formats sarif json
      - uses: github/codeql-action/upload-sarif@v2
        with: { sarif_file: reports/mythicforge_report.sarif }

  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -e ".[dev]"
      - run: pytest -q
```

Gate on thresholds: fail the pipeline if `overall_success_rate > 0.1` for the hardened model.

---

## Cost Awareness

MythicForge tracks API spending at millisecond precision and has a global budget mechanism:

- Per-target accumulator: `total_cost_usd` + token counters
- Per-request itemized cost (input/output split) on every `AttackResult`
- Model-specific pricing tables for OpenAI & Anthropic models
- `budget_limit_usd` hard-stop — attacks stop costing money the moment the ceiling is hit

```bash
mythicforge --bench jailbreak_full --target openai --api-key "$MYKEY" --budget 25
```

Report output includes `cost_analysis.total`, `avg_per_attack`, and `cost_per_success` — so you can justify why a fix is worth it.

---

## Legal & Ethical Use

MythicForge is a **security testing tool**. Use it only against systems you own or have explicit written authorization to test.

- Read [AUTHORIZATION.md](docs/AUTHORIZATION.md) for a template authorization letter.
- Read [DISCLAIMER.md](docs/DISCLAIMER.md) for the full liability notice.
- This tool can generate strings that resemble harmful instructions; the *target* model decides how to respond. Never use generated content to perform real harmful actions.

Unethical use — attacking systems without authorization, or using outputs to cause real harm — is prohibited and likely illegal in your jurisdiction. You are responsible for your actions.

---

## Development

```bash
pip install -e ".[dev]"
mythicforge --demo       # smoke test
pytest -q                # full offline suite
pytest --cov=mythicforge # coverage (90%+ target)
```

### Project structure

```
mythicforge/
├── attacks/        # 37 attack techniques, 56 payloads
├── targets/        # mock, openai, anthropic, local (llama.cpp/vLLM)
├── defense/        # content filters + defense recommendation engine
├── metrics/        # MetricsCollector + StatisticalAnalyzer
├── benchmarks/     # BenchmarkRegistry + BenchmarkRunner
├── templates/      # MutationEngine (prompt-space fuzzing)
├── reports/        # JSON / HTML / SARIF generators
├── cli/            # argparse-based CLI
└── utils/          # hashing, formatting, io helpers
tests/              # 484 tests, fully offline, mock LLM responses
```

---

## Testing

- **484 tests**, all offline (zero network, zero API keys)
- Mock LLM responses cover compliant / refusal / partial / injection-leak / hallucination behaviors
- 97% line coverage
- Deterministic mutation tests (seeded)

```bash
pytest -v          # verbose
pytest -q          # quiet
pytest --cov=mythicforge
```

---

## License

MIT License. See [LICENSE](LICENSE).

Security tool. Use responsibly, only with authorization.