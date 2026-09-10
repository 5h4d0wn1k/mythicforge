# Authorization Policy & Legal Kit

MythicForge is a **penetration-testing tool**. Running it against a system is an aggressive act that can only be performed lawfully with **explicit written authorization** from the system owner.

## 1. You MUST have written authorization

Before pointing MythicForge (or any probe) at any live LLM endpoint:

1. Obtain a signed statement from the system's legal owner.
2. Scope it to the exact endpoint(s), models, and time window.
3. Keep it on file. Do not begin testing without it.

## 2. Model input / output authorization

The prompts sent by MythicForge can trigger the target model to generate content that is hostile, offensive, or harmful. The **model architect and the system owner** (not the tool, not the operator) remain responsible for preventing harmful outputs. Confirm in writing that the owner accepts this before triggering such content.

## 3. Template authorization letter

Below is a starting template. Always have it reviewed by counsel familiar with your jurisdiction. Replace bracketed placeholders.

---

> **Letter of Authorization for Security Testing**
>
> To: [Organization / Owner name]
> Re: Authorized security testing of LLM application(s)
>
> I am the owner / duly authorized representative of [name of organization] ("Owner"). I hereby authorize [tester name] ("Tester") to conduct security testing of the following system(s) using the MythicForge adversarial LLM testing framework and related tooling:
>
> - Target endpoint(s) / API: [list URLs or model deployment IDs]
> - Models in scope: [e.g. "gpt-4o deployment 'prod-llm'", "local llama.cpp at 10.0.0.12:8080"]
> - Authorization window: [YYYY-MM-DD] through [YYYY-MM-DD]
> - Authorized tests: adversarial prompt injection, jailbreak, extraction, resource-exhaustion, and associated measurement activities
> - Constraints: [e.g. max $ budget, no data destruction, no production customer data, test data only]
>
> The Tester is authorized to send adversarial inputs that may induce the target models to produce unsafe or offensive text, and hereby acknowledges that the Tester exercises an authorization to cause the LLM to generate such content for testing purposes and assumes responsibility for the consequences of its use.
>
> Owner agrees to notify the Tester of any production incidents and to coordinate attribution of the incident to the testing window before any external reporting.
>
> Signed: ______________________  Date: ____________
> For: [Owner legal entity]
> Tester acknowledgment: ______________________  Date: ____________

---

## 4. What IS authorized vs NOT

| Scope item                                              | Auto-authorized by this doc? |
|---------------------------------------------------------|------------------------------|
| Testing LLM API endpoints you own / are contracted to   | Yes                         |
| Any endpoint without a signed agreement                 | **No**                      |
| Using generated content against third parties           | **No**                      |
| Extracting PII of real end users                        | **No**                      |
| Payment card / credential harvesting                    | **No**                      |
| Testing during scheduled maintenance when scoped        | Only if in scope            |

## 5. Records

Keep: the authorization letter, the exact MythicForge version (`mythicforge --version`), the seed, the target config, the JSON report, and the hash (`compute_hash`) of the exact payload set. This is your evidential chain for the engagement.

## 6. Jurisdiction

Security testing law differs by jurisdiction. If in doubt, get counsel's opinion before running. Some jurisdictions require active notification of relevant CERTs; others require coordination with the vendor (e.g. LLM provider) as well as the owner.

*This document is provided as a convenience and is not legal advice.*