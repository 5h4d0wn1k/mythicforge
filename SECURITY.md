# Security Policy

## Reporting a Vulnerability

This is a security tool; its own security matters. If you discover a vulnerability in MythicForge itself — for example, a way to make it take unauthorized action, a prompt-injection in report output, or an unsafe default — please report it privately.

**Do not open a public issue for security vulnerabilities.**

- Report via GitHub Security Advisories at: https://github.com/5h4d0wn1k/mythicforge/security/advisories/new
- Or open an encrypted/pastebin-style private note and link it from a new issue WITHOUT disclosing the vulnerability details in the issue body.

Please include:
- Affected version
- A minimal repro (no secrets)
- Impact assessment
- Suggested fix (if any)

## Scope

In scope: `mythicforge/**`, CLI argument handling, report generation (JSON/HTML/SARIF escaping), and the templates/mutation engines.

The target of this tool (the LLM) is **out of scope** — it is the thing being tested.

## Response expectations

- Acknowledgement within 5 business days.
- Assessment within 15 business days.
- A patched advisory release (with design credit) as soon as practical.

## Safe harbor

We will not pursue legal action against researchers who follow this disclosure policy and act in good faith.