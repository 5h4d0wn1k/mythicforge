# Contributing to MythicForge

Thanks for contributing to a security tool. A few rules of the road:

## Responsibilities

- Every change stays **offline-testable**. New attack payloads go in `attacks/` with tests in `tests/attacks/`.
- New techniques must carry full taxonomy: technique enum, severity, OWASP/NIST/MITRE mappings, tags, description.
- Mutation engine additions need a deterministic `mutate_fn` and a test.
- Keep coverage >= 90%.

## Workflow

1. Fork, create a branch off `main`.
2. Add tests first (or with) the change.
3. Run `pytest -q` and `pytest --cov=mythicforge`.
4. Open a PR against `main`. Reference the OWASP/NIST/MITRE item or the paper you're implementing.

## Standards for new attacks

- **Real, not decorative.** If you add an attack, implement the actual mechanism (encoding, multi-turn sequence, Unicode trick), not a plain string.
- Cite your sources in the description (paper year, CVE, incident writeup) via metadata where possible.
- Default severity should be conservative.

## CLI & API compatibility

- Add any new provider to `TargetConfig` + `create_target()`.
- CLI flags must round-trip into config objects.
- Never break the JSON report schema without a v1.0.1+ changelog entry.

## Legal

By submitting a PR you agree your contribution is original, MIT-licensed, and may be incorporated into the project. Do not submit content that would violate the [DISCLAIMER](docs/DISCLAIMER.md) or applicable law.

## Behavior

Behave per the [Code of Conduct](CODE_OF_CONDUCT.md). Keep discussion constructive; this project touches sensitive subject matter.