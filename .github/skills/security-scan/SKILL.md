---
name: security-scan
description: Perform a security-focused review of code in dotnet/runtime, thinking like a security researcher to find exploitable vulnerabilities. Use when asked to "security scan", "security review", "find vulnerabilities", "check for security issues", or "audit security". Supports reviewing diffs, specific files, or entire directories. Analyzes API contracts, serializer safety, DOS surface, and documentation accuracy. Anti-pattern catalog and CodeQL rules are reusable for downstream repos like ASP.NET Core.
---

# Security Scan

Security-researcher-style audit for dotnet/runtime. Reasons about data flow, trust boundaries, exploit paths, API contract abuse, and documentation accuracy.

> 🚨 **Human-in-the-loop**: Identifies vulnerabilities and suggests fixes but NEVER auto-applies patches. All findings require human review.

## Step 1: Determine Scope and Triage

Infer the review scope from the user's request:

| User intent | Scope | How to gather files |
|---|---|---|
| Review my changes / PR review (default) | **diff** | `git diff --merge-base origin/HEAD` or PR diff via MCP |
| Scan these files | **files** | Read the specified files directly |
| Audit this directory / library | **directory** | Run triage script, then analyze prioritized files |

**For directory scope**, run the triage script to focus on security-relevant files:

```bash
python .github/skills/security-scan/scripts/scan_security_surface.py <path> --json
```

For deeper API-level prioritization, apply the risk scoring formula: [references/risk-scoring.md](references/risk-scoring.md)

For large-scale scans (multiple libraries, 50+ files): [references/coordination.md](references/coordination.md)

## Step 2: Research Context

Before analyzing code, understand the security posture of the affected area using `Glob`, `Grep`, and `Read`:

1. **Security patterns in use** — validation helpers, `SafeHandle` usage, `[SecurityCritical]` attributes, `// SECURITY:` comments
2. **Trust boundaries** — where external input enters; what crosses process, AppDomain, or serialization boundaries
3. **Related security tests** — search for `*Security*`, `*Injection*`, `*Sanitiz*`, `*Untrusted*` in nearby test projects

## Step 3: Analyze

Execute a multi-phase analysis:

**Phase 1 — Vulnerability assessment:** Trace data flow from untrusted inputs to sensitive operations. Check for injection, unsafe deserialization, privilege boundary crossings, TOCTOU issues, and DOS vectors.

**Phase 2 — Contract analysis:** For public APIs, check for implicit contracts, missing validation, inconsistent overloads, and cross-component mismatches. Produce per-parameter safety classifications (SAFE/UNSAFE/CONDITIONAL) for CRITICAL/HIGH tier APIs. See [references/contract-analysis.md](references/contract-analysis.md).

**Phase 3 — Serializer audit:** For any serializer usage flagged by triage, apply the per-serializer checklist. See [references/serializer-audit.md](references/serializer-audit.md).

**Phase 4 — Self-critique:** For each potential finding, attempt to disprove it. Verify against the full source file, check for mitigations in callers/callees. Only keep findings with confidence ≥ 8/10.

**Reference materials** (read as needed):
- **Vulnerability categories**: [references/runtime-categories.md](references/runtime-categories.md)
- **Exclusions and precedents**: [references/precedents-and-exclusions.md](references/precedents-and-exclusions.md)
- **Known anti-patterns**: [references/anti-patterns/README.md](references/anti-patterns/README.md)

## Step 4: Documentation Verification

For CRITICAL and HIGH tier APIs, compare official docs against the code:

- Fetch docs via `web_fetch` from `https://learn.microsoft.com/en-us/dotnet/api/{type}.{member}`
- Compare documented preconditions, exceptions, defaults, and security remarks against the implementation
- Flag discrepancies as `doc_code_drift` findings

See [references/docs-verification.md](references/docs-verification.md) for the full comparison methodology.

## Step 5: Verify and Classify

### Verification

When the `task` tool is available, use parallel verification. For critical findings or uncertain dispositions, use ensemble verification with multiple models: [references/ensemble-verification.md](references/ensemble-verification.md)

Basic verification:
1. **Discovery agent**: `general-purpose` sub-agent with the diff/files and categories from [references/runtime-categories.md](references/runtime-categories.md).
2. **Verification agents**: Parallel `explore` agents to independently verify each finding.
3. **Filter**: Only keep findings with verification confidence ≥ 8.

### Disposition Classification

Every finding MUST receive a disposition:

| Disposition | Meaning | Action |
|---|---|---|
| 🔴 **SECURITY_BUG** | Exploitable. Must fix. | File bug, assign severity |
| 🟡 **DOCUMENT_USAGE** | Correct but easy to misuse. | Add docs/warnings. No code fix. |
| 🔵 **HARDEN** | Not exploitable. Defense-in-depth. | Optional fix |
| 🟢 **NO_ISSUE** | Looks suspicious but safe. | Record reasoning |

## Step 6: Synthesize (large audits only)

For multi-library audits, roll findings up: method → class → namespace summaries. See [references/synthesis.md](references/synthesis.md).

## Step 7: Generate CodeQL Rules (optional)

Convert SECURITY_BUG and DOCUMENT_USAGE findings into CodeQL queries for automated CI detection. See [references/codeql-generation.md](references/codeql-generation.md).

## Step 8: Report

Format findings per [references/output-format.md](references/output-format.md).

Record new anti-patterns in [references/anti-patterns/README.md](references/anti-patterns/README.md) for downstream repo reuse.
