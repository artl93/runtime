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

## Step 3: Analyze (dispatch scanner agents)

**This skill acts as the orchestrator.** Deep analysis is performed by scanner sub-agents with full security domain knowledge loaded into their context.

### Dispatching scanners

1. Read [references/scanner-prompt.md](references/scanner-prompt.md) — this is the concentrated "security researcher brain"
2. For each batch of files (max 10-15 per agent), launch a `general-purpose` sub-agent via the `task` tool:

```
task(
  agent_type="general-purpose",
  prompt="""
  {SCANNER_PROMPT_CONTENT}

  ## Your Assignment

  Analyze these files for security vulnerabilities:
  {FILE_LIST_WITH_PATHS}

  Library: {LIBRARY_NAME}
  Context: {BRIEF_DESCRIPTION_OF_WHAT_THIS_LIBRARY_DOES}

  Read each file and apply the full analysis framework above. Return structured JSON findings.
  """
)
```

3. For diff scope with few files, you may analyze directly instead of dispatching — read `scanner-prompt.md` for the analysis framework and apply it yourself.

### When to use deep reference docs

If the scanner flags serializer-related findings, consult [references/serializer-audit.md](references/serializer-audit.md) for per-serializer details.

For contract analysis requiring the structured design doc template, see [references/contract-analysis.md](references/contract-analysis.md).

**Additional reference materials** (read as needed):
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

When the `task` tool is available, use parallel verification. For each finding from scanner agents, launch a separate `explore` agent to independently verify:

```
task(
  agent_type="explore",
  prompt="""
  Verify this security finding:

  File: {FILE_PATH}:{LINE}
  Category: {CATEGORY}
  Claimed vulnerability: {DESCRIPTION}
  Disposition: {DISPOSITION}

  1. Read the full source file
  2. Check callers — do they validate before calling?
  3. Check callees — does the function do its own validation?
  4. Search for similar patterns elsewhere in the codebase

  Return JSON: { "verified": bool, "confidence": 0-10, "justification": "..." }
  """
)
```

For critical findings or uncertain dispositions, use ensemble verification: [references/ensemble-verification.md](references/ensemble-verification.md)

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
