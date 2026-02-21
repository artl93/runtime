# Output Format

## Report Template

```
## 🔒 Security Scan — <scope description>

### Summary

**Findings**: <N security bugs, N document usage, N harden, N no issue>
**Confidence threshold**: ≥ 8/10
**Verdict**: <✅ No issues found / ⚠️ Issues found — human review required>

---

### Findings

#### 🔴 SECURITY_BUG: <Brief title> — `path/to/file.cs:42`

- **Category**: <e.g., command_injection, path_traversal, unsafe_deserialization, doc_code_drift>
- **Confidence**: <8-10>/10
- **Description**: <What the vulnerability is, in plain English>
- **Exploit scenario**: <Concrete attack path — how an attacker would exploit this>
- **Recommendation**: <Specific fix, with code suggestion if possible>
- **CWE**: <CWE-NNN>

#### 🟡 DOCUMENT_USAGE: <Brief title> — `path/to/file.cs:87`

- **Category**: ...
- **Confidence**: ...
- **Description**: <API is correct but easy to misuse without guidance>
- **Misuse scenario**: <How a consumer could get this wrong>
- **Recommendation**: <What docs/warnings to add>
- **CWE**: <CWE-NNN if applicable>

#### 🔵 HARDEN: <Brief title> — `path/to/file.cs:120`

- **Category**: ...
- **Description**: <Not exploitable today but defense-in-depth worthwhile>
- **Recommendation**: <Optional hardening fix>

#### 🟢 NO_ISSUE: <Brief title> — `path/to/file.cs:200`

- **Category**: ...
- **Reasoning**: <Why this looks suspicious but is actually safe>

---

### Files Reviewed

<List of files examined with brief notes on security-relevant observations>

### Methodology Notes

<Brief description of what was checked, tools/agents used, and any limitations>
```

## Disposition Classification

Every finding MUST have exactly one disposition:

| Disposition | Icon | Meaning | Action required |
|---|---|---|---|
| **SECURITY_BUG** | 🔴 | Exploitable vulnerability. Must fix. | File bug, assign severity, block release if critical |
| **DOCUMENT_USAGE** | 🟡 | Correct but easy to misuse. No code fix. | Add/update docs + XML comments. Add to anti-pattern catalog |
| **HARDEN** | 🔵 | Not exploitable today. Defense-in-depth. | Optional fix. Low priority |
| **NO_ISSUE** | 🟢 | Looks suspicious but is safe. | No action. Record reasoning to prevent re-investigation |

### Classification criteria

- **SECURITY_BUG**: Concrete exploit scenario exists. Attacker can reach the path. Impact is HIGH or MEDIUM.
- **DOCUMENT_USAGE**: API works as designed, but "safe" usage isn't obvious. Downstream consumers could easily misuse without guidance.
- **HARDEN**: No known exploit, but adding validation/bounds costs little and prevents regressions.
- **NO_ISSUE**: Pattern matches an anti-pattern signature but context shows mitigation (pre-validated by all callers, internal-only, etc.).

## Severity Guidelines

Applies to SECURITY_BUG findings only:

- **🔴 HIGH**: Directly exploitable — leads to RCE, data breach, auth bypass, or arbitrary code execution. Clear attack path exists.
- **🟡 MEDIUM**: Exploitable under specific conditions with significant impact. Requires particular configuration, timing, or access level.
- **Do not report LOW severity.** Better to miss theoretical issues than flood the report with noise.

## Confidence Scoring

- **9-10**: Certain exploit path identified; verified against full source context
- **8-9**: Clear vulnerability pattern with known exploitation methods; verified no existing mitigation
- **Below 8**: Do not report. Too speculative.

## Final Checklist

Before presenting findings:

- [ ] Each finding verified against the **full source file**, not just the diff
- [ ] Each finding checked for **existing mitigations** in callers/callees
- [ ] Each SECURITY_BUG has a **concrete exploit scenario**
- [ ] Each DOCUMENT_USAGE has a **concrete misuse scenario**
- [ ] Each NO_ISSUE has **documented reasoning** for why it's safe
- [ ] No findings in **excluded categories** (test code, internal-only DOS, etc.)
- [ ] Confidence ≥ 8 for every SECURITY_BUG and DOCUMENT_USAGE finding
- [ ] All code suggestions are **syntactically correct** and would compile
- [ ] Dispositions are consistent with ensemble results (if ensemble was used)
