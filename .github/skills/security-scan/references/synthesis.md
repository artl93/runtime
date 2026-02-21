# Finding Synthesis

Roll up method-level findings into class-level and namespace-level summaries for large-scale audits.

## Contents

- [When to use](#when-to-use)
- [Method → Class rollup](#class-level-synthesis)
- [Class → Namespace rollup](#namespace-level-synthesis)
- [Rules](#rules)

## When to Use

| Audit scope | Use synthesis? |
|---|---|
| Single file or diff | No |
| Single library | Class-level only |
| Multiple libraries or namespace-wide | Both class and namespace levels |

## Class-Level Synthesis

Aggregate all findings for methods within a single class into a class-level summary.

### Template

```
Synthesize findings for class {CLASS_NAME} in {FILE_PATH}.

Method-level findings:
{LIST_OF_FINDINGS_WITH_DISPOSITIONS}

Produce a class-level summary:
1. Overall risk assessment (CRITICAL / HIGH / MEDIUM / LOW)
2. Dominant finding categories (e.g., "primarily serialization + DOS surface")
3. Cross-method patterns (e.g., "3 methods accept untrusted streams without size limits")
4. Disposition breakdown (N SECURITY_BUG, N DOCUMENT_USAGE, N HARDEN, N NO_ISSUE)
5. Recommended class-level actions (e.g., "add a shared validation helper for stream inputs")

CRITICAL RULE: Do NOT re-interpret method-level dispositions.
If a method finding was classified as DOCUMENT_USAGE, it stays DOCUMENT_USAGE in the rollup.
The class summary aggregates — it does not override.
```

### Output format

```markdown
### {ClassName} — {RiskLevel}

**Finding summary**: {N} findings ({breakdown by disposition})
**Dominant categories**: {categories}

**Cross-method patterns**:
- {pattern 1}
- {pattern 2}

**Recommended actions**:
- {action 1}
- {action 2}

**Method details**: See individual findings for {method1}, {method2}, ...
```

## Namespace-Level Synthesis

Aggregate class-level summaries within a namespace into a namespace-level overview.

### Template

```
Synthesize class-level summaries for namespace {NAMESPACE}.

Class summaries:
{LIST_OF_CLASS_SUMMARIES}

Produce a namespace-level overview:
1. Overall namespace risk (CRITICAL / HIGH / MEDIUM / LOW)
2. Classes ranked by risk (highest first)
3. Cross-class patterns (e.g., "inconsistent validation across Stream-accepting APIs")
4. Namespace-wide recommendations
5. Disposition totals across all classes

CRITICAL RULE: Preserve class-level assessments exactly.
Do not upgrade LOW classes or downgrade HIGH classes.
The namespace summary surfaces patterns visible only at this level.
```

### Output format

```markdown
## {Namespace} — {RiskLevel}

**Scope**: {N} classes, {M} total findings
**Disposition totals**: {N} SECURITY_BUG, {N} DOCUMENT_USAGE, {N} HARDEN, {N} NO_ISSUE

**Highest-risk classes**:
1. {ClassName} — {RiskLevel} ({finding count})
2. {ClassName} — {RiskLevel} ({finding count})

**Cross-class patterns**:
- {pattern visible only at namespace level}

**Namespace-wide recommendations**:
- {recommendation}

**Class details**: See individual summaries for each class.
```

## Rules

1. **Never re-interpret source findings.** Synthesis aggregates, it does not override dispositions or severity.
2. **Surface cross-cutting patterns.** The value of synthesis is spotting patterns invisible at the method level (e.g., "every class in this namespace has the same unbounded read pattern").
3. **Rank by risk.** Always list highest-risk items first.
4. **Preserve traceability.** Every namespace summary must link to class summaries, which link to method findings.
5. **Use SQL for tracking.** For large audits, store synthesis state:

```sql
CREATE TABLE IF NOT EXISTS synthesis_state (
  scope TEXT,          -- 'class' or 'namespace'
  name TEXT,           -- class or namespace name
  risk_level TEXT,     -- CRITICAL/HIGH/MEDIUM/LOW
  finding_count INT,
  security_bugs INT,
  document_usage INT,
  harden INT,
  no_issue INT,
  status TEXT DEFAULT 'pending',  -- pending, synthesized
  PRIMARY KEY (scope, name)
);
```
