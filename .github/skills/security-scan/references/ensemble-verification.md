# Ensemble Verification

Multi-model consensus for high-confidence security findings. Run the same analysis across different models/temperatures, then resolve disagreements.

## Contents

- [When to use](#when-to-use)
- [Configurations](#configurations)
- [Workflow](#workflow)
- [Disagreement handling](#disagreement-handling)

## When to Use

| Scenario | Use ensemble? |
|---|---|
| Diff review, few findings | No — standard verification is sufficient |
| Finding on a critical API (crypto, auth, serialization) | Yes — Configuration A |
| Uncertain disposition (SECURITY_BUG vs. DOCUMENT_USAGE) | Yes — Configuration B |
| Large audit, many findings to triage | Yes — Configuration C for batch validation |

## Configurations

### Configuration A: Model Diversity (highest confidence)

Run the same analysis prompt across different models:

| Run | Model | Temperature | Purpose |
|---|---|---|---|
| 1 | claude-opus-4 | 0.3 | Deep reasoning, conservative |
| 2 | claude-sonnet-4 | 0.5 | Balanced analysis |
| 3 | claude-haiku-4 | 0.7 | Fast, different perspective |

Best for: Critical findings where you need highest confidence. Most expensive.

### Configuration B: Temperature Diversity (cost-sensitive)

Same model, different temperatures:

| Run | Model | Temperature | Purpose |
|---|---|---|---|
| 1 | claude-sonnet-4 | 0.3 | Conservative interpretation |
| 2 | claude-sonnet-4 | 0.5 | Balanced |
| 3 | claude-sonnet-4 | 0.7 | More exploratory |

Best for: Uncertain dispositions where you want multiple perspectives at lower cost.

### Configuration C: Quick Validation (sanity check)

Same model, same temperature, 3 runs:

| Run | Model | Temperature |
|---|---|---|
| 1-3 | claude-sonnet-4 | 0.5 |

Best for: Batch validation of many findings. If all 3 agree, high confidence. If they disagree, escalate to Configuration A.

## Workflow

### Step 1: Prepare Analysis Context

For each finding to verify, create a structured prompt:

```
Analyze this potential security finding independently.

File: {FILE_PATH}:{LINE}
Code: {RELEVANT_CODE_SNIPPET}
Claimed category: {CATEGORY}
Claimed severity: {SEVERITY}

Questions to answer:
1. Is this a real vulnerability? (yes/no/uncertain)
2. If yes, what disposition? (SECURITY_BUG / DOCUMENT_USAGE / HARDEN / NO_ISSUE)
3. Confidence score (0.0 - 1.0)
4. Brief justification (2-3 sentences)

Return JSON:
{
  "is_vulnerability": true/false/null,
  "disposition": "SECURITY_BUG|DOCUMENT_USAGE|HARDEN|NO_ISSUE",
  "confidence": 0.0-1.0,
  "justification": "..."
}
```

### Step 2: Run Analyses

Launch one `general-purpose` sub-agent per run, each with the model override:

```
task(agent_type="general-purpose", model="<model>", prompt=<analysis_prompt>)
```

### Step 3: Calculate Agreement

```sql
CREATE TABLE IF NOT EXISTS ensemble_results (
  finding_id TEXT,
  run_number INT,
  model TEXT,
  temperature REAL,
  is_vulnerability BOOLEAN,
  disposition TEXT,
  confidence REAL,
  justification TEXT,
  PRIMARY KEY (finding_id, run_number)
);

-- Agreement ratio
SELECT finding_id,
  COUNT(DISTINCT disposition) as unique_dispositions,
  MAX(disposition) as majority_disposition,
  AVG(confidence) as avg_confidence,
  CASE
    WHEN COUNT(DISTINCT disposition) = 1 THEN 'unanimous'
    WHEN COUNT(DISTINCT disposition) = 2 THEN 'split'
    ELSE 'no_consensus'
  END as agreement_status
FROM ensemble_results
GROUP BY finding_id;
```

### Step 4: Apply Decision Rules

| Agreement | Avg Confidence | Action |
|---|---|---|
| Unanimous | ≥ 0.8 | Accept disposition |
| Unanimous | < 0.8 | Accept but flag for review |
| Split (2-1) | ≥ 0.6 | Use majority, document minority view |
| Split (2-1) | < 0.6 | Escalate to human review |
| No consensus | Any | Escalate to human review |

## Disagreement Handling

### Critical Disagreements (always escalate)

These disagreements MUST go to human review:

- **SECURITY_BUG vs. NO_ISSUE** — completely opposite conclusions
- Findings involving cryptography, authentication, or certificate validation
- Any finding where one run identifies RCE potential
- Disagreement on `safe_for_untrusted_input` classification

### Moderate Disagreements (use conservative answer)

- **SECURITY_BUG vs. DOCUMENT_USAGE** — use SECURITY_BUG (more conservative)
- **DOCUMENT_USAGE vs. HARDEN** — use DOCUMENT_USAGE
- **HARDEN vs. NO_ISSUE** — use HARDEN
- Disagreements on severity within the same disposition → use higher severity

### Minor Disagreements (use majority)

- Different confidence scores but same disposition → average the scores
- Same disposition, different justifications → combine justifications
- Agreement on disposition, disagreement on CWE classification → use most specific CWE

### Red Flags Requiring Human Review

Regardless of agreement scores:
- [ ] 2-way tie with no majority
- [ ] All runs give different answers
- [ ] Contradictory reasoning (one says "validated by caller", another says "no validation")
- [ ] Finding involves a known CVE pattern
- [ ] Confidence < 0.6 across all runs
