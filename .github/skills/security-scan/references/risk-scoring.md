# API-Level Risk Scoring

Formula-based scoring for prioritizing which APIs get deep security analysis. Supplements the grep-based triage script as a Layer 2 refinement.

## Contents

- [Scoring formula](#scoring-formula)
- [Tier thresholds](#tier-thresholds)
- [Worked examples](#worked-examples)
- [Usage](#usage)

## Scoring Formula

**Total score = Parameter risk + Method pattern + Return type + Namespace** (max 100)

### Parameter Risk (max 40)

Score the highest-risk parameter accepted by the method:

| Parameter type | Score | Rationale |
|---|---|---|
| `Uri`, `Stream`, `XmlDocument`, `XmlReader`, `TextReader` | +20 | Direct untrusted input vectors |
| `Type`, `Assembly`, `MethodInfo` | +20 | Reflection / code loading surface |
| `byte[]`, `ReadOnlySpan<byte>`, `ReadOnlyMemory<byte>` | +15 | Binary data, possible buffer issues |
| `string` (representing paths, URLs, queries, commands) | +10 | Injection surface |
| `string` (general purpose) | +5 | Lower risk but still untrusted data |
| `int`, `long`, `bool`, `enum` | +1 | Minimal risk |
| No parameters | +0 | No input surface |

When multiple parameters exist, use the **sum of the top 2** (capped at 40).

### Method Pattern (max 30)

Score based on the method name / verb:

| Pattern | Score | Examples |
|---|---|---|
| High-risk verbs | +30 | `Load`, `Execute`, `Start`, `Deserialize`, `Parse`, `Compile`, `Invoke`, `CreateInstance` |
| Medium-risk verbs | +15 | `Read`, `Write`, `Open`, `Connect`, `Send`, `Receive`, `Create` |
| Low-risk verbs | +5 | `Get`, `Set`, `Add`, `Remove`, `Contains`, `Equals` |
| Safe verbs | +0 | `ToString`, `GetHashCode`, `IsNullOrEmpty`, `Dispose` |

### Return Type (max 20)

| Return type | Score | Rationale |
|---|---|---|
| `Stream`, `TextReader`, `XmlReader`, `Process` | +20 | Returns a resource requiring safe handling |
| `object`, `dynamic`, `T` (unconstrained generic) | +15 | Type uncertainty |
| `byte[]`, `string` (containing structured data) | +10 | May contain sensitive data |
| `void` | +5 | Side effects only — what did it do? |
| `bool`, `int`, simple value types | +2 | Minimal risk |

### Namespace (max 10)

| Namespace | Score |
|---|---|
| `System.IO`, `System.Net`, `System.Xml`, `System.Security`, `System.Runtime.InteropServices` | +10 |
| `System.Text.Json`, `System.Runtime.Serialization`, `System.Diagnostics` | +8 |
| `System.Reflection`, `System.Threading` | +6 |
| `System.Collections`, `System.Linq`, `System.Text` | +3 |
| `System`, `Microsoft.Extensions` | +2 |

## Tier Thresholds

| Score | Tier | Analysis depth |
|---|---|---|
| 51–100 | 🔴 **CRITICAL** | Full analysis: contract + serializer audit + docs verification + ensemble |
| 31–50 | 🟡 **HIGH** | Full analysis: contract + serializer audit + docs verification |
| 11–30 | 🔵 **STANDARD** | Standard analysis with single-agent verification |
| 0–10 | ⚪ **MINIMAL** | Quick scan — still analyzed, never skipped |

## Worked Examples

### Example 1: `XmlReader.Create(Stream, XmlReaderSettings)`
- Parameter: `Stream` (+20) + `XmlReaderSettings` (+5) = **25** (capped at 40)
- Method: `Create` (+15)
- Return: `XmlReader` (+20)
- Namespace: `System.Xml` (+10)
- **Total: 70 → CRITICAL**

### Example 2: `String.IsNullOrEmpty(string)`
- Parameter: `string` general (+5)
- Method: `IsNullOrEmpty` (+0)
- Return: `bool` (+2)
- Namespace: `System` (+2)
- **Total: 9 → MINIMAL**

### Example 3: `JsonSerializer.Deserialize<T>(Stream, JsonSerializerOptions)`
- Parameter: `Stream` (+20) + `JsonSerializerOptions` (+5) = **25**
- Method: `Deserialize` (+30)
- Return: `T` unconstrained (+15)
- Namespace: `System.Text.Json` (+8)
- **Total: 78 → CRITICAL**

### Example 4: `File.ReadAllText(string)`
- Parameter: `string` path (+10)
- Method: `Read` (+15)
- Return: `string` structured data (+10)
- Namespace: `System.IO` (+10)
- **Total: 45 → CRITICAL**

## Usage

### As a triage agent prompt

After the grep-based `scan_security_surface.py` identifies security-relevant files, launch a Haiku `explore` agent to score individual APIs:

```
Score these public APIs using the risk scoring formula.

APIs to score:
{LIST_OF_PUBLIC_METHOD_SIGNATURES}

For each API, provide:
- Parameter risk (max 40): which params, what scores
- Method pattern (max 30): verb classification
- Return type (max 20): what's returned
- Namespace (max 10): which namespace

Return JSON:
{
  "scores": [
    { "api": "XmlReader.Create(Stream, XmlReaderSettings)", "parameter": 25, "method": 15, "return": 20, "namespace": 10, "total": 70, "tier": "HIGH" }
  ]
}
```

### In SQL tracking

```sql
CREATE TABLE IF NOT EXISTS api_risk_scores (
  api_signature TEXT PRIMARY KEY,
  library TEXT,
  parameter_score INT,
  method_score INT,
  return_score INT,
  namespace_score INT,
  total_score INT,
  tier TEXT,  -- CRITICAL, HIGH, STANDARD, MINIMAL
  analysis_status TEXT DEFAULT 'pending'
);
```
