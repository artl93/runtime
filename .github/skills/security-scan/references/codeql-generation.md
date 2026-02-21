# CodeQL Rule Generation

Convert security findings and anti-patterns into CodeQL queries for automated detection in CI.

## Contents

- [Workflow](#workflow)
- [Pattern templates](#pattern-templates)
- [Existing rules index](#existing-rules-index)
- [Validation](#validation)

## Workflow

### Step 1: Check Existing Coverage

Before writing a new rule, check if it's already covered:

```bash
# Search existing CodeQL rules by CWE
grep -r "CWE-" ql/csharp/ql/src/Security/ --include="*.ql" -l
# Search by API name
grep -r "XmlReader\|JsonSerializer\|BinaryFormatter" ql/csharp/ql/src/ --include="*.qll" -l
```

### Step 2: Choose Pattern Template

| Finding type | CodeQL pattern | When to use |
|---|---|---|
| Tainted data reaches dangerous sink | **Taint tracking** | Injection, path traversal, SSRF |
| API called without required precondition | **API misuse** | Missing validation, missing config |
| Dangerous configuration value | **Config detection** | `TypeNameHandling != None`, `DtdProcessing.Parse` |

### Step 3: Write, Test, Validate

See pattern templates below, then validate per the [validation section](#validation).

## Pattern Templates

### Taint Tracking

For vulnerabilities where untrusted data flows to a dangerous operation (injection, traversal, SSRF):

```ql
/**
 * @name <Title>
 * @description <Description>
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id cs/security/<rule-id>
 * @tags security
 *       external/cwe/cwe-<NNN>
 */

import csharp
import semmle.code.csharp.security.dataflow.flowsources.FlowSources
import semmle.code.csharp.dataflow.TaintTracking

module <Name>Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ThreatModelFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getTarget().hasName("<dangerousMethod>") and
      mc.getTarget().getDeclaringType().hasQualifiedName("System.<Namespace>", "<Type>") and
      sink.asExpr() = mc.getArgument(<N>)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // Validation that makes the data safe
    exists(MethodCall mc |
      mc.getTarget().hasName("<validationMethod>") and
      node.asExpr() = mc
    )
  }
}

module <Name>Flow = TaintTracking::Global<<Name>Config>;
import <Name>Flow::PathGraph

from <Name>Flow::PathNode source, <Name>Flow::PathNode sink
where <Name>Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted data from $@ flows to <dangerous operation>.", source.getNode(), "user input"
```

### API Misuse

For vulnerabilities where a required precondition is missing before an API call:

```ql
/**
 * @name <Title>
 * @description <Description>
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision high
 * @id cs/security/<rule-id>
 * @tags security
 *       external/cwe/cwe-<NNN>
 */

import csharp

from MethodCall dangerousCall
where
  dangerousCall.getTarget().hasName("<method>") and
  dangerousCall.getTarget().getDeclaringType().hasQualifiedName("System.<Namespace>", "<Type>") and
  // No preceding validation call dominates this call
  not exists(MethodCall validation |
    validation.getTarget().hasName("<validationMethod>") and
    validation.getAControlFlowNode().dominates(dangerousCall.getAControlFlowNode())
  )
select dangerousCall, "Call to <method> without prior <validation>."
```

### Config Detection

For dangerous configuration values:

```ql
/**
 * @name <Title>
 * @description <Description>
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision very-high
 * @id cs/security/<rule-id>
 * @tags security
 *       external/cwe/cwe-<NNN>
 */

import csharp

from Assignment assign, PropertyAccess prop
where
  prop = assign.getLValue() and
  prop.getTarget().hasName("<DangerousProperty>") and
  prop.getTarget().getDeclaringType().hasQualifiedName("Newtonsoft.Json", "JsonSerializerSettings") and
  not assign.getRValue().(FieldAccess).getTarget().hasName("<SafeValue>")
select assign, "Dangerous configuration: <property> set to non-safe value."
```

## Existing Rules Index (Coverage Gaps)

Areas with existing CodeQL coverage (avoid duplicating):
- SQL injection (CWE-089): 3 queries
- XSS (CWE-079): 2 queries
- Path traversal (CWE-022): 2 queries
- XML injection/XXE (CWE-611): 2 queries
- LDAP injection (CWE-090): 1 query
- Regex injection (CWE-730): 1 query
- Insecure deserialization (CWE-502): 3 queries
- Hardcoded credentials (CWE-798): 2 queries
- Certificate validation (CWE-295): 1 query
- Weak crypto (CWE-327/328): 2 queries

**Known gaps needing new rules:**
- System.Text.Json custom converter misuse
- `JsonDocument.Parse` without size limits (DOS)
- gRPC/GraphQL injection
- NoSQL injection
- SSRF via `HttpClient`
- Unbounded stream reads (AP-001)
- Unbounded allocations from external size (AP-002)
- Collection growth from untrusted input (AP-015)

## Anti-Pattern to CodeQL Mapping

Each anti-pattern in `anti-patterns/README.md` should produce a CodeQL rule:

| Anti-Pattern | CodeQL Pattern | CWE |
|---|---|---|
| AP-001: Unbounded stream read | Taint tracking (source→ReadToEnd) | CWE-400 |
| AP-002: Unbounded allocation | Taint tracking (source→new byte[]) | CWE-400 |
| AP-003: BinaryFormatter | Config detection | CWE-502 |
| AP-004: TypeNameHandling | Config detection | CWE-502 |
| AP-005: JsonDocument no limits | API misuse | CWE-400 |
| AP-006: XmlReader no DTD prohibit | API misuse | CWE-611 |
| AP-007: Path traversal | Taint tracking | CWE-022 |
| AP-008: Process.Start injection | Taint tracking | CWE-078 |
| AP-009: Non-constant-time compare | API misuse | CWE-208 |
| AP-013: Cert validation bypass | Config detection | CWE-295 |

## Validation

### Mandatory: All rules must be validated before use

```bash
# 1. Create test pack
mkdir -p test && cat > test/qlpack.yml << 'EOF'
name: security-scan-tests
version: 0.0.1
dependencies:
  codeql/csharp-all: "*"
  codeql/csharp-queries: "*"
EOF

# 2. Compile check
codeql query compile rule.ql

# 3. Create test database
codeql database create testdb --language=csharp --source-root=test-project/

# 4. Run query
codeql query run rule.ql --database=testdb

# 5. Check results
codeql bqrs decode results.bqrs
```

### Test case design

Every rule needs test cases with clear BAD/GOOD annotations:

```csharp
class TestCases
{
    void Bad_UnboundedRead(Stream networkStream)
    {
        var reader = new StreamReader(networkStream);
        string data = reader.ReadToEnd(); // BAD: unbounded read from network
    }

    void Good_BoundedRead(Stream networkStream)
    {
        var buffer = new byte[MaxSize];
        int read = networkStream.Read(buffer, 0, buffer.Length); // GOOD: bounded
    }
}
```

### Common compilation errors

| Error | Fix |
|---|---|
| `Could not resolve type` | Check `import` statements; use `hasQualifiedName` with correct namespace |
| `Ambiguous call` | Add type annotations to narrow overload resolution |
| `No results` | Verify predicate logic with `select` on intermediate steps |
| `Wrong results on generics` | Use `getUnboundDeclaration()` for generic methods |
