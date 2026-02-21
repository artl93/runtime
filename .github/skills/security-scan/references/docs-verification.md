# Documentation vs. Code Verification

Compare official learn.microsoft.com documentation against actual implementation to find security-relevant discrepancies.

## Contents

- [Why this matters](#why-this-matters)
- [Workflow](#workflow)
- [What to compare](#what-to-compare)
- [Discrepancy categories](#discrepancy-categories)

## Why This Matters

Downstream consumers (ASP.NET Core, SDK, user applications) rely on Microsoft's official documentation to use APIs safely. When docs are wrong, incomplete, or misleading about security behavior, every consumer inherits the risk.

Common examples:
- Docs say "throws `ArgumentNullException`" but code silently accepts null
- Docs don't mention that `XmlReader.Create` processes DTDs by default
- Docs describe a default value of 64 for `MaxDepth` but the code uses a different default
- Docs say "validates input" but the validation is incomplete or bypassable

## Workflow

### Step 1: Identify APIs to Verify

From the risk scoring results, select APIs at **CRITICAL** and **HIGH** tiers for documentation verification. For STANDARD tier, verify only if the finding disposition is uncertain.

### Step 2: Fetch Documentation

Use `web_fetch` to retrieve the official API documentation:

```
URL pattern: https://learn.microsoft.com/en-us/dotnet/api/{fully-qualified-type-name}.{member}

Examples:
- https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreader.create
- https://learn.microsoft.com/en-us/dotnet/api/system.text.json.jsonserializer.deserialize
- https://learn.microsoft.com/en-us/dotnet/api/system.io.file.readalltext
```

For overloaded methods, the docs page typically covers all overloads. Check each one.

### Step 3: Compare Against Source

Read the actual implementation source and compare point-by-point.

### Step 4: Record Discrepancies

Flag each discrepancy with a `doc_code_drift` category and appropriate disposition.

## What to Compare

### Parameters and Preconditions

| Doc claim | Check in code |
|---|---|
| "Throws `ArgumentNullException` if X is null" | Does code actually have `ArgumentNullException.ThrowIfNull(x)`? |
| "X must be a valid URI" | Is `Uri.TryCreate` or equivalent called? |
| "X must be non-negative" | Is there an `ArgumentOutOfRangeException` check? |
| Parameter described as "optional" | Does the overload without it behave safely? |

### Exceptions and Error Handling

| Doc claim | Check in code |
|---|---|
| Documented exception types | Are all listed exceptions actually thrown? |
| Undocumented exceptions | Does code throw exceptions not listed in docs? |
| "This method never throws" | Are exceptions caught and swallowed? What happens on failure? |

### Security Remarks

| Doc claim | Check in code |
|---|---|
| "Validate input before calling" | Does the API enforce validation, or is it caller's responsibility? |
| Security warnings in Remarks section | Are the warnings accurate and complete? |
| "Thread-safe" claims | Is there proper synchronization? |
| "This type is immutable" | Can state actually be mutated via reflection or unsafe code? |

### Default Values

| Doc claim | Check in code |
|---|---|
| Documented default for optional parameter | Does code use the same default? |
| Default configuration values | e.g., `MaxDepth`, `DtdProcessing`, `TypeNameHandling` — match docs? |
| "Defaults to secure configuration" | Is the actual default really secure? |

### Behavioral Guarantees

| Doc claim | Check in code |
|---|---|
| "Returns null if not found" | Does it actually return null, or throw? |
| "Truncates to MaxLength" | Does it truncate silently or throw? |
| "Disposes the stream" | Does it actually dispose, or leave it open? |
| "Encoding defaults to UTF-8" | What encoding does the code actually use? |

## Discrepancy Categories

### 🔴 Security-Critical Drift

Documentation actively misleads about security behavior:
- Docs say input is validated; code doesn't validate
- Docs omit a known dangerous default (e.g., DTD processing enabled)
- Docs describe safe behavior; code has an exploitable edge case

**Disposition**: SECURITY_BUG or DOCUMENT_USAGE depending on whether code or docs should change.

### 🟡 Missing Security Guidance

Documentation is technically correct but omits important security context:
- No mention of DOS risk for unbounded operations
- No guidance on secure configuration for serializers
- No warning about thread-safety requirements in security-critical paths

**Disposition**: DOCUMENT_USAGE — docs need security remarks added.

### 🔵 Behavioral Drift

Documentation describes behavior that doesn't match implementation, but impact is non-security:
- Wrong default value for a non-security parameter
- Incorrect exception type documented
- Missing documentation for a new overload

**Disposition**: HARDEN or NO_ISSUE — file a docs bug but not a security issue.

### ⚪ Documentation Correct, Code Questionable

Documentation correctly describes the API, but the documented behavior itself is questionable:
- Docs correctly say "does not validate input" — but should the API validate?
- Docs correctly say "processes DTDs by default" — but should the default be secure?

**Disposition**: Depends on analysis — may be SECURITY_BUG (change the code) or DOCUMENT_USAGE (add security warnings).
