---
name: java-deser-exploiter
description: Java Deserialization Vulnerability Research & Exploitation Assistant. Supports **Fat JAR/Decompiled Source** analysis with automatic dependency inference. Extracts deserialization endpoints, analyzes WAF breakpoints, and **mines as many available Gadget Chains as possible**.
metadata:
  openclaw:
    emoji: 🔓
    requires:
      bins: ["python3"]
---

# Java Deserialization Exploit Researcher

Analyzes Java project source code (including decompiled Fat JARs) to assist in mining deserialization vulnerabilities.

## When to Use (Trigger Phrases)

Use this skill when:
- "Analyze this Java project for deserialization vulnerabilities"
- "Find gadget chains in this Fat JAR"
- "Check WAF bypass possibilities"
- "Generate exploit notes for this Spring Boot app"
- "Scan for deserialization endpoints"

## Core Tasks

1. **Direction**: Identify reachable and dangerous routes
2. **Breakpoint Identification**: Point out where Gadget Chains are blocked
3. **Multi-Path Discovery**: List ALL possible variants and bypass ideas
4. **Reproduction**: Generate Maven dependency lists (supports Fat JAR inference)

---

## Quick Start

```bash
# Step 1: Scan Routes & Sinks
python scripts/search_deser_endpoints.py /path/to/project endpoints.md

# Step 2: Parse Dependencies (supports Fat JAR)
python scripts/parse_pom.py /path/to/project deps

# Step 3: Scan Dangerous Code
python scripts/scan_dangerous_code.py /path/to/project dangerous_code.md

# Step 4: Scan WAF Candidates
python scripts/analyze_waf.py /path/to/project waf_candidates.md
```

---

## Workflow

### 1. Route Discovery → Sink Tracing

**Core Logic: Find Routes first, then Vulnerabilities.**

```bash
python scripts/search_deser_endpoints.py /path/to/project report.md
```

- Script outputs: **Detected Routes** + **Potential Sinks**
- LLM task: Verify which routes connect to sinks
- If no routes found: Manually analyze `web.xml`, `struts.xml`, `application.properties`

> See [references/endpoint_identification.md](references/endpoint_identification.md) for detailed patterns.

### 2. Dependency Analysis & Chain Mining

For Fat JARs / decompiled projects:
```bash
python scripts/parse_pom.py /path/to/project output
# Generates: output_dependencies.xml (merges POM + JAR inference)
```

**Multi-Chain Mining Principle**: Do NOT stop at one chain!

> See [references/dependency_analysis.md](references/dependency_analysis.md) for chain mining strategies.

### 3. WAF Bypass Analysis

```bash
python scripts/analyze_waf.py /path/to/project waf_candidates.md
```

**Output Requirements**:
- Gadget Class Status Table
- ALL unblocked key classes (NO ellipsis!)
- At least 3 alternative directions

> See [references/waf_bypass.md](references/waf_bypass.md) for bypass techniques.

### 4. Dangerous Code Scanning

```bash
python scripts/scan_dangerous_code.py /path/to/project dangerous_code.md
```

**Key Patterns**:
- Method invocation: `Method.invoke`, `Class.forName`
- JNDI: `InitialContext.lookup`
- Command exec: `Runtime.exec`, `ProcessBuilder`
- File operations: `FileOutputStream`, `Files.write`

---

## Rules

| Rule | Description |
|------|-------------|
| **Verification First** | Confirm controller reachability, not just sink presence |
| **Multi-Path** | List at least 2-3 potential exploit paths |
| **No Ellipsis** | List ALL dependencies and classes - never use "..." or "etc." |
| **Clear Breakpoints** | If blocked, specify exact class and suggest alternatives |
| **Chinese Reports** | Final exploit notes must be in Chinese |

---

## Output Structure

```
{project}_exploit_research/
├── {project}_exploit_notes_{timestamp}.md    # Core analysis (Chinese)
├── {project}_dependencies.xml                 # XML dependency list
├── {project}_dangerous_code.md                # Dangerous code scan
└── references/                                # Gadget references
```

> See [references/report_template.md](references/report_template.md) for full template.

---

## References

- [endpoint_identification.md](references/endpoint_identification.md) - Route and sink patterns
- [dependency_analysis.md](references/dependency_analysis.md) - Chain mining strategies
- [waf_bypass.md](references/waf_bypass.md) - Bypass techniques
- [report_template.md](references/report_template.md) - Report format
- [gadget_database.json](references/gadget_database.json) - Machine-readable gadget DB
- [commons_collections_chains.md](references/commons_collections_chains.md) - CC chain details
