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

# Step 2: Parse Dependencies (Maven + Gradle + Fat JAR + non-Maven bundled libs)
# Scans: META-INF/maven > pom.xml > gradle.lockfile > build.gradle > JAR filenames > package dirs
# Outputs: deps_dependencies.xml, deps_dependencies.md, deps_llm_verify_prompt.md (if needed)
python scripts/parse_pom.py /path/to/project deps

# Step 3: Scan Dangerous Code (sinks + intermediate gadget nodes in target source)
python scripts/scan_dangerous_code.py /path/to/project dangerous_code.md

# Step 4: Magic Method Search — run grep directly, no script needed (see Workflow §4)

# Step 5: Scan WAF Candidates (do this AFTER steps 3-4 so you have full context)
python scripts/analyze_waf.py /path/to/project waf_candidates.md
```

---

## Workflow

> **Step order matters.** Steps 3 & 4 build the "available alternative nodes" picture that WAF bypass analysis (Step 5) depends on. Do NOT jump to WAF analysis before scanning target source code.

### 1. Route Discovery → Sink Tracing

**Core Logic: Script finds candidates, LLM confirms reachability.**

```bash
python scripts/search_deser_endpoints.py /path/to/project report.md
```

**Step 1a — Script scan**: Outputs candidate routes (HTTP/WS/MQ) + potential sinks (readObject/JSON.parse/etc.) into `report.md`.

**Step 1b — LLM secondary judgment** (required, do not skip):

For each route × sink pair in the report:
1. **Read the controller/handler source** — confirm the method is reachable (not dead code, not test-only)
2. **Trace parameter flow** — follow user-controlled input from entry point to sink:
   - Direct: `readObject(request.getInputStream())`
   - Indirect: `readObject(decode(request.getParameter("data")))`
   - Multi-hop: through service/util layers
3. **Confirm or discard**:
   - ✅ Reachable → record in Attack Surface table
   - ❌ Dead code / internal-only → discard
   - ⚠️ Uncertain → note for manual review

If no routes found: manually analyze `web.xml`, `struts.xml`, `application.properties`.

> See [references/endpoint_identification.md](references/endpoint_identification.md) for data flow patterns and false positive list.

### 2. Dependency Analysis

For Maven / Gradle / Fat JARs / decompiled projects (including non-Maven bundled):
```bash
python scripts/parse_pom.py /path/to/project output
# Generates:
#   output_dependencies.xml         (merged, priority: META-INF/maven > pom > gradle.lockfile > build.gradle > JAR > package_dir)
#   output_dependencies.md          (table with ⚠️VERIFY flags for uncertain entries)
#   output_llm_verify_prompt.md     (auto-generated only when JAR/package_dir/gradle-var sources found)
```

**Dependency sources (priority order)**:
1. `META-INF/maven/*/pom.properties` — most accurate, from embedded Maven metadata
2. `pom.xml` — declared deps only
3. `gradle.lockfile` / `*.lockfile` — exact versions, most reliable for Gradle projects
4. `build.gradle` / `build.gradle.kts` — declared deps, version may be variable references
5. JAR filename — version reliable, groupId guessed → feed to LLM
6. Package directory scan — for libs bundled as class files (e.g., AspectJ Weaver as `aj/`)

If `output_llm_verify_prompt.md` is generated, send it to LLM to correct groupIds and fill in missing versions before proceeding to chain mining.

> See [references/dependency_analysis.md](references/dependency_analysis.md) for chain mining strategies.

### 3. Dangerous Code Scanning

**Run before WAF analysis** — identifies sink candidates AND intermediate gadget nodes in the target's own code, both of which inform new chain construction.

```bash
python scripts/scan_dangerous_code.py /path/to/project dangerous_code.md
```

**Step 3a — Script scan**: Outputs `dangerous_code.md` with all pattern-matched dangerous call sites.

**Step 3b — LLM secondary judgment** (required):

For each entry in `dangerous_code.md`:
1. **Read the surrounding method** — is the dangerous call reachable from user input or a magic method?
2. **Assess controllability** — are the arguments (cmd/path/class name) partially or fully controlled?
3. **Classify exploitation value**:
   - ⭐⭐⭐ Direct sink reachable from entry point → highest priority
   - ⭐⭐ Reachable via magic method pivot → new chain candidate
   - ⭐ Internal/hardcoded args → low value, note and skip
4. **Record candidates** in the 危险代码 table of exploit notes

### 4. Magic Method Search (New Chain Mining)

**Run before WAF analysis** — finds custom `hashCode / compareTo / toString / equals / readObject` implementations in target source that serve as pivot points for new chains.

**No script needed — run grep commands directly** (cross-platform):

```bash
# Linux / macOS / Git Bash on Windows
SRC=/path/to/sources
grep -rn "public int hashCode()\|public String toString()\|public boolean equals(\|public int compareTo\|public int compare(" "$SRC" --include="*.java" | grep -v "/test/"
grep -rn "private void readObject\|protected Object readResolve" "$SRC" --include="*.java"
grep -rn "implements.*Serializable" "$SRC" --include="*.java" | grep -i "Comparator\|Transformer\|InvocationHandler\|Map\b" | grep -v "/test/"
```

```powershell
# Windows PowerShell (alternative)
$SRC = "C:\path\to\sources"
Get-ChildItem -Path $SRC -Recurse -Filter "*.java" | Select-String -Pattern "public int hashCode\(\)|public String toString\(\)|public boolean equals\(|public int compareTo|public int compare\(" | Where-Object { $_.Path -notmatch "test" }
Get-ChildItem -Path $SRC -Recurse -Filter "*.java" | Select-String -Pattern "private void readObject|protected Object readResolve"
```

Read each candidate file and check for `invoke`, `lookup`, `exec`, `forName` in the method body.

> See [references/waf_bypass.md](references/waf_bypass.md) § Magic Method Pivot for full command set and analysis guidance.

### 5. WAF Bypass Analysis

**Run after Steps 3 & 4** — now you have: entry points (Step 1) + available gadget libs (Step 2) + target sinks (Step 3) + magic method pivot nodes (Step 4). This is the full picture needed to plan bypass chains.

```bash
python scripts/analyze_waf.py /path/to/project waf_candidates.md
```

**Step 5a — Script scan**: Outputs `waf_candidates.md` with Java/TXT/config/XML WAF candidate files.

**Step 5b — LLM secondary judgment** (required):

1. **Read each candidate file** from `waf_candidates.md`
2. **Extract blacklist** — list every blocked class name (Java + TXT sources)
3. **Check serial filter logic** — if `ObjectInputFilter` found, read `checkInput()` implementation
4. **Cross-reference with deps** (Step 2) — map each blocked class to its gadget chain
5. **Fill Gadget Class Status table** in exploit notes: ✅ Available / ❌ Blocked / ⚠️ Partial
6. **Identify bypass opportunities** using techniques in `waf_bypass.md`

> See [references/waf_bypass.md](references/waf_bypass.md) for bypass techniques.

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
- [gadget_database_springboot_extensions.json](references/gadget_database_springboot_extensions.json) - Spring Boot 专属扩展链（任意文件写 → RCE）
- [commons_collections_chains.md](references/commons_collections_chains.md) - CC chain details
