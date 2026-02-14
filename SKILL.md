---
name: java-deser-exploiter
description: Java Deserialization Vulnerability Research & Exploitation Assistant. Supports **Fat JAR/Decompiled Source** analysis with automatic dependency inference. Extracts deserialization endpoints, analyzes WAF breakpoints, and **mines as many available Gadget Chains as possible**. Suitable for: Vulnerability mining research and exploit chain construction. **Output focuses on multi-path mining, breakpoint analysis, and manual construction directions**.
---

# Java Deserialization Exploit Researcher

Analyzes Java project source code (including decompiled Fat JARs) to assist in mining deserialization vulnerabilities.
**Core Tasks:**
1.  **Direction**: Identify reachable and dangerous routes.
2.  **Breakpoint Identification**: Clearly point out where Gadget Chains are blocked by WAFs.
3.  **Multi-Path Discovery**: Do not just find one chain; list all possible variants and bypass ideas.
4.  **Reproduction**: Automatically generate Maven dependency lists, supporting inference from Fat JARs.

## ⚠️ Core Goals

**This skill is a researcher's assistant, responsible for providing "Panoramic" intelligence.**

- ✅ **Fat JAR Support**: Automatically scan jars in `lib/` to infer dependencies.
- ✅ **Multi-Chain**: Mine at least 2 potential exploit paths whenever possible.
- ✅ **Clear Breakpoints**: If a chain cannot be exploited, precisely identify which class is blocked.
- ✅ **Provide Direction**: Suggest what kind of alternative classes to look for based on breakpoints.

---

## ⚠️ CRITICAL Rules Summary (Mandatory)

---

### CRITICAL 1: Deserialization Endpoint Identification Rules

**Core Logic: Find Routes first, then Vulnerabilities.**

Traditional "global search for deserialization functions" prone to high false positives (e.g., test code, unused utility classes).
**Must follow this workflow:**

1.  **Route Discovery**:
    *   Prioritize using `scripts/search_deser_endpoints.py` to scan common Web Framework routes (Spring, Struts2, Servlet).
    *   **Fallback**: If the script finds no routes (e.g., obscure frameworks or special configs), **MUST** use LLM to read project config files (e.g., `web.xml`, `struts.xml`, `application.properties`) and directory structure to manually identify entry points.

2.  **Trace to Sink**:
    *   Start from the discovered **Route Entry**, trace data flow.
    *   Determine if external input (HTTP Body, Param, Header) eventually flows into a **Deserialization Sink** (e.g., `readObject`, `JSON.parse`).
    *   **Only mark as a valid vulnerability if the route connects to the deserialization point.**

3.  **Script Usage Example:**

```bash
# Scan Routes and Deserialization Sinks
python scripts/search_deser_endpoints.py /path/to/project report.md
```

**Script Output Contains:**
*   **Detected Routes**: All Web entries (Controller, Action, Servlet).
*   **Potential Sinks**: All deserialization function calls.

**LLM Analysis Task:**
*   Read script output.
*   If routes found: **Verify** which routes call Sinks.
*   If no routes found: **Autonomously analyze** codebase to find entry points.

#### 1.1 Route Identification Patterns (Reference)

*   **Spring MVC/Boot**: `@Controller`, `@RestController`, `@RequestMapping`, `@GetMapping`, `@PostMapping`
*   **Struts2**: `extends ActionSupport`, `struts.xml` config
*   **Servlet**: `@WebServlet`, `extends HttpServlet`, `web.xml`
*   **Others**: JAX-RS (`@Path`), Vert.x, etc.

#### 1.2 Deserialization Sink Identification

(Script automatically scans these patterns, LLM needs to focus on tracing)

*   **Native**: `ObjectInputStream.readObject`, `readUnshared`
*   **Fastjson**: `JSON.parse`, `JSON.parseObject`, `parseArray`
*   **Jackson**: `ObjectMapper.readValue`
*   **XStream**: `fromXML`
*   **SnakeYAML**: `Yaml.load`
*   **XMLDecoder**: `readObject`
*   **Hessian**: `HessianInput.readObject`
*   **fury**: `fury.deserialize`
*   **fory**: `fory.deserialize`

#### 1.3 Vulnerability Confirmation Standard

Must satisfy all:
1.  **Entry**: Exists accessible Web Route.
2.  **Sink**: Exists deserialization call.
3.  **Flow**: Data flows from Entry to Sink without effective filtering.

---

### CRITICAL 2: Dependency Analysis & Chain Mining (Decompiled & Fat JAR Support)

**Scenario:**
User provided code is usually **Decompiled Fat JAR** (e.g., Spring Boot App).
This means:
1.  `pom.xml` might not exist or be incomplete.
2.  Dependencies usually exist as `.jar` files in `BOOT-INF/lib/` or `lib/` directories.

**Script Enhancement:**
`scripts/parse_pom.py` is updated to automatically scan `pom.xml` **AND all `.jar` files**, inferring dependency versions from filenames.

#### 2.1 Generate Dependency List

Execute script:
```bash
python scripts/parse_pom.py /path/to/project output
```
The script automatically merges POM definitions and JAR inferences, generating `output_dependencies.xml`.

#### 2.2 Multi-Chain Mining (Maximize Gadget Discovery)

**Core Instruction: Do NOT just find one chain!**
The attacker's goal is to find **as many potential paths as possible**, as real environments have various unknown restrictions.

**LLM Prompt Template:**

```
As a Java Deserialization Vulnerability Researcher, analyze the following dependency list (including POM and JAR inferences).

Dependency List:
[Insert dependencies.xml content]

Tasks:
1. **Full Mining**: List **ALL** possible Gadget Chains (e.g., CC1-7, CB1, Hibernate, Groovy, Rome, JSON, etc.).
2. **Combination**: Think about "Second Deserialization" (SignedObject) or "Multi-Hop" (TiedMapEntry -> BadAttribute -> ...) possibilities.
3. **Filter Noise**: Ignore URLDNS/DoS, focus on RCE/IO.
4. **Output**: List all findings by priority, noting if **Key Dependencies** exist for each chain.
```

### CRITICAL 3: WAF Bypass & Gadget Availability Analysis

#### 3.1 Reconnaissance (WAF Reconnaissance)

Same as above, use `analyze_waf.py`.

#### 3.2 Multi-Path Gadget Analysis

**Core Principle: Don't stop at the first chain!**
WAF might block popular chains (CC1) but miss obscure variants (CC5, CC6, CommonBeanUtils).

**Must output two parts:**

1.  **Gadget Class Status Table**: Clear breakpoints.
2.  **Unblocked Key Classes List**: **Must list ALL** discovered, unblocked potential Gadget classes (e.g., `LazyMap`, `TiedMapEntry`, `ObjectBean`, `JdbcRowSetImpl`, `BadAttributeValueExpException`, etc.), **do NOT just list a few examples, list as many as possible**.
3.  **Brainstorming**: Provide **at least 3** alternative ideas or variant chains based on breakpoints.

**Output Format Requirement (Mandatory):**

```markdown
### 🛡️ Gadget Class Status Analysis

| Gadget Class | Common Chain | Status | Breakpoint Analysis & Research Direction |
| :--- | :--- | :--- | :--- |
| InvokerTransformer | CC1 | ❌ | **Breakpoint**: transform blocked.<br>**Direction**: Find InstantiateTransformer, ChainedTransformer variants. |
| TiedMapEntry | CC6 | ✅ | **Status**: Available.<br>**Direction**: Combine with LazyMap to trigger getValue. |
| ... | ... | ... | ... |

#### 🧠 Research Directions (Brainstorming)

1.  **Variant Chain A**: Since `InvokerTransformer` is banned, try using `InstantiateTransformer` + `TrAXFilter` to construct TemplatesImpl chain.
2.  **Variant Chain B**: Since `TiedMapEntry` is available, look for `BadAttributeValueExpException` alternatives (like `XString`, `HotSwappableTargetSource`) to trigger `toString`.
3.  **Second Deserialization**: Check if `SignedObject` or `RMIConnector` exists, try wrapping serialized data to bypass shallow class checks.
```

---

### CRITICAL 4: Dangerous Component Scanning (Dangerous Code Scanning)

**Purpose:**
Besides known chains, must scan the project for dangerous code snippets that could be used to build **New Gadget Chains**.

**Script Usage:**
```bash
python scripts/scan_dangerous_code.py /path/to/project dangerous_code.md
```

**Key Patterns to Focus On:**
1.  **Arbitrary Method Call**: `Method.invoke`, `Class.forName` (Gadget connection)
2.  **Getter Call**: `PropertyUtils.getProperty`, `BeanUtils` (Trigger getter chain)
3.  **JNDI Injection**: `InitialContext.lookup` (Direct RCE Sink)
4.  **Command Execution**: `Runtime.exec`, `ProcessBuilder`, `ScriptEngine.eval` (RCE Sink)
5.  **File Write**: `FileOutputStream`, `Files.write` (File upload/overwrite)
6.  **Dynamic Class Loading**: `ClassLoader.defineClass`, `Unsafe.defineClass` (MemShell/Malicious Class Load)

**LLM Analysis Task:**
*   **Analyze Context**: Are these dangerous codes reachable via `readObject` or other entry points?
*   **Find Connection**: Can these dangerous methods' parameters be controlled via deserialization?

---

### CRITICAL 5: Forbidden Output Formats

| Forbidden Pattern | Bad Example | Correct Practice |
|:---------|:---------|:---------|
| Using "etc." | `spring-core, fastjson etc.` | List ALL dependencies |
| Using "..." | `dep1, dep2, ...` | List ALL dependencies |
| Using "Others" | `and 30 other deps` | List ALL 30 dependencies |
| Omitting Details | `CC1-7 available` | Analyze each chain in detail |

---

### CRITICAL 6: Exploit Notes (Report Format - Chinese Output)

**IMPORTANT: The content of the report must be in CHINESE.**

#### 6.1 File Structure

```
{project}_exploit_research/
├── {project}_exploit_notes_{timestamp}.md        # 📄 核心挖掘笔记 (All-in-one)
├── {project}_dependencies.xml                    # 📄 XML 依赖清单
├── {project}_dangerous_code.md                   # 📄 危险代码扫描结果
└── references/                                   # 📂 辅助资料
    └── gadget_database.json
```

#### 6.2 Note Structure (Chinese Template)

```markdown
# {项目名称} - 反序列化漏洞挖掘笔记

**Target**: {project_path}
**Date**: {timestamp}
**Focus**: RCE / Arbitrary File Read/Write (No DNS/DoS)

## 🔍 攻击面总览 (Attack Surface)

| Entry Point (Route) | Parameter | Sink Type | Reachable? |
| :--- | :--- | :--- | :--- |
| `/api/upload` | `data` (POST Body) | `ObjectInputStream` | ✅ Yes |

---

## 💣 潜在 Gadget 组件扫描 (Dangerous Code)

**(来自 scan_dangerous_code.py 的扫描结果)**

| Category | File:Line | Code Snippet | Context Analysis |
| :--- | :--- | :--- | :--- |
| **Command Exec** | `Util.java:45` | `Runtime.exec(cmd)` | **可利用性**: 参数 cmd 来自 HTTP 请求？需人工确认。 |
| **JNDI** | `LogService.java:12` | `ctx.lookup(uri)` | **可利用性**: 潜在 Log4j 变种？ |
| **File Write** | `FileUtil.java:88` | `new FileOutputStream(path)` | **可利用性**: 任意文件覆盖？ |
| **Reflection** | `BeanHelper.java:30` | `method.invoke(obj, args)` | **关键**: 可用于连接利用链。 |

---

## 🛡️ Gadget 类状态分析 (Gadget Analysis)

**(此部分必须包含详细的类状态表，重点指出利用链的断点)**

| Gadget 类 | 常见链 | 状态 | 断点分析与研究方向 |
| :--- | :--- | :--- | :--- |
| TemplatesImpl | Multiple | ❌ 被拦截 | **断点**: 核心类被禁。<br>**方向**: 寻找其他 ClassLoader。 |
| InvokerTransformer | CC1-7 | ❌ 被拦截 | **断点**: `transform()` 方法不可用。<br>**方向**: 寻找项目中其他实现了 `Transformer` 的类。 |
| TiedMapEntry | CC5-6 | ⚠️ Partial | **断点**: 自身可用，但依赖的 Transformer 被禁。<br>**方向**: 尝试结合 `LazyMap` 触发。 |
| ObjectBean | ROME | ✅ Available | **状态**: 完整可用。<br>**方向**: 重点测试。 |
| JdbcRowSetImpl | JNDI | ✅ Available | **状态**: 完整可用。<br>**方向**: 构造 JNDI 注入。 |

#### ✅ 未被拦截的关键类 (Unblocked Key Classes)

**(注意：请尽最大努力列出所有发现的、未被拦截的潜在 Gadget 类，不要只列出几个例子，不要使用省略号)**

*   `org.apache.commons.collections.map.LazyMap` (Transformer chain helper)
*   `org.apache.commons.collections.keyvalue.TiedMapEntry` (HashCode trigger)
*   `com.rometools.rome.feed.impl.ObjectBean` (ToString/Equals trigger)
*   `com.sun.rowset.JdbcRowSetImpl` (JNDI trigger)
*   `org.springframework.aop.target.HotSwappableTargetSource` (ToString trigger)
*   `org.apache.xbean.naming.context.ContextUtil$ReadOnlyBinding` (JNDI trigger)
*   `javax.management.BadAttributeValueExpException` (ToString trigger)
*   `...` (List ALL found classes)

---

## 💣 漏洞利用详情 (Exploitation Details - Multiple Paths)

**(尽可能列出不少于 3 条潜在路径)**

### [PATH-1] ROME Chain via `/api/upload`
*   **入口**: `ObjectInputStream.readObject`
*   **核心**: `ObjectBean` -> `ToStringBean` -> `JdbcRowSetImpl`
*   **状态**: ✅ 完全可用。
*   **Payload**: `ysoserial ROME "ldap://..."`

### [PATH-2] CC6 Variant via `TiedMapEntry`
*   **入口**: `ObjectInputStream.readObject`
*   **核心**: `TiedMapEntry` -> `LazyMap` -> `Factory`
*   **状态**: ⚠️ 部分受阻 (InvokerTransformer 被禁)。
*   **突破口**: 需寻找替代 `InvokerTransformer` 的类（如 `InstantiateTransformer`）。

---

## 🧠 挖掘方向建议 (Brainstorming)

**(针对受阻路径的替代方案)**

1.  **替代 Transformer**: 既然 `Invoker` 被禁，项目中是否存在 `org.apache.commons.collections.functors.InstantiateTransformer`？
2.  **二次反序列化**: 尝试使用 `java.security.SignedObject` 包装恶意对象，绕过浅层类名检查。
3.  **异常触发**: 如果 `BadAttributeValueExpException` 被禁，尝试利用 `javax.management.BadStringOperationException` (JDK < 8u20) 或 `org.springframework.aop.target.HotSwappableTargetSource`.
```

## References Directory Structure

**Reserved `references/` for Gadget Chain details:**

```
references/
├── commons_collections_chains.md    # CC Series details
└── gadget_database.json             # Machine readable Gadget DB
```

**gadget_database.json format:**
```json
"gadget_chains": [
    {
      "id": "CHAIN-0001",
      "name": "CommonsCollectionsK1",
      "aliases": [
        "CCK1"
      ],
      "description": "CC3.2.1 InvokerTransformer Chain",
      "dependencies": [
        {
          "group_id": "commons-collections",
          "artifact_id": "commons-collections",
          "version": "3.2.1",
          ...
        }
      ],
      "tags": [
        "JavaNativeDeserialize",
        "TemplatesImplChain",
        "SignedObjectChain",
        "SpecialPublicMethod"
      ],
      "jdk_version": "any"
    }
]
```

---

## Exploit Workflow

### 1. Reconnaissance
*   **Target ID**: Identify framework (Spring, Struts2, etc.).
*   **Endpoint Scan**: Use `scripts/search_deser_endpoints.py` to find entries.
*   **Dependency Extraction**: Use `scripts/parse_pom.py` to get `dependencies.xml` (supports Fat JARs).

### 2. Attack Surface Analysis
*   **Route Verification**: Confirm which Sinks are reachable via HTTP.
*   **Dangerous Code Scan**: Use `scripts/scan_dangerous_code.py` to find potential Gadget components (RCE/JNDI/FileIO).
*   **WAF Recon**: Use `scripts/analyze_waf.py` to extract Blacklists.

### 3. Weaponization
*   **Gadget Matching**: Match `dependencies.xml` vs WAF Blacklist.
*   **Chain Construction**: Combine **Dangerous Code** (e.g., `Method.invoke`) and **Library Gadgets**.
*   **Payload Gen**: Design payload generation commands (e.g., ysoserial).
*   **Bypass Test**: Design obfuscation or alternative classes if WAF exists.

### 4. Reporting
*   **MUST Generate** `_exploit_notes.md`.
*   **MUST Include** ALL discovered Gadget Chains (even partial ones).
*   **MUST Include** Brainstorming section for manual directions.

---

## Tool Usage

### Independent Execution

```bash
# Step 1: Scan Routes & Sinks
python scripts/search_deser_endpoints.py /path/to/project endpoints.md

# Step 2: Parse Dependencies
python scripts/parse_pom.py /path/to/project deps
# Generates: deps_dependencies.md, deps_dependencies.xml

# Step 3: Scan Dangerous Code
python scripts/scan_dangerous_code.py /path/to/project dangerous_code.md

# Step 4: Scan WAF Candidates
python scripts/analyze_waf.py /path/to/project waf_candidates.md
```

---

## Best Practices

1.  **Verification First**: Don't just list Sinks, confirm controller reachability.
2.  **Combination**: Try "Second Deserialization" or "Chain Combination" (e.g., SignedObject).
3.  **WAF Bypass**: Focus on `resolveClass` logic flaws, not just the list.
4.  **Full Records**: Record failed attempts in notes to avoid repetition.

---

## Limits & Boundaries

**Script Actions:**
- Search patterns in decompiled source.
- Parse POM/JARs for dependencies.
- Scan for WAF files and Dangerous Code.

**LLM Actions:**
- Read and analyze source code.
- Extract Blacklist/Whitelist.
- Match Gadget Chains.
- Analyze Breakpoints.
- Provide Exploit Directions.
