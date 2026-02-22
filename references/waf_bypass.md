# WAF Bypass & Gadget Analysis Guide

> Advanced techniques for analyzing WAF restrictions, discovering alternative gadget paths, and constructing custom deserialization chains.

## WAF Reconnaissance & Verification

### 1. Automated Script Extraction

Use custom scripts to extract potential blacklist patterns and filter logic from the target:

```bash
python scripts/analyze_waf.py /path/to/project waf_candidates.md

```

### 2. LLM Secondary Validation

Automated scripts (using regex or AST) often miss semantic context or complex filter logic. Always perform a secondary check:

* **Contextual Analysis:** Feed the `waf_candidates.md` and surrounding source code snippets to an LLM to identify logical flaws in the WAF implementation.
* **False Positive/Negative Reduction:** Have the LLM verify if a "blocked" class can actually be reached via an alternative classloader or if an "allowed" class is implicitly blocked by a parent class filter.

### Common WAF Locations

| Type | Files to Check |
| --- | --- |
| **Custom ObjectInputFilter** | `*.java` with `ObjectInputFilter` implementation |
| **Apache Commons** | `org.apache.commons.io.serialization.*` |
| **Spring Security** | Security configuration classes |
| **WebLogic** | `weblogic.deser` packages |
| **Fury Framework** | `disallowed.txt` (Official built-in blacklist file) |
| **Hessian Framework** | `DENY_CLASS` definitions (Official built-in blacklist) |
| **Custom Blacklist** | Classes overriding the `resolveClass` method |

## Core Philosophy: Known Chains First, New Chains Always

> **两件事都必须做，缺一不可。**

**① 已知链可用性分析（优先级更高）**：对照 WAF 黑名单 + 依赖列表，确认哪些公开链（CC/CB/ROME/Spring...）可以直接使用或稍作调整即可使用。这是最快产出可用 Payload 的路径。

**② 新链挖掘（同步进行）**：利用目标源码中特有的 Magic Method 实现，将旧链的触发节点接入目标自定义代码，构造专属链。这是应对严格黑名单时的核心突破口。

**常见错误**：仅盯着旧链修修补补（把时间浪费在已被封堵的路径上），或仅挖新链（忽略唾手可得的已知链）。

### The Right Mental Model

```
Step 1: 对照 WAF 黑名单检查已知链
  ├─ 未被拦截 → 直接使用，构造 Payload ✅
  └─ 全部被拦截 → 进入 Step 2

Step 2: 旧链触发 magic method → 在目标源码中找新路径
  旧链 (CC/CB/...) ──触发──→ hashCode() / compareTo() / toString() / equals()
                                        │
                                        ▼
                            在目标源码中搜索实现这些方法的类
                                        │
                                        ▼
                            向下追踪 → 新的危险 Sink → ✅ 目标特有新链
```

**旧链的价值**：可靠地触发某个 magic method；触发之后走哪条路，既可以是公开路径（若未被拦截），也可以是目标源码中的自定义实现。

---

## Existing Chain Reference Resources

在开始分析现存链子是否可用时，优先查阅以下资源，**不要重复记忆，直接查表**：

### gadget_database.json

`references/gadget_database.json` — 收录 236 条已知链，包含依赖版本约束、JDK 要求、标签等。

**使用时机**：
- 获得依赖清单后，对照 `gadget_chains[].dependencies` 快速筛选哪些链理论上可用
- 检查目标依赖版本是否在 `vulnerable_versions` 范围内
- 了解每条链的 `tags`（如 `TemplatesImplChain`、`SignedObjectChain`）以判断组合可能性

```bash
# 快速查：目标有 commons-collections 3.2.2，哪些链受影响？
# → 在 gadget_database.json 中搜索 "commons-collections"，看 safe_version
# → 3.2.2 在大多数链的 safe_version，但 TemplatesImpl 类链仍需具体验证
```

**关键原则**：gadget_database.json 只告诉你"理论上可用"。实际上是否被 WAF 拦截、是否真的可触发，**必须结合目标 WAF 分析结果判断**，不能直接套用。

### commons_collections_chains.md

`references/commons_collections_chains.md` — CC 全系列链详解（CC1-CC10 及变种）。

**使用时机（仅当目标存在 CC 依赖时）**：
- 依赖分析发现 `commons-collections` 或 `commons-collections4`
- 查阅各链的入口类、关键类、JDK 限制，确认哪些类在 WAF 黑名单中
- 以链的"触发 magic method 的节点"为参考，决定从哪里开始向目标源码延伸

**注意**：commons_collections_chains.md 中的链是**跳板结构参考**，最终还是要看目标源码能接上哪条新路径。

### gadget_database_springboot_extensions.json

`references/gadget_database_springboot_extensions.json` — Spring Boot 专属扩展链，收录任意文件写 → RCE 场景的利用路径。

**使用时机**：
- 目标为 Spring Boot 应用，且存在任意文件写能力（AspectJWeaver、Log4j 配置覆盖等）
- 常规 readObject 链均被 WAF 拦截，考虑文件写作为替代路径
- 查阅可写目录列表、JSP Webshell 上传路径、SpEL/Logback 注入方式

---

## Multi-Path Analysis Strategy

**Core Principle: Don't stop at the first blocked chain, and don't get tunnel vision fixing an old chain!**

Security controls often block highly publicized chains (like CC1-CC7). If a chain breaks, pivot. Use the exact breakpoint as a springboard to mine a completely new path rather than obsessing over repairing the old one.

### Analysis Output Format

```markdown
### 🛡️ Gadget Class Status Analysis

| Gadget Class | Common Chain | Status | Breakpoint Analysis |
|--------------|--------------|--------|---------------------|
| InvokerTransformer | CC1 | ❌ | `transform` method blocked |
| TiedMapEntry | CC6 | ✅ | Available |
| ObjectBean | ROME | ✅ | Available |

### ✅ Unblocked Key Classes

[List ALL discovered unblocked classes]

### 🧠 Research Directions

1. Variant Chain A: [Description]
2. Pivot Chain from Breakpoint: [Description of new path]
3. Custom Source Chain: [Description]

```

## Common Bypass Techniques

### 1. Magic Method Pivot — 从旧链触发点挖掘新链（核心方法论）

**核心思路**：旧链的价值在于它能稳定触发某个 magic method。一旦到达该触发点，立刻切换到目标源码视角，从这里开始挖新路径。

#### 常见 Magic Method 触发点对照表

| 触发 Magic Method | 典型旧链节点 | 触发条件 |
|:-----------------|:------------|:--------|
| `hashCode()` | `HashMap.put()` / `HashSet.readObject()` / `Hashtable.reconstitutionPut()` | 对象放入 Hash 结构时 |
| `compareTo()` / `compare()` | `PriorityQueue.readObject()` / `TreeBag.readObject()` | 优先队列/有序结构恢复时 |
| `toString()` | `BadAttributeValueExpException.readObject()` / `XString.equals()` | 异常信息构建 / equals 比较时 |
| `equals()` | `Hashtable.reconstitutionPut()` / `AbstractMap.equals()` | hash 冲突时的等值比较 |
| `get()` / `getValue()` | `LazyMap.get()` / `TiedMapEntry.getValue()` | Map 访问时的懒加载 |
| `readObject()` | `SignedObject` 二次反序列化 | 二次解析嵌套序列化数据 |

#### 从触发点向目标源码延伸的步骤

```
Step 1: 确认旧链能到达哪个 magic method（查 gadget_database.json / commons_collections_chains.md）

Step 2: 在目标源码中搜索所有实现该 magic method 的非标准库类
        → 重点关注业务类、框架扩展类、自定义工具类
        → 搜索关键词：implements Serializable + 重写了 hashCode/equals/compareTo/toString

Step 3: 阅读这些实现，寻找"有趣的副作用"
        → 调用了 Method.invoke / Class.forName?
        → 触发了 JNDI lookup?
        → 访问了外部资源（文件、数据库、网络）?
        → 调用了其他对象的方法（可继续延伸）?

Step 4: 若找到有趣的实现，以此为中间节点，构造"旧链前段 + 新链后段"的组合链

Step 5: 若无直接 sink，继续向下追踪调用链（Step 3 中发现的方法再次重复 Step 2-4）
```

#### 实际搜索模式（LLM 直接执行，无需脚本）

> **平台说明**：以下命令适用于 Linux / macOS / Git Bash（Windows）。
> 纯 Windows CMD/PowerShell 用户请使用 SKILL.md §4 中的 PowerShell 替代命令。
> 将 `SRC` 替换为目标源码根路径。
> 过滤规则：排除 `test/`、`Test`、`Mock` 避免噪音；只看 `.java` 文件（若无源码见末尾说明）。

**Phase 1 — 一次性全量扫描，获取候选文件列表**

```bash
SRC=/path/to/sources   # Windows Git Bash 示例: SRC="C:/path/to/sources"

# 1. hashCode 覆写 → HashMap/HashSet/Hashtable 入口链后段
grep -rn "public int hashCode()" "$SRC" --include="*.java" | grep -v "/test/"

# 2. compareTo / Comparator.compare → PriorityQueue/TreeBag 入口链后段
grep -rn "public int compareTo\|public int compare(" "$SRC" --include="*.java" | grep -v "/test/"

# 3. toString 覆写 → BadAttributeValueExpException/XString 入口链后段
grep -rn "public String toString()" "$SRC" --include="*.java" | grep -v "/test/"

# 4. equals 覆写 → Hashtable/AbstractMap.equals 入口链后段
grep -rn "public boolean equals(" "$SRC" --include="*.java" | grep -v "/test/"

# 5. 自定义 readObject / readResolve / readObjectNoData → 直接链起点
grep -rn "private void readObject\|protected Object readResolve\|private void readObjectNoData" "$SRC" --include="*.java"

# 6. 实现了已知可利用接口的类（Serializable + 有趣接口组合）
grep -rn "implements.*Serializable" "$SRC" --include="*.java" | grep -i "Comparator\|Transformer\|InvocationHandler\|Runnable\|Callable\|Map\b" | grep -v "/test/"

# 7. get()/getValue() 覆写 → LazyMap/TiedMapEntry 后段的替换节点
grep -rn "public Object get(\|public.*getValue(" "$SRC" --include="*.java" | grep -v "/test/"
```

**Phase 2 — 读取 Phase 1 中有趣的文件，逐个阅读**

对每个候选文件，阅读时关注：
- magic method 的方法体里是否调用了 `this.` 的其他字段/方法（可继续控制）
- 方法体里是否出现 `invoke`、`lookup`、`exec`、`newInstance`、`forName`、`eval`
- 字段是否为 `Object` / 接口类型（可注入任意可序列化对象）
- 是否有 `transient` 之外的字段在 `readObject` 中被直接使用

**Phase 2 辅助：快速过滤高价值候选**

```bash
# 在 Phase 1 输出的文件中，进一步过滤含反射/JNDI/执行调用的实现
# 将 Phase 1 输出的文件路径存入 candidates.txt 后运行：
grep -lnE "Method\.invoke|Class\.forName|InitialContext|lookup|Runtime\.exec|ProcessBuilder|defineClass|newInstance" \
  $(grep -rln "public int hashCode\|public String toString\|public int compareTo\|public boolean equals" \
    "$SRC" --include="*.java" | grep -v "/test/")
```

**无 .java 源码时（仅有 .class 文件）**

反编译后再搜索，或用 `javap` 快速确认方法存在：
```bash
# 列出所有覆写了 hashCode 的 .class（需要 javap）
find "$SRC" -name "*.class" | while read f; do
  javap -p "$f" 2>/dev/null | grep -q "int hashCode()" && echo "$f"
done

# 更推荐：用 IDE（IDEA/JD-GUI）批量反编译后再执行 Phase 1
```

#### 示例：从 CC6 的 hashCode 触发点挖新链

```
已知：CC6 能到达 TiedMapEntry.hashCode() → LazyMap.get() → Transformer.transform()

常规路径（可能被 WAF 拦截）：
  LazyMap.get() → InvokerTransformer.transform() → Runtime.exec()

挖新链（搜索目标源码）：
  目标有自定义类 UserSessionCache implements Map, Serializable
  → UserSessionCache.get(key) 会调用 sessionService.loadUser(key)
  → sessionService.loadUser() 内部有 Method.invoke(handler, key)
  → handler 可被控制为任意可序列化对象

新链：
  HashSet.readObject()
    → HashMap.put() → TiedMapEntry.hashCode()
      → LazyMap.get() [wrapping UserSessionCache]
        → UserSessionCache.get()
          → sessionService.loadUser()
            → Method.invoke(controlledObject, ...)
              → 任意方法调用 ✅
```

### 2. Project-Specific Gadget Hunting & Chain Pivoting

When standard public chains are truncated by the WAF or framework blacklists, pivot to the target's proprietary source code or obscure dependencies:

* **Chain Pivoting (Branching Out):** If a well-known chain is interrupted at a specific class, do not focus solely on finding a direct 1:1 replacement for that class. Instead, look at the state of the execution right before the breakpoint. What other methods can be called? What other objects are in scope? Try to branch out from that exact execution state to mine an entirely new chain to a sink.
* **Alternative Getter/Setter Chains:** If a chain relying on specific `get()` or `set()` methods is broken, search the target's source code for other classes implementing exploitable `get*()`/`set*()` methods (e.g., look for getters that inadvertently invoke reflection, execute JNDI lookups, or trigger file I/O).
* **Magic Method Replacements:** Hunt for custom implementations of `hashCode()`, `equals()`, `compareTo()`, or `readObject()` within the project itself that perform unsafe state alterations.
* **Sink Tracing:** Identify the ultimate execution sink you need (e.g., `Method.invoke`, `Runtime.exec`, `InitialContext.lookup`) and build a custom call graph backward through the application's unique codebase.

### 3. Alternative Transformers

When `InvokerTransformer` is blocked:

* `InstantiateTransformer` + `TrAXFilter`
* `FactoryTransformer` with a custom factory
* Project-specific `Transformer` implementations found via source code auditing

### 4. Alternative Triggers

When `BadAttributeValueExpException` is blocked:

* `XString` (Xalan)
* `HotSwappableTargetSource` (Spring AOP)
* `UID` in `EventHandler`

### 5. Alternative Entry Points

When standard entries (like `AnnotationInvocationHandler`) are blocked:

* `SignedObject` for secondary deserialization bypasses
* `RMIConnector` for JMX-based deserialization
* `EventHandler` for reflection-based triggers

### 6. Class Name Obfuscation & Syntax Quirks

* **Inner classes:** `Outer$Inner` vs `Outer$1`
* **Array notation:** `[Ljava.lang.Object;`
* **Primitive arrays:** `[B`, `[I`

## Breakpoint Classification

| Status | Meaning | Next Step |
| --- | --- | --- |
| ✅ **Available** | Full chain possible | Construct payload immediately. |
| ⚠️ **Partial** | Some components blocked | Pivot from the breakpoint to mine a new chain. |
| ❌ **Blocked** | Core class blocked | Try an entirely different chain or entry point. |
| ❓ **Unknown** | Need more analysis | Run LLM secondary validation and manual verification. |

## Brainstorming Framework

When a payload is blocked, systematically ask:

1. **What exactly is blocked?**
   - Is it a specific class, a method, or a whole package?

2. **Am I trying to repair an old chain or mine a new one?**
   - If you've spent more than 10 minutes trying to fix one old chain → **stop, pivot**
   - Check `gadget_database.json` for other chains with the same dependency
   - If CC dependency exists → check `commons_collections_chains.md` for alternative entry classes
   - Then ask: which magic method does each alternative chain reach? Can any of those connect to target source code?

3. **What magic method does the current chain reach?**
   - `hashCode` → search target source for interesting `hashCode()` overrides
   - `compareTo` → search target source for interesting `Comparator` / `Comparable` implementations
   - `toString` → search target source for interesting `toString()` overrides
   - `get()` / `getValue()` → search target source for `Map` implementations with side effects

4. **Can we pivot from the breakpoint into target source code?**
   - If `ClassA.methodB()` is blocked, what else can `ClassA` do?
   - More importantly: does the target's own code implement an interface that `ClassA` calls?

5. **What alternatives exist within the target's ecosystem?**
   - Same interface, different implementation in the target's codebase
   - Same behavior (e.g., a different getter method that achieves the same reflection)

6. **Can we bypass the check syntactically?**
   - Case sensitivity issues
   - Array vs. scalar type confusion
   - Inner class naming conventions

7. **Is there a secondary execution path?**
   - Second deserialization (`SignedObject`)
   - Exception-based triggers
   - Finalizer/Garbage collection-based triggers

