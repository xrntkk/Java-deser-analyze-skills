# Report Template

> Standard format for deserialization vulnerability research reports.

## Output Language

**IMPORTANT: Reports must be in CHINESE.**

## File Structure

```
{project}_exploit_research/
├── {project}_exploit_notes_{timestamp}.md    # Core analysis notes
├── {project}_dependencies.xml                 # XML dependency list
├── {project}_dependencies.md                  # Dependency table with VERIFY flags
├── {project}_dangerous_code.md                # Dangerous code scan results
├── {project}_llm_verify_prompt.md             # (if needed) dependency verification
└── references/                                # Auxiliary materials
    └── gadget_database.json
```

## Report Template

```markdown
# {项目名称} - 反序列化漏洞挖掘笔记

**Target**: {project_path}
**Date**: {timestamp}
**Focus**: RCE / Arbitrary File Read/Write (No DNS/DoS)

## 🔍 攻击面总览 (Attack Surface)

| Entry Point (Route) | Parameter | Sink Type | Reachable? |
|:--------------------|:----------|:----------|:-----------|
| `/api/upload` | `data` (POST Body) | `ObjectInputStream` | ✅ Yes |
| `/api/config` | `json` (Param) | `JSON.parseObject` | ✅ Yes |

---

## 💣 潜在 Gadget 组件扫描 (Dangerous Code)

| Category | File:Line | Code Snippet | Context Analysis |
|:---------|:----------|:-------------|:-----------------|
| **Command Exec** | `Util.java:45` | `Runtime.exec(cmd)` | Parameter from HTTP? |
| **JNDI** | `LogService.java:12` | `ctx.lookup(uri)` | Log4j variant? |
| **File Write** | `FileUtil.java:88` | `FileOutputStream(path)` | Arbitrary overwrite? |
| **Reflection** | `BeanHelper.java:30` | `method.invoke(obj, args)` | Chain connector |

---

## 🛡️ Gadget 类状态分析 (Gadget Analysis)

| Gadget 类 | 常见链 | 状态 | 断点分析与研究方向 |
|:----------|:-------|:-----|:-------------------|
| TemplatesImpl | Multiple | ❌ 被拦截 | 寻找其他 ClassLoader |
| InvokerTransformer | CC1-7 | ❌ 被拦截 | 寻找其他 Transformer |
| TiedMapEntry | CC5-6 | ⚠️ Partial | 结合 LazyMap 触发 |
| ObjectBean | ROME | ✅ Available | 重点测试 |

### ✅ 未被拦截的关键类 (Unblocked Key Classes)

[List ALL discovered unblocked classes - no ellipsis]

*   `org.apache.commons.collections.map.LazyMap`
*   `org.apache.commons.collections.keyvalue.TiedMapEntry`
*   `com.rometools.rome.feed.impl.ObjectBean`
*   `com.sun.rowset.JdbcRowSetImpl`
*   [Continue listing ALL classes]

---

## 🔬 新链挖掘分析 (New Chain Mining)

> 本节记录从目标源码中挖掘的新反序列化链，与上节"已知链可用性"互补，**两者都必须完成**。
> 核心思路：旧链 → 触发 magic method → 目标自定义实现 → 新 Sink。

### Magic Method 触发点可用性

| Magic Method | 旧链触发节点 | WAF 状态 | 可用于延伸? |
|:-------------|:------------|:---------|:-----------|
| `hashCode()` | CC6: `TiedMapEntry.hashCode()` | ✅ 可触发 | 是 |
| `compareTo()` | CC2: `PriorityQueue → TransformingComparator` | ❌ 被拦截 | 否 |
| `toString()` | CC5: `BadAttributeValueExpException.readObject()` | ✅ 可触发 | 是 |
| `equals()` | CC7: `Hashtable.reconstitutionPut()` | ✅ 可触发 | 待确认 |

### 目标源码中发现的自定义实现

> 使用 grep 命令在源码中搜索 magic method 覆写，阅读方法体内容后填写此表。

| 类名:行号 | 实现的 Magic Method | 关键逻辑摘要 | 字段是否可控? | 利用价值 |
|:---------|:--------------------|:------------|:------------|:--------|
| `CustomCache.java:45` | `hashCode()` | 调用 `this.loader.load(key)` | ✅ loader 为 Object 类型 | ⭐⭐⭐ 高 |
| `BeanWrapper.java:88` | `toString()` | 调用 `this.bean.getXxx()` | ✅ bean 可注入 | ⭐⭐ 中 |
| `UtilComparator.java:12` | `compare()` | 仅做数值比较，无副作用 | — | ⭐ 无利用价值 |

### 新链路径设计

#### [NEW-1] {新链名称（自定义，非 ysoserial 链名）}

*   **触发入口**: `HashMap.readObject()` → `TiedMapEntry.hashCode()`
*   **目标代码节点**: `CustomCache.hashCode()` → `this.loader.load(key)`
*   **到达 Sink**: `loader.load()` → `Method.invoke(handler, ...)` → RCE
*   **完整调用路径**:
    ```
    HashMap.readObject()
      → TiedMapEntry.hashCode()
        → LazyMap.get() [wrapping CustomCache]
          → CustomCache.hashCode()
            → this.loader.load(key)       ← 目标自定义代码
              → Method.invoke(handler, ...)  ← Sink
                → ✅ RCE
    ```
*   **所需依赖**: commons-collections（入口段）+ 目标自身代码（后段，无额外依赖）
*   **已知障碍**: `[说明哪些类被 WAF 拦截，以及如何规避]`
*   **状态**: 🔬 待验证 / ⚠️ 理论可行 / ✅ 已验证

#### [NEW-2] {第二条新链}

*   **触发入口**: `[入口类.方法()]`
*   **目标代码节点**: `[目标类.方法()]`
*   **到达 Sink**: `[最终 sink]`
*   **状态**: 🔬 待验证

## 📦 依赖利用深度分析 (Dependency Analysis)

### Dependency: `[Jar Name]`
*   **Role**: Gadget Provider / Utility
*   **Key Classes**: `[Class1]`, `[Class2]`
*   **Exploit Method**: [Explain exploitation technique]
*   **Prerequisites**: [Version/Config requirements]

---

## 💣 漏洞利用详情 (Exploitation Details)

### [PATH-1] {Chain Name} via `/api/upload`
*   **入口**: `ObjectInputStream.readObject`
*   **数据流验证**: `Http Body` -> `Controller` -> `readObject` (Verified: Yes/No)
*   **核心**: `ObjectBean` -> `ToStringBean` -> `JdbcRowSetImpl`
*   **状态**: ✅ 完全可用
*   **Payload**: `ysoserial ROME "ldap://..."`

### [PATH-2] {Chain Name} via `/api/config`
*   **入口**: `JSON.parseObject`
*   **数据流验证**: [Details]
*   **核心**: [Chain details]
*   **状态**: ⚠️ 部分受阻
*   **突破口**: [Bypass strategy]

---

## 🧠 挖掘方向建议 (Brainstorming)

> 此节聚焦**新链挖掘思路**，与已知链分析互补，两者均不可省略。优先提出基于目标源码的新路径。

1.  **Magic Method 延伸**: `[类名.方法()]` 中调用了 `[危险操作]`，可作为 `[旧链触发节点]` 的后段
2.  **接口替换**: 目标实现了 `[接口名]`，可替换旧链中的 `[被拦截类]`
3.  **二次反序列化**: 使用 `SignedObject` 绕过浅层类检查
4.  **[其他方向]**: [描述]
```

## Output Requirements

1. **NO Ellipsis**: List ALL items completely
2. **NO "etc."**: Provide full enumeration
3. **Both Required**: Known chain analysis (§🛡️) AND new chain mining (§🔬) must both be completed; known chains take priority but new chain mining is mandatory
4. **Multiple Paths**: At least 3 potential paths when possible (new chains preferred over old chain variants)
5. **Chinese Language**: Main content in Chinese
6. **Actionable**: For new chains, describe the full call path; for known chains, include specific payload commands
