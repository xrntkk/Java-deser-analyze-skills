# Report Template

> Standard format for deserialization vulnerability research reports.

## Output Language

**IMPORTANT: Reports must be in CHINESE.**

## File Structure

```
{project}_exploit_research/
├── {project}_exploit_notes_{timestamp}.md    # Core analysis notes
├── {project}_dependencies.xml                 # XML dependency list
├── {project}_dangerous_code.md                # Dangerous code scan results
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

1.  **替代 Transformer**: 寻找 `InstantiateTransformer` 替代
2.  **二次反序列化**: 使用 `SignedObject` 绕过检查
3.  **异常触发**: 尝试 `HotSwappableTargetSource` 替代
```

## Output Requirements

1. **NO Ellipsis**: List ALL items completely
2. **NO "etc."**: Provide full enumeration
3. **Multiple Paths**: At least 3 potential paths when possible
4. **Chinese Language**: Main content in Chinese
5. **Actionable**: Include specific payload commands
