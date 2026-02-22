# Java-deser-analyze-skills

Java 反序列化漏洞挖掘辅助工具集，专为 Fat JAR / 反编译源码设计。采用**脚本扫描 + LLM 二次判定**双阶段模式，重点挖掘新反序列化链而非修复旧链。

## 核心能力

| 能力 | 说明 |
|------|------|
| **端点发现** | Spring/Struts2/Servlet/JAX-RS/WebSocket/MQ 消费者 + readObject/JSON/YAML/Hessian/Fury 等 Sink |
| **依赖推断** | META-INF/maven > pom.xml > gradle.lockfile > build.gradle > JAR 文件名 > 包目录扫描，支持非 Maven 捆绑库 |
| **危险代码扫描** | RCE / JNDI / Reflection / File I/O — 既是 Sink 也是新链中间节点 |
| **Magic Method 搜索** | 直接 grep 目标源码中的 hashCode/toString/compareTo/equals 自定义实现，作为新链 Pivot 点 |
| **WAF 分析** | 扫描 Java/TXT/配置/XML 四类黑名单来源，含 JDK serial filter (ObjectInputFilter) |
| **Gadget 链分析** | ①优先：已知链可用性分析（对照 WAF 黑名单确认哪些链可直接使用）；②同步：旧链触发 Magic Method → 目标自定义实现 → 新 Sink（两者都必须进行）|

## 工作流（顺序不可颠倒）

```bash
# Step 1: 扫描端点候选（脚本）→ LLM 追踪数据流确认可达性
python scripts/search_deser_endpoints.py /path/to/project endpoints.md

# Step 2: 推断依赖（脚本）→ LLM 修正 groupId / 填充 Gradle 变量版本
python scripts/parse_pom.py /path/to/project deps
# 输出: deps_dependencies.xml / deps_dependencies.md / deps_llm_verify_prompt.md

# Step 3: 扫描危险代码（脚本）→ LLM 评估参数可控性和利用价值
python scripts/scan_dangerous_code.py /path/to/project dangerous_code.md

# Step 4: Magic Method 搜索（直接 grep，无脚本）→ LLM 读方法体确认利用价值
grep -rn "public int hashCode()\|public String toString()\|public boolean equals(\|public int compareTo" /path/to/src --include="*.java"

# Step 5: WAF 分析（脚本）→ LLM 读候选文件提取黑名单、对照 Gadget DB 找绕过
python scripts/analyze_waf.py /path/to/project waf_candidates.md
```

> 详细说明见 [SKILL.md](SKILL.md)

## 输出结构

```
{project}_exploit_research/
├── {project}_exploit_notes_{timestamp}.md    # 主报告（中文）
├── {project}_dependencies.xml                # Maven 依赖列表
├── {project}_dependencies.md                 # 依赖表（含 ⚠️VERIFY 标记）
├── {project}_llm_verify_prompt.md            # LLM 验证提示（按需生成）
└── {project}_dangerous_code.md               # 危险代码扫描结果
```

## 参考文档

| 文件 | 说明 |
|------|------|
| [references/gadget_database.json](references/gadget_database.json) | 65 条 Gadget Chain 数据库 |
| [references/gadget_database_springboot_extensions.json](references/gadget_database_springboot_extensions.json) | Spring Boot 专属扩展链（任意文件写 → RCE） |
| [references/commons_collections_chains.md](references/commons_collections_chains.md) | CC 链详解 |
| [references/waf_bypass.md](references/waf_bypass.md) | WAF 绕过技术 + 新链挖掘方法 |
| [references/report_template.md](references/report_template.md) | 报告模板 |
| [references/endpoint_identification.md](references/endpoint_identification.md) | 端点识别与数据流验证 |
| [references/dependency_analysis.md](references/dependency_analysis.md) | 依赖分析与链挖掘策略 |

## 免责声明

仅用于授权安全测试、防御评估和教育研究，禁止用于未授权攻击。
