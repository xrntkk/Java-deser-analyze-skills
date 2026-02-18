# Dependency Analysis Guide

> Detailed guidance for analyzing dependencies and mining gadget chains in decompiled/Fat JAR projects.

## Fat JAR Structure

Typical Spring Boot Fat JAR:
```
application.jar
├── BOOT-INF/
│   ├── classes/          # Application code (decompiled)
│   └── lib/              # Dependencies as .jar files
├── META-INF/
└── org/springframework/  # Spring Boot loader
```

## Dependency Inference from JAR Files

When `pom.xml` is missing or incomplete, infer from JAR filenames:

| Filename Pattern | Inferred Dependency |
|-----------------|---------------------|
| `commons-collections-3.2.2.jar` | `commons-collections:commons-collections:3.2.2` |
| `spring-core-5.3.20.jar` | `org.springframework:spring-core:5.3.20` |
| `fastjson-1.2.83.jar` | `com.alibaba:fastjson:1.2.83` |

## Multi-Chain Mining Strategy

**Core Principle: Do NOT stop at the first chain!**

Real environments have various unknown restrictions. The goal is to find **as many potential paths as possible**.

### Chain Categories

| Category | Examples | Typical Use |
|----------|----------|-------------|
| **Transformer-based** | CC1-7, CB1-5 | Runtime.exec via reflection |
| **Template-based** | TemplatesImpl | Class loading / bytecode execution |
| **JNDI-based** | JdbcRowSetImpl | Remote class loading |
| **ToString triggers** | ROME, XString | Indirect chain entry |
| **Second Deserialize** | SignedObject | Bypass shallow checks |

### Version-Specific Analysis

For each dependency, check:

1. **Official Mitigations**: Does this version have patches?
   - Example: CC 3.2.2+ has `InvokerTransformer` restriction

2. **Known Bypasses**: Are there documented bypasses?
   - Example: CC 3.2.2 bypass via `InstantiateTransformer`

3. **JDK Compatibility**: Does the chain require specific JDK?
   - Example: Some chains break after JDK 8u20

## LLM Prompt Template for Chain Mining

```
You are a specialized Java Deserialization Vulnerability Researcher.

Context:
You will analyze dependency lists from POM declarations and JAR inferences.
Focus on practical attack vectors relevant to the given dependencies.

Dependency List:
[Insert dependencies.xml content]

Tasks:
1. Extract Core Vulnerability Surface
2. Full Gadget Chain Mining (ALL possible chains)
3. Dependency Exploitation Analysis (per chain)
4. Advanced Chain Combination Analysis
5. Noise Filtering (ignore URLDNS, DoS)
6. Structured Output (priority-ordered)

Quality Requirements:
- Verify version compatibility
- Cross-check against CVE/NVD
- Self-correct if chains are missed
- Note version ambiguities
```

## Chain Combination Techniques

### Second Deserialization
Wrap serialized data to bypass shallow class checks:
- `java.security.SignedObject`
- `javax.management.remote.rmi.RMIConnector`

### Multi-Hop Chaining
Connect multiple partial chains:
- `TiedMapEntry` -> `BadAttributeValueExpException` -> `toString` trigger
- `LazyMap` + alternative `Transformer` implementations

## Transitive Dependency Consideration

When analyzing dependencies, consider:
1. **Declared vs Actual**: Fat JARs include transitive deps
2. **Version Conflicts**: Multiple versions of same library
3. **Shaded Libraries**: Relocated packages (com.example.shaded.xxx)
