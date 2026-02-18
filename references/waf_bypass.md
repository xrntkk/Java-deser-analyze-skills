# WAF Bypass & Gadget Analysis Guide

> Techniques for analyzing WAF restrictions and finding alternative gadget paths.

## WAF Reconnaissance

Use `analyze_waf.py` to extract blacklist patterns:

```bash
python scripts/analyze_waf.py /path/to/project waf_candidates.md
```

### Common WAF Locations

| Type | Files to Check |
|------|---------------|
| **Custom ObjectInputFilter** | `*.java` with `ObjectInputFilter` |
| **Apache Commons** | `org.apache.commons.io.serialization.*` |
| **Spring Security** | Security config classes |
| **WebLogic** | `weblogic.deser` packages |
| **Custom Blacklist** | Classes with `resolveClass` override |

## Multi-Path Analysis Strategy

**Core Principle: Don't stop at the first blocked chain!**

WAF might block popular chains (CC1) but miss obscure variants.

### Analysis Output Format

```markdown
### 🛡️ Gadget Class Status Analysis

| Gadget Class | Common Chain | Status | Breakpoint Analysis |
|--------------|--------------|--------|---------------------|
| InvokerTransformer | CC1 | ❌ | transform blocked |
| TiedMapEntry | CC6 | ✅ | Available |
| ObjectBean | ROME | ✅ | Available |

### ✅ Unblocked Key Classes

[List ALL discovered unblocked classes]

### 🧠 Research Directions

1. Variant Chain A: [Description]
2. Variant Chain B: [Description]
3. Second Deserialization: [Description]
```

## Common Bypass Techniques

### 1. Alternative Transformers

When `InvokerTransformer` is blocked:
- `InstantiateTransformer` + `TrAXFilter`
- `FactoryTransformer` with custom factory
- Project-specific `Transformer` implementations

### 2. Alternative Triggers

When `BadAttributeValueExpException` is blocked:
- `XString` (Xalan)
- `HotSwappableTargetSource` (Spring AOP)
- `UID` in `EventHandler`

### 3. Alternative Entry Points

When standard entries are blocked:
- `SignedObject` for second deserialization
- `RMIConnector` for JMX-based deserialization
- `EventHandler` for reflection-based triggers

### 4. Class Name Obfuscation

- Inner classes: `Outer$Inner` vs `Outer$1`
- Array notation: `[Ljava.lang.Object;`
- Primitive arrays: `[B`, `[I`

## Breakpoint Classification

| Status | Meaning | Next Step |
|--------|---------|-----------|
| ✅ Available | Full chain possible | Construct payload |
| ⚠️ Partial | Some components blocked | Find alternatives |
| ❌ Blocked | Core class blocked | Try different chain |
| ❓ Unknown | Need more analysis | Manual verification |

## Brainstorming Framework

When blocked, ask:

1. **What exactly is blocked?**
   - Specific class? Method? Package?

2. **What alternatives exist?**
   - Same interface, different implementation
   - Same behavior, different trigger

3. **Can we bypass the check?**
   - Case sensitivity issues
   - Array vs scalar confusion
   - Inner class naming

4. **Is there a secondary path?**
   - Second deserialization
   - Exception-based triggers
   - Finalizer-based triggers
