# Java Deserialization Gadget Chain Database

## Database Description

This directory contains the complete Java deserialization Gadget Chain database with verified dependency version information.

### `gadget_database.json` (Unified Database)

**Complete merged and verified database** - Contains all deserialization exploit chains and verified dependency versions

**Database Version:** 4.0
**Last Updated:** 2026-02-14
**Total Chains:** 65
**Source:** Merged from multiple data sources with dependency version verification

**Data Structure:**
```json
{
  "version": "4.0",
  "description": "Complete Java Deserialization Gadget Chain Database - Merged and Verified",
  "last_updated": "2026-02-14",
  "total_chains": 65,
  "gadget_chains": [
    {
      "name": "CommonsCollections5",
      "aliases": ["CC5"],
      "category": "commons-collections",
      "description": "...",
      "dependencies": [
        {
          "group_id": "commons-collections",
          "artifact_id": "commons-collections",
          "version": "3.2.1",
          "vulnerable_versions": ["3.0", "3.1", "3.2", "3.2.1"],
          "safe_version": "3.2.2"
        }
      ],
      "jdk_version": "any",
      "tags": ["JavaNativeDeserialize", "CommonsCollections"],
      "entry_class": "javax.management.BadAttributeValueExpException",
      "key_classes": [...],
      "ysoserial": "CommonsCollections5",
      "recommended": true,
      "notes": "No JDK version restrictions, recommended"
    }
  ],
  "metadata": {
    "dependency_rules": 21,
    "verification_method": "rule_based + heuristic + context_inference"
  }
}
```

**Field Descriptions:**

| Field | Type | Description |
|:------|:-----|:------------|
| `name` | string | Gadget name (unique identifier) |
| `aliases` | array | Alias list (e.g., CC5, CCK1) |
| `category` | string | Category (commons-collections, fastjson, etc.) |
| `description` | string | Detailed description |
| `dependencies` | array | Dependency list (with version info) |
| `jdk_version` | string | JDK version requirement |
| `tags` | array | Tags (for classification and search) |
| `entry_class` | string | Entry class |
| `key_classes` | array | Key class list |
| `ysoserial` | string | ysoserial payload name |
| `recommended` | boolean | Whether recommended |
| `notes` | string | Notes |
| `cve` | array | Related CVE numbers |

---

## Dependency Version Verification Mechanism

The database uses a three-layer verification mechanism to ensure dependency version accuracy:

### 1. Rule-based Verification
Built-in **21 dependency version rules** covering the most common libraries:

```python
{
  "commons-collections:commons-collections": {
    "vulnerable": ["3.0", "3.1", "3.2", "3.2.1"],
    "safe": "3.2.2",
    "latest_vulnerable": "3.2.1"
  },
  "com.alibaba:fastjson": {
    "vulnerable": ["< 1.2.83"],
    "safe": "1.2.83",
    "milestones": {
      "1.2.47": "Many JNDI bypasses fixed",
      "1.2.68": "Some JDBC exploits fixed"
    }
  }
}
```

### 2. Heuristic Inference
Infer versions from Gadget names and descriptions:

- `CommonsCollectionsK2` → Infer `commons-collections4:4.0`
- `CommonsBeanutils1` + "CB 1.9" → Infer version `1.9.4`
- `FastjsonH2Jdbc` + "1.2.47" → Infer `fastjson <= 1.2.47`

### 3. Context Inference
Combine JDK version, tags, and other context:

- `jdk_version: "<8u71"` → Infer older JDK required
- `tags: ["Echo"]` → Usually no specific version needed

---

## Database Coverage

### Statistics by Category

| Category | Chain Count | Description |
|:---------|:------------|:------------|
| commons-collections | 18 | CC1-CC10 and community variants (CCK series) |
| commons-beanutils | 5 | CB1-CB5 different versions |
| fastjson | 5 | Fastjson JNDI/C3P0/JDBC, etc. |
| echo | 5 | Echo chains for various middlewares |
| jdbc | 4 | H2/MySQL/PostgreSQL JDBC attacks |
| reference | 4 | JNDI Reference exploitation |
| template_impl | 2 | TemplatesImpl bytecode loading |
| c3p0 | 2 | C3P0 DataSource exploitation |
| rome | 2 | Rome deserialization chains |
| hibernate | 2 | Hibernate deserialization chains |
| jdk | 2 | JDK native chains (7u21, 8u20) |
| secondary_deser | 2 | SignedObject, MapMessage |
| spring | 1 | Spring deserialization chain |
| jackson | 1 | Jackson deserialization chain |
| groovy | 1 | Groovy deserialization chain |
| detection | 1 | URLDNS detection chain |

### Major Dependencies Covered

- Apache Commons Collections 3.x/4.x
- Commons Beanutils 1.5-1.10
- Fastjson 1.x/2.x
- Spring Framework
- Hibernate 3.x-5.x
- Rome/RomeTools
- Groovy
- Jackson Databind
- H2 Database
- PostgreSQL JDBC
- MySQL Connector
- C3P0
- Various middlewares (Tomcat, WebLogic, Jetty, Resin, TongWeb)

---

## Usage

### 1. Python Script Usage

```python
import json

# Load database
with open('references/gadget_database.json', 'r', encoding='utf-8') as f:
    db = json.load(f)

# Find specific chain
def find_chain(chain_name):
    for chain in db['gadget_chains']:
        if chain['name'] == chain_name or chain_name in chain.get('aliases', []):
            return chain
    return None

# Example: Find CC5
cc5 = find_chain('CC5')
if cc5:
    print(f"Name: {cc5['name']}")
    print(f"Dependencies: {cc5['dependencies']}")
    print(f"Recommended: {cc5.get('recommended', False)}")

# Find by category
def find_by_category(category):
    return [c for c in db['gadget_chains'] if c.get('category') == category]

# Example: Find all Commons Collections chains
cc_chains = find_by_category('commons-collections')
print(f"Commons Collections chains: {len(cc_chains)}")

# Find recommended chains
recommended = [c for c in db['gadget_chains'] if c.get('recommended')]
print(f"Recommended chains: {[c['name'] for c in recommended]}")
```

### 2. Usage in POM Analysis

`parse_pom.py` will automatically:
1. Look up known dependency vulnerabilities from the database
2. Match dependency versions with `vulnerable_versions`
3. Provide `safe_version` recommendations

### 3. Usage in WAF Analysis

`analyze_waf.py` will:
1. Extract all `key_classes` from the database
2. Compare with WAF blacklist
3. Generate coverage report

---

## Extending the Database

To add new Gadget Chains:

### 1. Add to `gadget_chains` array

```json
{
  "name": "NewGadget",
  "aliases": ["NG"],
  "category": "new-category",
  "description": "New Gadget Chain",
  "dependencies": [
    {
      "group_id": "com.example",
      "artifact_id": "library",
      "version": "1.0.0",
      "vulnerable_versions": ["1.0.0"],
      "safe_version": "1.0.1"
    }
  ],
  "jdk_version": "any",
  "tags": ["JavaNativeDeserialize"],
  "entry_class": "com.example.EntryPoint",
  "key_classes": ["com.example.KeyClass1", "com.example.KeyClass2"],
  "notes": "Notes"
}
```

### 2. Update Dependency Version Rules

Add new rules in `merge_databases.py`'s `DEPENDENCY_VERSION_RULES`:

```python
"com.example:library": {
    "vulnerable": ["< 1.0.1"],
    "safe": "1.0.1",
    "notes": "Description"
}
```

### 3. Regenerate Database

```bash
python scripts/merge_databases.py
```

---

## Maintenance Scripts

### `merge_databases.py`
Merge multiple databases and verify dependency versions

**Features:**
- Merge JSON databases
- Verify dependency versions
- Infer missing version information
- Generate statistical summaries

**Usage:**
```bash
cd scripts
python merge_databases.py
```

### `parse_pom.py`
Parse POM files and analyze dependencies

**Features:**
- Recursively parse all pom.xml files
- Generate dependency list (Markdown + XML format)
- Match known vulnerable dependencies

### `analyze_waf.py`
Analyze WAF blacklist/whitelist rules

**Features:**
- Extract key classes from gadget database
- Compare with WAF rules
- Generate coverage report

### `search_deser_endpoints.py`
Search for deserialization endpoints in Java projects

**Features:**
- Scan Java files for ObjectInputStream usage
- Detect Fastjson/Jackson deserialization
- Identify high-risk deserialization points

---

## Additional Reference Documents

### `commons_collections_chains.md`
**Commons Collections Detailed Documentation** - Contains complete analysis of 20+ CC chains

**Contents:**
- 7 entry class groups
- Complete exploit chains
- WAF bypass techniques
- Defense recommendations

### `DATABASE_REPORT.md`
**Database Statistics Summary** - Auto-generated database overview

**Contents:**
- Statistics by category
- Dependency coverage
- Version information

---

## Version History

### v4.0 (2026-02-14) - Current Version
- ✅ Merged multiple data sources
- ✅ Implemented dependency version verification mechanism
- ✅ Added 21 dependency version rules
- ✅ Inferred and supplemented missing version information
- ✅ Unified database structure
- ✅ 65 Gadget Chains (including CC, CB, Fastjson, JDBC, Echo, Hibernate, Spring, Rome, Groovy, JDK, etc.)
- ✅ 73% dependencies contain inference metadata
- ✅ 37% dependencies contain vulnerability version information

### v3.0 (2026-02-14)
- Added 500+ raw Gadget data
- Extended categories

### v2.0 (2026-02-14)
- CC1-CC10 detailed analysis
- Community variants

### v1.0 (Initial Version)
- Basic CC chains

---

## Data Quality Assurance

### Verification Methods

1. **Rule Verification:** 21 known dependency version rules
2. **Heuristic Verification:** Infer versions from names and descriptions
3. **Context Verification:** Combine JDK, tags, and other information

### Confidence Levels

Dependency version information in the database includes `_inference` metadata:

```json
{
  "group_id": "...",
  "artifact_id": "...",
  "version": "1.0.0",
  "_inference": {
    "confidence": "high",  // high/medium/low
    "method": "rule_based"  // rule_based/heuristic/context_inference
  }
}
```

**Confidence Descriptions:**
- **high:** Based on rule database or explicit documentation
- **medium:** Heuristic inference with some evidence
- **low:** Context inference, for reference only

---

## Contributions

Welcome contributions of new Gadget Chains or improvements to existing data:

1. Add dependency rules in `merge_databases.py`
2. Submit Pull Request
3. Explain data source and verification method

---

## References

- [ysoserial](https://github.com/frohoff/ysoserial) - Java deserialization tool
- [java-chains](https://github.com/vulhub/java-chains) - Gadget database
- [Java Deserialization Vulnerability Principles](https://paper.seebug.org/312/)

---

**Maintainer:** Java-deser-analyze-skills
**Last Updated:** 2026-02-14
**Database Version:** 4.0
**Total Chains:** 65
**Dependency Rules:** 21
