# Java-deser-analyze-skills

An automated research assistant for Java deserialization vulnerability mining and exploitation. It analyzes decompiled source code (including Fat JARs), extracts deserialization endpoints, identifies WAF breakpoints, infers dependencies, and mines available Gadget Chains.

## Core Capabilities

- **Endpoint Discovery**: Automatically detects deserialization sinks (ObjectInputStream, Fastjson, Jackson, XStream, SnakeYAML, Hessian, Fury, etc.) and reachable Web Routes (Spring, Struts2, Servlet).
- **Dependency Inference**: Parses `pom.xml` and scans `lib/*.jar` files (Fat JAR support) to generate accurate dependency lists.
- **Dangerous Code Scanning**: Scans for internal gadget components like RCE, JNDI, Reflection, and File I/O sinks to aid in custom chain construction.
- **WAF Breakpoint Analysis**: Extracts Blacklist/Whitelist rules and identifies exactly where a Gadget Chain is blocked.
- **Multi-Path Mining**: Discovers multiple potential exploit paths and suggests alternative "Brainstorming" directions for manual verification.
- **Exploit Notes Generation**: Produces a comprehensive `_exploit_notes.md` report with attack surface details, gadget status tables, and payload construction ideas.

## Supported Frameworks

- **Web**: Spring Boot / Spring MVC, Struts2, Servlet
- **Serialization**: Fastjson, Jackson, XStream, SnakeYAML, Hessian, Fury
- **Components**: Commons Collections, BeanUtils, ROME, Hibernate, etc.

## Quick Start

### 1. Full Analysis Workflow

Use the Claude Code CLI to invoke the skill:

```bash
# Start Claude Code
claude

# Use the skill in conversation
/java-deser-exploiter /path/to/decompiled-project
```

### 2. Independent Script Usage

You can also run individual analysis scripts:

```bash
# Step 1: Scan Routes and Sinks
python scripts/search_deser_endpoints.py /path/to/project endpoints.md

# Step 2: Parse Dependencies (Fat JAR supported)
python scripts/parse_pom.py /path/to/project deps
# Generates: deps_dependencies.md, deps_dependencies.xml

# Step 3: Scan Dangerous Code Components
python scripts/scan_dangerous_code.py /path/to/project dangerous_code.md

# Step 4: Scan WAF Candidates
python scripts/analyze_waf.py /path/to/project waf_candidates.md
```

## Output Structure

Upon completion, the tool generates a research workspace (Note: The generated `_exploit_notes.md` report is in **Chinese** by default to support the target user base):

```
{project}_exploit_research/
├── {project}_exploit_notes_{timestamp}.md    # Main Research Report (Chinese)
├── {project}_dependencies.xml                # Maven Dependency List
├── {project}_dangerous_code.md               # Dangerous Code Scan Results
└── references/                               # Gadget Chain Database
    ├── commons_collections_chains.md
    ├── fastjson_chains.md
    └── gadget_database.json
```

### Main Report Contents

- **Attack Surface**: Reachable routes and sink types.
- **Dangerous Components**: Internal RCE/JNDI/Reflection sinks for gadget construction.
- **Gadget Analysis**: Detailed table showing which chains are blocked and where (Breakpoints).
- **Unblocked Classes**: A comprehensive list of available gadget classes (e.g., `LazyMap`, `TiedMapEntry`).
- **Exploitation Details**: Multiple potential attack paths (e.g., `[PATH-1]`, `[PATH-2]`).
- **Brainstorming**: Directions for manual bypass research.

## How It Works

### Phase 1: Automated Scanning (Scripts)

1.  **Endpoint & Route Scan**: identifying `readObject`, `JSON.parse` and Web Routes (`@Controller`, etc.).
2.  **Dependency Inference**: Parsing POMs and inspecting JAR filenames.
3.  **Dangerous Code Scan**: Regex-based scanning for RCE, JNDI, Reflection patterns.
4.  **WAF Recon**: Locating potential blacklist files.

### Phase 2: Intelligent Analysis (LLM)

5.  **WAF Rule Extraction**: Reading candidate files to extract class blacklists.
6.  **Gadget Matching**: Cross-referencing dependencies with the Gadget Database and WAF rules.
7.  **Breakpoint Analysis**: Determining if/where a chain is blocked and suggesting bypasses.
8.  **Report Generation**: Synthesizing all findings into a structured Exploit Note.

## Key Features

- **Fat JAR Support**: Works directly on decompiled Spring Boot applications.
- **No False Hope**: Clearly distinguishes between "Available", "Partial", and "Blocked" chains.
- **Manual Assist**: Provides "Maven-Ready" XML and "Unblocked Class Lists" to speed up manual PoC development.

## License

This project is for educational and research purposes only.

## Disclaimer

This tool is intended for authorized security testing, defensive assessment, and educational research. Do not use for unauthorized attacks.
