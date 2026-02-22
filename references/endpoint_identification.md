# Endpoint Identification Guide

> This document provides detailed patterns and workflows for identifying deserialization endpoints.

## Route Identification Patterns

### Web Framework Entry Points

| Framework | Patterns |
|-----------|----------|
| **Spring MVC/Boot** | `@Controller`, `@RestController`, `@RequestMapping`, `@GetMapping`, `@PostMapping` |
| **Struts2** | `extends ActionSupport`, `struts.xml` config |
| **Servlet** | `@WebServlet`, `extends HttpServlet`, `web.xml` |
| **JAX-RS** | `@Path`, `@GET`, `@POST` |
| **Vert.x** | `Router`, `Route` handlers |

## Deserialization Sink Patterns

The script automatically scans these patterns. LLM should focus on tracing data flow.

### Native Java
- `ObjectInputStream.readObject`
- `ObjectInputStream.readUnshared`
- `XMLDecoder.readObject`

### JSON Libraries
- **Fastjson**: `JSON.parse`, `JSON.parseObject`, `parseArray`
- **Jackson**: `ObjectMapper.readValue`, `ObjectMapper.readValueAs`
- **Gson**: `gson.fromJson`

### YAML Libraries
- **SnakeYAML**: `Yaml.load`, `Yaml.loadAs`

### XML Libraries
- **XStream**: `fromXML`, `fromXMLWithProcessingInstructions`

### Binary Serialization
- **Hessian**: `HessianInput.readObject`, `Hessian2Input.readObject`
- **Fury**: `fury.deserialize`, `FuryInput.readObject`
- **Fory**: `fory.deserialize`

## Vulnerability Confirmation Standard

**CRITICAL: Mere presence of a sink is NOT enough.**

### Data Flow Verification

1. **Entry (Source)**: Identify a public-facing entry point
   - HTTP Controller, Filter, Listener
   - Message Queue consumer
   - Scheduled job with external input

2. **Flow (Taint Propagation)**: Confirm input data reaches the Sink
   - **Direct**: `readObject(request.getInputStream())`
   - **Indirect**: `readObject(decode(request.getParameter("data")))`
   - **Multi-hop**: Through service layers, utility classes

3. **Sink (Trigger)**: Deserialization function called with user-controlled data

### Dead Code Detection

If the Sink is NOT reachable from an Entry, classify as:
- **Dead Code**: Unused utility methods
- **Internal Utility**: Called only by trusted internal code
- **Test Code**: Only in test directories

These are **NOT** vulnerabilities.

## Route Discovery Workflow

```
1. Run search_deser_endpoints.py → get candidate list (report.md)
   ↓
2. LLM reads report.md — for each Route × Sink pair:
   a. Read controller/handler source file
   b. Trace user-controlled input → sink
   c. Classify: ✅ Confirmed / ❌ Dead code / ⚠️ Uncertain
   ↓
3. Fill Attack Surface table in exploit notes (confirmed entries only)
   ↓
4. If no routes found:
   - Analyze web.xml, struts.xml manually
   - Check application.properties for custom config
   - Look for framework-specific annotations
```

### LLM Judgment Checklist (Step 2 Detail)

For each route entry in the script output:

| Check | Question | Action |
|-------|----------|--------|
| **Reachability** | Is the method public and mapped? | Read controller class, confirm annotation |
| **Source** | Does a user-controlled param reach the sink? | Trace: `request.getBody()` / `request.getParam()` → sink |
| **No sanitization** | Is input deserialized without type check first? | Look for `instanceof`, `getClass()`, blacklist checks before sink |
| **Not test code** | Is the file under `src/main/`, not `src/test/`? | Check file path |
| **Not internal** | Is the sink called only from this route, not from internal schedulers? | Search call sites |

## Common False Positives

| Pattern | Why False Positive | How to Verify |
|---------|-------------------|---------------|
| `readObject` in `toString()` | Usually called on trusted data | Check caller context |
| `JSON.parse` in test files | Test data not user-controlled | Verify file location |
| Utility class with `readObject` | May only be called internally | Trace all call sites |
