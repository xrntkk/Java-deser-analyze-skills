#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Search for Web Routes and Deserialization Sinks in Java Projects.

覆盖的端点类型：
- Spring MVC (@Controller / @RestController)
- JAX-RS (@Path)
- Servlet (@WebServlet / extends HttpServlet)
- WebSocket (@ServerEndpoint / @OnMessage)
- Message Queue consumers (Kafka @KafkaListener / RabbitMQ @RabbitListener /
  JMS @JmsListener / ActiveMQ MessageListener)
- Struts2 Action
- Filter / Listener (implements Filter / ServletContextListener)
- web.xml / struts.xml / Spring XML config
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict


class JavaAnalyzer:
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.java_files = list(self.project_path.rglob('*.java'))
        self.xml_files = list(self.project_path.rglob('*.xml'))
        self.routes: List[Dict] = []
        self.sinks: List[Dict] = []

    def analyze(self):
        print(f"[*] Scanning {len(self.java_files)} Java files and {len(self.xml_files)} XML files...")

        for file_path in self.java_files:
            try:
                self._scan_java_file(file_path)
            except Exception as e:
                print(f"[!] Error reading {file_path}: {e}")

        for file_path in self.xml_files:
            try:
                self._scan_xml_file(file_path)
            except Exception as e:
                print(f"[!] Error reading {file_path}: {e}")

    # ------------------------------------------------------------------ #
    # Per-file dispatch
    # ------------------------------------------------------------------ #
    def _scan_java_file(self, file_path: Path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        lines = content.split('\n')

        # --- Route Detection ---
        if '@Controller' in content or '@RestController' in content:
            self._find_spring_routes(file_path, lines)

        if '@Path' in content and ('javax.ws.rs' in content or 'jakarta.ws.rs' in content):
            self._find_jaxrs_routes(file_path, lines)

        if '@WebServlet' in content or 'extends HttpServlet' in content:
            self._find_servlet_routes(file_path, lines)

        if ('@ServerEndpoint' in content or '@OnMessage' in content
                or ('extends Endpoint' in content
                    and ('import javax.websocket' in content
                         or 'import jakarta.websocket' in content))):
            self._find_websocket_endpoints(file_path, lines)

        if ('extends ActionSupport' in content or 'implements Action' in content):
            self._find_struts_action(file_path, lines)

        if ('implements javax.servlet.Filter' in content
                or 'implements jakarta.servlet.Filter' in content
                or ('implements Filter' in content
                    and ('import javax.servlet.Filter' in content
                         or 'import jakarta.servlet.Filter' in content))):
            self._find_filter(file_path, lines)

        if ('implements ServletContextListener' in content
                or 'implements HttpSessionListener' in content
                or 'implements ServletRequestListener' in content):
            self._find_listener(file_path, lines)

        if ('@KafkaListener' in content or '@RabbitListener' in content
                or '@JmsListener' in content or 'implements MessageListener' in content
                or 'onMessage(' in content):
            self._find_mq_consumers(file_path, lines, content)

        # --- Sink Detection ---
        self._find_sinks(file_path, lines)

    def _scan_xml_file(self, file_path: Path):
        filename = file_path.name.lower()
        if filename == 'web.xml':
            self.routes.append({
                'type': 'Servlet (web.xml)',
                'file': str(file_path),
                'line': 1,
                'details': 'Found web.xml — manual review needed for servlet mappings',
                'code': '<web-app>...</web-app>'
            })
        elif filename == 'struts.xml':
            self.routes.append({
                'type': 'Struts2 (struts.xml)',
                'file': str(file_path),
                'line': 1,
                'details': 'Found struts.xml — manual review needed for action mappings',
                'code': '<struts>...</struts>'
            })
        elif filename in ('applicationcontext.xml', 'spring-mvc.xml', 'dispatcher-servlet.xml'):
            self.routes.append({
                'type': 'Spring XML Config',
                'file': str(file_path),
                'line': 1,
                'details': 'Found Spring XML config — check for bean/mvc mappings',
                'code': f'<beans> ({filename})'
            })

    # ------------------------------------------------------------------ #
    # Route finders
    # ------------------------------------------------------------------ #
    def _find_spring_routes(self, file_path: Path, lines: List[str]):
        mapping_patterns = [
            (r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']', 'Spring RequestMapping'),
            (r'@GetMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',     'Spring GetMapping'),
            (r'@PostMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',    'Spring PostMapping'),
            (r'@PatchMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',   'Spring PatchMapping'),
            (r'@PutMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',     'Spring PutMapping'),
            (r'@DeleteMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',  'Spring DeleteMapping'),
        ]
        for line_num, line in enumerate(lines, 1):
            for pattern, r_type in mapping_patterns:
                m = re.search(pattern, line)
                if m:
                    self.routes.append({
                        'type': r_type,
                        'file': str(file_path),
                        'line': line_num,
                        'details': f"Path: {m.group(1)}",
                        'code': line.strip()
                    })

    def _find_jaxrs_routes(self, file_path: Path, lines: List[str]):
        """JAX-RS: @Path at class or method level, combined with @GET/@POST etc."""
        http_methods = {'@GET', '@POST', '@PUT', '@DELETE', '@PATCH', '@HEAD', '@OPTIONS'}
        path_pattern = re.compile(r'@Path\s*\(\s*["\']([^"\']+)["\']')

        # Collect class-level @Path
        class_path = ''
        for line in lines:
            m = path_pattern.search(line)
            if m and not any(hm in line for hm in http_methods):
                class_path = m.group(1)
                break

        for line_num, line in enumerate(lines, 1):
            # Method-level @Path — record when combined with HTTP method annotation nearby
            pm = path_pattern.search(line)
            if pm:
                method_path = pm.group(1)
                full_path = class_path.rstrip('/') + '/' + method_path.lstrip('/') if class_path else method_path
                self.routes.append({
                    'type': 'JAX-RS @Path',
                    'file': str(file_path),
                    'line': line_num,
                    'details': f"Path: {full_path}",
                    'code': line.strip()
                })

        # If only class @Path exists (no method paths detected), still report the class
        if class_path and not any(
            r['file'] == str(file_path) and r['type'] == 'JAX-RS @Path'
            for r in self.routes
        ):
            self.routes.append({
                'type': 'JAX-RS @Path (class)',
                'file': str(file_path),
                'line': 1,
                'details': f"Class path: {class_path} — check methods for HTTP annotations",
                'code': f'@Path("{class_path}")'
            })

    def _find_servlet_routes(self, file_path: Path, lines: List[str]):
        pattern = re.compile(r'@WebServlet\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
        found_annotation = False
        for line_num, line in enumerate(lines, 1):
            m = pattern.search(line)
            if m:
                found_annotation = True
                self.routes.append({
                    'type': 'Servlet (@WebServlet)',
                    'file': str(file_path),
                    'line': line_num,
                    'details': f"Path: {m.group(1)}",
                    'code': line.strip()
                })

        if not found_annotation and 'extends HttpServlet' in '\n'.join(lines):
            self.routes.append({
                'type': 'Servlet (HttpServlet)',
                'file': str(file_path),
                'line': 1,
                'details': 'Extends HttpServlet — check web.xml for URL mapping',
                'code': 'extends HttpServlet'
            })

    def _find_websocket_endpoints(self, file_path: Path, lines: List[str]):
        ep_pattern = re.compile(r'@ServerEndpoint\s*\(\s*["\']([^"\']+)["\']')
        found = False
        for line_num, line in enumerate(lines, 1):
            m = ep_pattern.search(line)
            if m:
                found = True
                self.routes.append({
                    'type': 'WebSocket (@ServerEndpoint)',
                    'file': str(file_path),
                    'line': line_num,
                    'details': f"WS path: {m.group(1)}",
                    'code': line.strip()
                })

        if not found and ('@OnMessage' in '\n'.join(lines) or 'extends Endpoint' in '\n'.join(lines)):
            self.routes.append({
                'type': 'WebSocket (Endpoint)',
                'file': str(file_path),
                'line': 1,
                'details': 'WebSocket endpoint — @OnMessage or extends Endpoint detected',
                'code': '@OnMessage / extends Endpoint'
            })

    def _find_struts_action(self, file_path: Path, lines: List[str]):
        self.routes.append({
            'type': 'Struts2 Action',
            'file': str(file_path),
            'line': 1,
            'details': 'Extends ActionSupport / implements Action — check struts.xml for mapping',
            'code': 'extends ActionSupport'
        })

    def _find_filter(self, file_path: Path, lines: List[str]):
        """Servlet Filter — runs on all requests, potential deserialization entry."""
        self.routes.append({
            'type': 'Servlet Filter',
            'file': str(file_path),
            'line': 1,
            'details': 'Implements Filter.doFilter() — check if it processes raw request body',
            'code': 'implements Filter'
        })

    def _find_listener(self, file_path: Path, lines: List[str]):
        """ServletContextListener etc. — runs on lifecycle events, not typical HTTP entry."""
        self.routes.append({
            'type': 'Servlet Listener',
            'file': str(file_path),
            'line': 1,
            'details': 'Lifecycle listener — low chance of user-controlled input, verify manually',
            'code': 'implements *Listener'
        })

    def _find_mq_consumers(self, file_path: Path, lines: List[str], content: str):
        """
        Message Queue consumers — high-value deserialization entry points.
        These often process serialized messages directly from queues.
        """
        mq_patterns = [
            (r'@KafkaListener\s*\(.*?topics\s*=\s*["\']([^"\']+)["\']', 'Kafka @KafkaListener'),
            (r'@KafkaListener\b', 'Kafka @KafkaListener'),
            (r'@RabbitListener\s*\(.*?queues\s*=\s*["\']([^"\']+)["\']', 'RabbitMQ @RabbitListener'),
            (r'@RabbitListener\b', 'RabbitMQ @RabbitListener'),
            (r'@JmsListener\s*\(.*?destination\s*=\s*["\']([^"\']+)["\']', 'JMS @JmsListener'),
            (r'@JmsListener\b', 'JMS @JmsListener'),
        ]
        found = False
        for line_num, line in enumerate(lines, 1):
            for pattern, mq_type in mq_patterns:
                m = re.search(pattern, line)
                if m:
                    found = True
                    topic = m.group(1) if m.lastindex and m.lastindex >= 1 else 'unknown'
                    self.routes.append({
                        'type': mq_type,
                        'file': str(file_path),
                        'line': line_num,
                        'details': f"Queue/Topic: {topic} — ⚠️ MQ consumers often process serialized data",
                        'code': line.strip()
                    })
                    break  # one match per line is enough

        # ActiveMQ / Generic JMS: implements MessageListener
        if not found and ('implements MessageListener' in content or
                          ('onMessage(' in content and 'Message' in content)):
            self.routes.append({
                'type': 'JMS MessageListener',
                'file': str(file_path),
                'line': 1,
                'details': 'Implements MessageListener.onMessage() — check message deserialization',
                'code': 'implements MessageListener / onMessage('
            })

    # ------------------------------------------------------------------ #
    # Sink detection
    # ------------------------------------------------------------------ #
    def _find_sinks(self, file_path: Path, lines: List[str]):
        for line_num, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str or line_str.startswith('//') or line_str.startswith('*'):
                continue

            # 1. Native Java
            if 'ObjectInputStream' in line and 'readObject' in line:
                self.sinks.append(self._create_sink(file_path, line_num, 'Native Java (readObject)', line_str, 'CRITICAL'))

            # 2. Fastjson
            if 'JSON.parse' in line:
                self.sinks.append(self._create_sink(file_path, line_num, 'Fastjson', line_str, 'CRITICAL'))

            # 3. Jackson
            if 'ObjectMapper' in line and 'readValue' in line:
                self.sinks.append(self._create_sink(file_path, line_num, 'Jackson', line_str, 'HIGH'))
            if 'enableDefaultTyping' in line or 'activateDefaultTyping' in line:
                self.sinks.append(self._create_sink(file_path, line_num, 'Jackson Config (DefaultTyping)', line_str, 'HIGH'))

            # 4. XStream
            if 'XStream' in line and 'fromXML' in line:
                self.sinks.append(self._create_sink(file_path, line_num, 'XStream', line_str, 'HIGH'))

            # 5. SnakeYAML
            if 'Yaml' in line and ('load(' in line or 'loadAll(' in line):
                self.sinks.append(self._create_sink(file_path, line_num, 'SnakeYAML', line_str, 'HIGH'))

            # 6. Hessian / Hessian2
            if ('HessianInput' in line or 'Hessian2Input' in line) and 'readObject' in line:
                self.sinks.append(self._create_sink(file_path, line_num, 'Hessian', line_str, 'HIGH'))

            # 7. XMLDecoder
            if 'XMLDecoder' in line and 'readObject' in line:
                self.sinks.append(self._create_sink(file_path, line_num, 'XMLDecoder', line_str, 'HIGH'))

            # 8. Fury
            if ('fury.deserialize' in line or 'fury.deserializeJavaObject' in line
                    or ('FuryInput' in line and 'readObject' in line)):
                self.sinks.append(self._create_sink(file_path, line_num, 'Fury', line_str, 'HIGH'))

            # 9. Kryo
            if 'Kryo' in line and ('readObject' in line or 'readClassAndObject' in line):
                self.sinks.append(self._create_sink(file_path, line_num, 'Kryo', line_str, 'HIGH'))

    def _create_sink(self, file_path, line, s_type, code, risk):
        return {
            'type': s_type,
            'file': str(file_path),
            'line': line,
            'code': code,
            'risk': risk
        }

    # ------------------------------------------------------------------ #
    # Report
    # ------------------------------------------------------------------ #
    def generate_report(self, output_file: str):
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# Endpoint & Sink Analysis Report\n\n")
            f.write(f"Scanned: `{self.project_path}`\n\n")

            # Group routes by type for readability
            mq_types = {'Kafka', 'RabbitMQ', 'JMS', 'MessageListener'}

            http_routes = [r for r in self.routes if not any(t in r['type'] for t in mq_types)]
            mq_routes   = [r for r in self.routes if any(t in r['type'] for t in mq_types)]

            f.write(f"## 1. HTTP / WebSocket Routes ({len(http_routes)})\n\n")
            if not http_routes:
                f.write("> No HTTP routes detected. Manual review of web.xml / struts.xml recommended.\n\n")
            else:
                for r in http_routes:
                    f.write(f"- **{r['type']}**\n")
                    f.write(f"  - File: `{r['file']}:{r['line']}`\n")
                    f.write(f"  - {r.get('details', '')}\n")
                    f.write(f"  - Code: `{r['code'].strip()}`\n\n")

            f.write(f"## 2. Message Queue Consumers ({len(mq_routes)})\n\n")
            if not mq_routes:
                f.write("> No MQ consumers detected.\n\n")
            else:
                f.write("> ⚠️ MQ consumers are high-value deserialization entry points — always verify.\n\n")
                for r in mq_routes:
                    f.write(f"- **{r['type']}**\n")
                    f.write(f"  - File: `{r['file']}:{r['line']}`\n")
                    f.write(f"  - {r.get('details', '')}\n")
                    f.write(f"  - Code: `{r['code'].strip()}`\n\n")

            f.write(f"## 3. Potential Deserialization Sinks ({len(self.sinks)})\n\n")
            if not self.sinks:
                f.write("> No deserialization sinks detected.\n\n")
            else:
                for s in self.sinks:
                    f.write(f"- **{s['type']}** (Risk: {s['risk']})\n")
                    f.write(f"  - File: `{s['file']}:{s['line']}`\n")
                    f.write(f"  - Code: `{s['code'].strip()}`\n\n")

        print(f"[*] Report saved to {output_file}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python search_deser_endpoints.py <project_path> [output_file]")
        sys.exit(1)

    project_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'analysis_report.md'

    analyzer = JavaAnalyzer(project_path)
    analyzer.analyze()
    analyzer.generate_report(output_file)
