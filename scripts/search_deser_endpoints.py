#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Search for Web Routes and Deserialization Sinks in Java Projects.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Set


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

        # Basic XML scanning for web.xml or struts.xml
        for file_path in self.xml_files:
            try:
                self._scan_xml_file(file_path)
            except Exception as e:
                print(f"[!] Error reading {file_path}: {e}")

    def _scan_java_file(self, file_path: Path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        # --- Route Detection ---
        # Spring MVC
        if '@Controller' in content or '@RestController' in content:
            self._find_spring_routes(file_path, lines)
        
        # Servlet
        if '@WebServlet' in content or 'extends HttpServlet' in content:
            self._find_servlet_routes(file_path, lines)

        # Struts2 Action
        if 'extends ActionSupport' in content or 'implements Action' in content:
             self._find_struts_action(file_path, lines)

        # --- Sink Detection ---
        self._find_sinks(file_path, lines)

    def _scan_xml_file(self, file_path: Path):
        filename = file_path.name.lower()
        if filename == 'web.xml':
            # Simplified detection: just note the file exists
            self.routes.append({
                'type': 'Servlet (web.xml)',
                'file': str(file_path),
                'line': 1,
                'details': 'Found web.xml descriptor',
                'code': '<web-app>...</web-app>'
            })
        elif filename == 'struts.xml':
             self.routes.append({
                'type': 'Struts2 (struts.xml)',
                'file': str(file_path),
                'line': 1,
                'details': 'Found struts.xml descriptor',
                'code': '<struts>...</struts>'
            })

    def _find_spring_routes(self, file_path: Path, lines: List[str]):
        # Regex for mappings
        mapping_patterns = [
            (r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', 'Spring RequestMapping'),
            (r'@GetMapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', 'Spring GetMapping'),
            (r'@PostMapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', 'Spring PostMapping'),
            (r'@PatchMapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', 'Spring PatchMapping'),
            (r'@PutMapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', 'Spring PutMapping'),
            (r'@DeleteMapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', 'Spring DeleteMapping'),
        ]

        for line_num, line in enumerate(lines, 1):
            for pattern, r_type in mapping_patterns:
                match = re.search(pattern, line)
                if match:
                    self.routes.append({
                        'type': r_type,
                        'file': str(file_path),
                        'line': line_num,
                        'details': f"Path: {match.group(1)}",
                        'code': line.strip()
                    })

    def _find_servlet_routes(self, file_path: Path, lines: List[str]):
        # @WebServlet("/path")
        pattern = r'@WebServlet\s*\(\s*(?:value\s*=\s*)?"([^"]+)"'
        for line_num, line in enumerate(lines, 1):
            match = re.search(pattern, line)
            if match:
                self.routes.append({
                    'type': 'Servlet Annotation',
                    'file': str(file_path),
                    'line': line_num,
                    'details': f"Path: {match.group(1)}",
                    'code': line.strip()
                })
        
        # Check for class definition if no annotation found but extends HttpServlet
        if 'extends HttpServlet' in '\n'.join(lines) and not any(r['file'] == str(file_path) for r in self.routes):
             self.routes.append({
                    'type': 'Servlet Class',
                    'file': str(file_path),
                    'line': 1,
                    'details': 'Extends HttpServlet (Check web.xml for mapping)',
                    'code': 'extends HttpServlet'
                })

    def _find_struts_action(self, file_path: Path, lines: List[str]):
        # Just flag the file
        self.routes.append({
            'type': 'Struts2 Action',
            'file': str(file_path),
            'line': 1,
            'details': 'Extends ActionSupport',
            'code': 'extends ActionSupport'
        })

    def _find_sinks(self, file_path: Path, lines: List[str]):
        # Simple string matching for now, can be regex enhanced
        for line_num, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str or line_str.startswith('//') or line_str.startswith('*'):
                continue

            # 1. Native Java
            if 'ObjectInputStream' in line and 'readObject' in line:
                self.sinks.append(self._create_sink(file_path, line_num, 'Native Java (readObject)', line_str, 'CRITICAL'))
            
            # 2. Fastjson
            if 'JSON.parse' in line and ('parseObject' in line or 'parseArray' in line or 'parse(' in line):
                 self.sinks.append(self._create_sink(file_path, line_num, 'Fastjson', line_str, 'CRITICAL'))
            
            # 3. Jackson
            if 'ObjectMapper' in line and 'readValue' in line:
                self.sinks.append(self._create_sink(file_path, line_num, 'Jackson', line_str, 'HIGH'))
            if 'enableDefaultTyping' in line:
                 self.sinks.append(self._create_sink(file_path, line_num, 'Jackson Config', line_str, 'HIGH'))

            # 4. XStream
            if 'XStream' in line and 'fromXML' in line:
                 self.sinks.append(self._create_sink(file_path, line_num, 'XStream', line_str, 'HIGH'))

            # 5. SnakeYAML
            if 'Yaml' in line and ('load(' in line or 'loadAll(' in line):
                 self.sinks.append(self._create_sink(file_path, line_num, 'SnakeYAML', line_str, 'HIGH'))
            
            # 6. Hessian
            if 'HessianInput' in line and 'readObject' in line:
                 self.sinks.append(self._create_sink(file_path, line_num, 'Hessian', line_str, 'HIGH'))
            
            # 7. XMLDecoder
            if 'XMLDecoder' in line and 'readObject' in line:
                 self.sinks.append(self._create_sink(file_path, line_num, 'XMLDecoder', line_str, 'HIGH'))

    def _create_sink(self, file_path, line, s_type, code, risk):
        return {
            'type': s_type,
            'file': str(file_path),
            'line': line,
            'code': code,
            'risk': risk
        }

    def generate_report(self, output_file: str):
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Analysis Report\n\n")
            f.write(f"Scanned Paths: {self.project_path}\n\n")
            
            f.write(f"## 1. Detected Routes ({len(self.routes)})\n\n")
            if not self.routes:
                f.write("> No common routes detected (Spring/Struts/Servlet). Manual analysis required.\n\n")
            else:
                for r in self.routes:
                    f.write(f"- **{r['type']}**\n")
                    f.write(f"  - File: `{r['file']}:{r['line']}`\n")
                    f.write(f"  - Details: {r.get('details', '')}\n")
                    f.write(f"  - Code: `{r['code'].strip()}`\n\n")

            f.write(f"## 2. Potential Deserialization Sinks ({len(self.sinks)})\n\n")
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
