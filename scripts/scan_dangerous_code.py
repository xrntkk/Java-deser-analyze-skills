#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
危险代码与 Gadget 组件扫描脚本
功能：扫描项目中可能被用于构建利用链的危险代码片段。
规则源：整合了 sinks.json 中的常见 Sink 点与手工挖掘经验。
"""

import os
import re
from pathlib import Path
from typing import List, Dict


class DangerousCodeScanner:
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.results: List[Dict] = []
        
        # 定义危险模式 (Regex)
        # 格式: Category -> List of Regex
        self.patterns = {
            # --- RCE / Code Execution ---
            'RCE (Command Exec)': [
                r'Runtime\.getRuntime\(\)\.exec\(',
                r'new ProcessBuilder\(',
                r'ProcessImpl\.start\(',
                r'ChannelExec\.setCommand\('
            ],
            'RCE (Script/Expression)': [
                r'ScriptEngine\.eval\(',
                r'Expression\.getValue\(',          # Spring EL
                r'ElProcessor\.eval\(',             # Tomcat EL
                r'MVEL\.eval\(',
                r'Ognl\.getValue\(',
                r'MethodExpression\.invoke\(',      # JSF
                r'MethodBinding\.invoke\(',         # JSF
                r'GroovyShell\.evaluate\(',
                r'GroovyShell\.run\(',
                r'Interpreter\.eval\(',             # BeanShell
                r'Velocity\.evaluate\(',
                r'JXPathContext\.getValue\('
            ],

            # --- Injection ---
            'JNDI Injection': [
                r'InitialContext\.lookup\(',
                r'Context\.lookup\(',
                r'Registry\.lookup\(',
                r'LdapCtx\.c_lookup\(',
                r'JndiTemplate\.lookup\(',
                r'DriverManager\.getConnection\(',  # JDBC RCE via JNDI/AutoDeserialize
                r'JdbcUtils\.getConnection\(',
                r'JNDIUtil\.lookup\(',
                r'ldap://',
                r'rmi://'
            ],
            'SQL Injection (Sink)': [
                r'\.query\(',
                r'\.queryForList\(',
                r'\.queryForObject\(',
                r'\.execute\(',
                r'\.executeQuery\(',
                r'\.executeUpdate\(',
                r'\.executeLargeUpdate\(',
                r'\.prepareStatement\('
            ],
            'SSRF (Sink)': [
                r'\.openConnection\(',
                r'\.openStream\(',
                r'\.execute\(',
                r'\.url\(',
                r'HttpUrl\.parse\(',
                r'new HttpGet\(',
                r'new HttpPost\(',
                r'new GetMethod\(',
                r'\.RequestHttpBanRedirects\(',
                r'\.RequestHttp\(',
                r'Jsoup\.connect\(',
                r'\.executeMethod\(',
                r'HttpUtil\.get\('  # Hutool
            ],

            # --- Deserialization Sinks ---
            'Deserialization (Sink)': [
                r'readObject\(',
                r'readExternal\(',
                r'JSON\.parse',
                r'ObjectMapper\.readValue',
                r'Yaml\.load',
                r'YamlReader',
                r'XMLDecoder\.readObject',
                r'XStream\.fromXML',
                r'Unmarshaller\.unmarshal', # Castor
                r'HessianInput\.readObject',
                r'Hessian2Input\.readObject',
                r'BurlapInput\.readObject',
                r'Kryo\.readClassAndObject',
                r'Amf3Input\.readObject',
                r'ExternalizableHelper\.deserializeInternal'
            ],

            # --- File Operation ---
            'Arbitrary File Write': [
                r'new FileOutputStream\(',
                r'Files\.write\(',
                r'FileWriter\(',
                r'Files\.newOutputStream\(',
                r'Files\.newBufferedWriter\(',
                r'Files\.copy\(',
                r'RandomAccessFile\.write',
                r'MultipartFile\.transferTo',
                r'Part\.write'
            ],
            'Arbitrary File Read': [
                r'new FileInputStream\(',
                r'new FileReader\(',
                r'Files\.readAllBytes\(',
                r'Files\.readAllLines\(',
                r'Files\.lines\(',
                r'Files\.newBufferedReader\(',
                r'RandomAccessFile\.read',
                r'ZipInputStream'
            ],

            # --- XXE (XML External Entity) ---
            'XXE (XML Parser)': [
                r'DocumentBuilder\.parse\(',
                r'SAXBuilder\.build\(',
                r'SAXParser\.parse\(',
                r'SAXReader\.read\(',
                r'Transformer\.transform\(',
                r'Validator\.validate\(',
                r'SchemaFactory\.newSchema\(',
                r'Digester\.parse\(',
                r'XmlUtils\.document\(',
                r'DocumentHelper\.parseText\('
            ],

            # --- Reflection / Dynamic Loading ---
            'Arbitrary Method Invoke': [
                r'Method\.invoke\(',
                r'Class\.forName\(',
                r'Constructor\.newInstance\('
            ],
            'Dynamic Class Loading': [
                r'ClassLoader\.defineClass\(',
                r'Unsafe\.defineClass\(',
                r'URLClassLoader',
                r'System\.loadLibrary\('
            ],

            # --- Getter/Setter Access ---
            'Property/Getter Access': [
                r'PropertyUtils\.getProperty\(',
                r'BeanUtils\.getProperty\(',
                r'BeanWrapperImpl',
                r'Introspector\.getBeanInfo\('
            ]
        }

    def scan(self):
        print(f"[*] Scanning for dangerous code patterns in: {self.project_path}")
        java_files = list(self.project_path.rglob('*.java'))
        
        for java_file in java_files:
            try:
                self._scan_file(java_file)
            except Exception:
                pass
                
        return self.results

    def _scan_file(self, file_path: Path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str or line_str.startswith('//') or line_str.startswith('*'):
                continue
                
            for category, regex_list in self.patterns.items():
                for regex in regex_list:
                    if re.search(regex, line_str):
                        self.results.append({
                            'category': category,
                            'file': str(file_path),
                            'line': line_num,
                            'code': line_str,
                            'pattern': regex.replace('\\', '')
                        })

    def generate_report(self, output_file: str):
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Dangerous Code & Gadget Candidate Scan\n\n")
            f.write(f"Scanned Path: {self.project_path}\n\n")
            
            if not self.results:
                f.write("No dangerous patterns found.\n")
                return

            # Group by Category
            grouped = {}
            for item in self.results:
                cat = item['category']
                if cat not in grouped:
                    grouped[cat] = []
                grouped[cat].append(item)
                
            for cat, items in grouped.items():
                f.write(f"## {cat} ({len(items)})\n\n")
                for item in items:
                    f.write(f"- **{os.path.basename(item['file'])}:{item['line']}**\n")
                    f.write(f"  - Code: `{item['code']}`\n")
                f.write("\n")
                
        print(f"[*] Report saved to: {output_file}")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python scan_dangerous_code.py <project_path> [output_file]")
        sys.exit(1)
        
    project_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'dangerous_code.md'
    
    scanner = DangerousCodeScanner(project_path)
    scanner.scan()
    scanner.generate_report(output_file)
