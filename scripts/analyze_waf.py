#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF File Finder
通过关键词搜索可能包含 WAF/Blacklist 的文件，不进行信息提取，只返回候选文件列表。

覆盖范围：
1. Java 代码中的 ObjectInputStream 子类 / resolveClass 实现 / 黑白名单变量
2. JDK 9+ serial filter (ObjectInputFilter / jdk.serialFilter)
3. 配置文件中的 serial filter 属性 (.properties / .yml / .yaml)
4. 文本格式黑名单文件 (.txt) — 如 Fury disallowed.txt、自定义黑名单
5. XML 配置中的框架黑名单声明
"""

import os
from pathlib import Path
from typing import List, Tuple
import argparse


class WAFFileFinder:
    """WAF 文件查找器 - 只搜索文件，不提取信息"""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    # ------------------------------------------------------------------ #
    # Java 源码扫描
    # ------------------------------------------------------------------ #
    def _search_java_files(self) -> List[Tuple[Path, str]]:
        """
        扫描 .java 文件中的 WAF 相关关键词。
        返回 (文件路径, 匹配原因) 列表。
        """
        results = []

        # 1a. 安全目录内的所有 Java 文件（rglob 确保多层嵌套不遗漏）
        security_dir_patterns = [
            '**/security/**/*.java',
            '**/filter/**/*.java',
            '**/interceptor/**/*.java',
            '**/validator/**/*.java',
            '**/protect/**/*.java',
            '**/defense/**/*.java',
            '**/guard/**/*.java',
            '**/check/**/*.java',
            '**/serial/**/*.java',
        ]
        seen = set()
        for pat in security_dir_patterns:
            for f in self.project_path.glob(pat):
                if f not in seen:
                    seen.add(f)
                    results.append((f, f'security-related directory: {f.parent.name}'))

        # 1b. 全局关键词扫描
        # 经典黑白名单关键词
        blacklist_keywords = [
            'extends ObjectInputStream',
            'resolveClass',
            'blacklist', 'whitelist',
            'blackList', 'whiteList',
            'BLACK_LIST', 'WHITE_LIST',
            'denyList', 'allowList',
            'forbiddenClasses', 'allowedClasses', 'blockedClasses',
            'DENY_CLASS', 'ALLOW_CLASS',
        ]
        # JDK 9+ serial filter 关键词
        serial_filter_keywords = [
            'ObjectInputFilter',
            'serialFilter',
            'Config.createFilter',
            'createFilter(',
            'jdk.serialFilter',
            'checkInput(',           # ObjectInputFilter.checkInput
            'ObjectInputFilter.Status',
        ]
        all_keywords = blacklist_keywords + serial_filter_keywords

        for java_file in self.project_path.rglob('*.java'):
            if java_file in seen:
                continue
            try:
                content = java_file.read_text(encoding='utf-8', errors='ignore')
                matched = [kw for kw in all_keywords if kw in content]
                if matched:
                    seen.add(java_file)
                    reason = 'keywords: ' + ', '.join(matched[:3])
                    results.append((java_file, reason))
            except Exception:
                continue

        return results

    # ------------------------------------------------------------------ #
    # 文本格式黑名单文件（.txt）
    # ------------------------------------------------------------------ #
    def _search_txt_blacklists(self) -> List[Tuple[Path, str]]:
        """
        扫描 .txt 文件，识别包含类名黑名单的文本文件。
        典型案例：Fury framework 的 fury/disallowed.txt
        """
        results = []

        # 文件名命中（高置信度）
        high_confidence_names = {
            'disallowed.txt', 'blacklist.txt', 'whitelist.txt',
            'deny.txt', 'allow.txt', 'blocked.txt',
            'forbidden.txt', 'serial-filter.txt',
        }

        for txt_file in self.project_path.rglob('*.txt'):
            fname = txt_file.name.lower()
            if fname in high_confidence_names:
                results.append((txt_file, f'blacklist filename: {txt_file.name}'))
                continue

            # 内容特征：包含 Java 完全限定类名格式（package.Class）
            try:
                content = txt_file.read_text(encoding='utf-8', errors='ignore')
                lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith('#')]
                # 判断是否有 ≥ 3 行看起来像 Java 类名（含 . 且无空格）
                class_like = [l for l in lines if '.' in l and ' ' not in l and len(l) < 200]
                if len(class_like) >= 3:
                    results.append((txt_file, f'contains {len(class_like)} class-name-like entries'))
            except Exception:
                continue

        return results

    # ------------------------------------------------------------------ #
    # 配置文件中的 serial filter 属性
    # ------------------------------------------------------------------ #
    def _search_config_serial_filter(self) -> List[Tuple[Path, str]]:
        """
        扫描 .properties / .yml / .yaml 文件中的 JDK serial filter 配置。
        典型：jdk.serialFilter=!* 或 spring security 的序列化配置。
        """
        results = []
        config_keywords = [
            'jdk.serialFilter',
            'serialFilter',
            'objectinputfilter',       # case-insensitive via lower()
            'serial.filter',
            'deserialization.filter',
        ]

        for ext in ('*.properties', '*.yml', '*.yaml'):
            for cfg_file in self.project_path.rglob(ext):
                try:
                    content = cfg_file.read_text(encoding='utf-8', errors='ignore').lower()
                    matched = [kw for kw in config_keywords if kw.lower() in content]
                    if matched:
                        results.append((cfg_file, 'serial filter config: ' + ', '.join(matched[:2])))
                except Exception:
                    continue

        return results

    # ------------------------------------------------------------------ #
    # XML 配置中的框架黑名单
    # ------------------------------------------------------------------ #
    def _search_xml_blacklists(self) -> List[Tuple[Path, str]]:
        """
        扫描 XML 文件中的序列化过滤器配置。
        典型：Spring Security 的 defaultDeserializationFilter、
              WebLogic 的序列化过滤器 XML 配置。
        """
        results = []
        xml_keywords = [
            'deserializat',        # deserialization / deserializationFilter
            'serialization-filter',
            'jdk.serialFilter',
            'ObjectInputFilter',
            'blacklist', 'whitelist', 'denylist',
        ]

        for xml_file in self.project_path.rglob('*.xml'):
            fname = xml_file.name.lower()
            # 跳过 pom.xml、build 产物
            if fname in ('pom.xml',) or 'target' in xml_file.parts:
                continue
            try:
                content = xml_file.read_text(encoding='utf-8', errors='ignore').lower()
                matched = [kw for kw in xml_keywords if kw.lower() in content]
                if matched:
                    results.append((xml_file, 'XML filter config: ' + ', '.join(matched[:2])))
            except Exception:
                continue

        return results

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    def search_waf_files(self) -> dict:
        """
        搜索所有类型的 WAF/黑名单文件。
        返回按类别分组的结果字典。
        """
        print("[*] Searching for potential WAF files...")

        print("[*] [1/4] Scanning Java source files (ObjectInputFilter / resolveClass / blacklist)...")
        java_results = self._search_java_files()

        print("[*] [2/4] Scanning .txt blacklist files...")
        txt_results = self._search_txt_blacklists()

        print("[*] [3/4] Scanning .properties/.yml for serial filter config...")
        cfg_results = self._search_config_serial_filter()

        print("[*] [4/4] Scanning XML files for filter declarations...")
        xml_results = self._search_xml_blacklists()

        total = len(java_results) + len(txt_results) + len(cfg_results) + len(xml_results)
        print(f"[*] Found {total} potential WAF files/configs across all types")

        return {
            'java':   java_results,
            'txt':    txt_results,
            'config': cfg_results,
            'xml':    xml_results,
        }

    # ------------------------------------------------------------------ #
    # 报告生成
    # ------------------------------------------------------------------ #
    def generate_report(self, grouped: dict, output_file: str):
        """生成候选文件列表报告"""
        print(f"[*] Generating report: {output_file}")

        total = sum(len(v) for v in grouped.values())

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# WAF 候选文件列表\n\n")
            f.write(f"**项目路径**: {self.project_path}\n\n")
            f.write(f"**发现的候选文件数量**: {total}\n\n")
            f.write("---\n\n")

            if total == 0:
                f.write("## ⚠️ 未发现候选文件\n\n")
                f.write("项目中没有找到可能包含 WAF 或黑名单的文件。\n\n")
                f.write("**建议**:\n")
                f.write("- 手动查看目录结构，寻找 security/filter/interceptor 目录\n")
                f.write("- 检查是否有自定义 ObjectInputStream 子类\n")
                f.write("- 搜索框架文档确认内置黑名单位置\n\n")
                return

            # ---- Java 文件 ----
            if grouped['java']:
                f.write(f"## 📄 Java WAF 文件 ({len(grouped['java'])})\n\n")
                f.write("可能包含 `resolveClass` 覆写、`ObjectInputFilter` 实现或黑白名单逻辑：\n\n")
                for idx, (fp, reason) in enumerate(grouped['java'], 1):
                    try:
                        rel = fp.relative_to(self.project_path)
                    except ValueError:
                        rel = fp
                    f.write(f"{idx}. `{rel}` — *{reason}*\n")
                f.write("\n")

            # ---- TXT 黑名单 ----
            if grouped['txt']:
                f.write(f"## 📝 文本黑名单文件 ({len(grouped['txt'])})\n\n")
                f.write("可能包含类名黑名单（如 Fury `disallowed.txt`）：\n\n")
                for idx, (fp, reason) in enumerate(grouped['txt'], 1):
                    try:
                        rel = fp.relative_to(self.project_path)
                    except ValueError:
                        rel = fp
                    f.write(f"{idx}. `{rel}` — *{reason}*\n")
                f.write("\n")

            # ---- 配置文件 ----
            if grouped['config']:
                f.write(f"## ⚙️ 配置文件 Serial Filter ({len(grouped['config'])})\n\n")
                f.write("包含 `jdk.serialFilter` 或序列化过滤器属性配置：\n\n")
                for idx, (fp, reason) in enumerate(grouped['config'], 1):
                    try:
                        rel = fp.relative_to(self.project_path)
                    except ValueError:
                        rel = fp
                    f.write(f"{idx}. `{rel}` — *{reason}*\n")
                f.write("\n")

            # ---- XML ----
            if grouped['xml']:
                f.write(f"## 🗂️ XML 过滤器配置 ({len(grouped['xml'])})\n\n")
                f.write("包含序列化过滤器 XML 配置声明：\n\n")
                for idx, (fp, reason) in enumerate(grouped['xml'], 1):
                    try:
                        rel = fp.relative_to(self.project_path)
                    except ValueError:
                        rel = fp
                    f.write(f"{idx}. `{rel}` — *{reason}*\n")
                f.write("\n")

            # ---- 后续步骤 ----
            f.write("---\n\n")
            f.write("## 📝 后续步骤 (Next Steps for Bypass)\n\n")
            f.write("请使用大模型详细分析以上文件，寻找 WAF 绕过机会：\n\n")
            f.write("1. **黑名单提取 (Blacklist Extraction)**\n")
            f.write("   - 提取所有被禁止的类名（Java 文件 + TXT 文件）。\n")
            f.write("   - 检查是否有漏网之鱼（如 `commons-collections4` vs `commons-collections`）。\n\n")
            f.write("2. **JDK Serial Filter 分析**\n")
            f.write("   - 若存在 `ObjectInputFilter` 实现，检查 `checkInput()` 的过滤逻辑。\n")
            f.write("   - 若为 `jdk.serialFilter` 属性，解析模式字符串（如 `!org.apache.**;*`）。\n")
            f.write("   - **注意**: JDK serial filter 在 `resolveClass` 之前触发，优先级更高。\n\n")
            f.write("3. **逻辑漏洞分析 (Logic Analysis)**\n")
            f.write("   - 检查 `resolveClass` / `checkInput` 的实现逻辑。\n")
            f.write("   - **弱点模式**:\n")
            f.write("     - `endsWith` 检查 → 可尝试 `com.evil.GoodSuffix`\n")
            f.write("     - 正则错误 → 换行符/特殊编码绕过\n")
            f.write("     - 包名检查不完整 → 子包或同名包\n")
            f.write("     - `startsWith` 白名单 → 寻找白名单包内的危险类\n\n")
            f.write("4. **Gadget 可用性 (Availability)**\n")
            f.write("   - 将黑名单与 `gadget_database.json` 对比。\n")
            f.write("   - 标记出 **未被拦截** 的潜在 Gadget Chain。\n\n")

            # ---- 绝对路径列表（方便 LLM read 命令）----
            f.write("---\n\n")
            f.write("## 📋 文件路径（用于读取）\n\n")
            f.write("```\n")
            for items in grouped.values():
                for fp, _ in items:
                    f.write(f"{fp}\n")
            f.write("```\n\n")

        print(f"[OK] Report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='搜索可能包含 WAF/Blacklist 的文件（Java + TXT + 配置文件）'
    )
    parser.add_argument('project_path', help='Java 项目路径')
    parser.add_argument('output_file', nargs='?', default='waf_candidates.md',
                        help='输出报告文件 (默认: waf_candidates.md)')

    args = parser.parse_args()

    if not os.path.exists(args.project_path):
        print(f"[!] Error: Project path does not exist: {args.project_path}")
        return 1

    print("=" * 60)
    print("WAF File Finder")
    print("=" * 60)

    finder = WAFFileFinder(args.project_path)
    grouped = finder.search_waf_files()

    print()
    finder.generate_report(grouped, args.output_file)

    print()
    print("Next Steps:")
    print("  1. Review the candidate files in the report")
    print("  2. Use LLM to read and analyze each file")
    print("  3. Extract blacklist/whitelist class lists")
    print("  4. Check JDK serial filter patterns if present")
    print("  5. Perform Gadget coverage analysis against gadget_database.json")

    return 0


if __name__ == '__main__':
    exit(main())
