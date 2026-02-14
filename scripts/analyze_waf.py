#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF File Finder
根据 CRITICAL 3.1 要求，通过关键词搜索可能包含 WAF/Blacklist 的文件
不进行任何信息提取，只返回候选文件列表
"""

import os
from pathlib import Path
from typing import List
import argparse


class WAFFileFinder:
    """WAF 文件查找器 - 只搜索文件，不提取信息"""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def search_waf_files(self) -> List[Path]:
        """搜索可能包含 WAF 的文件"""
        print("[*] Searching for potential WAF files...")

        candidates = []

        # 1. Search in security-related directories
        security_patterns = [
            '**/security/*.java',
            '**/filter/*.java',
            '**/interceptor/*.java',
            '**/validator/*.java',
            '**/protect/*.java',
            '**/defense/*.java',
            '**/guard/*.java',
            '**/check/*.java'
        ]

        print("[*] Searching in security-related directories...")
        for pattern in security_patterns:
            files = list(self.project_path.glob(pattern))
            candidates.extend(files)

        # 2. Search for files with WAF keywords
        print("[*] Searching for files with WAF keywords...")
        waf_keywords = [
            'extends ObjectInputStream',
            'resolveClass',
            'blacklist',
            'whitelist',
            'blackList',
            'whiteList',
            'BLACK_LIST',
            'WHITE_LIST',
            'denyList',
            'allowList',
            'forbiddenClasses',
            'allowedClasses',
            'blockedClasses'
        ]

        for java_file in self.project_path.rglob('*.java'):
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    if any(keyword in content for keyword in waf_keywords):
                        if java_file not in candidates:
                            candidates.append(java_file)

            except Exception:
                continue

        # Remove duplicates and sort
        candidates = sorted(set(candidates))

        print(f"[*] Found {len(candidates)} potential WAF files")
        return candidates

    def generate_report(self, candidates: List[Path], output_file: str):
        """生成候选文件列表报告"""
        print(f"[*] Generating report: {output_file}")

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# WAF 候选文件列表\n\n")
            f.write(f"**项目路径**: {self.project_path}\n\n")
            f.write(f"**发现的候选文件数量**: {len(candidates)}\n\n")
            f.write("---\n\n")

            if not candidates:
                f.write("## ⚠️ 未发现候选文件\n\n")
                f.write("项目中没有找到可能包含 WAF 或黑名单的文件。\n\n")
                f.write("**建议**:\n")
                f.write("- 使用 tree 命令手动查看目录结构\n")
                f.write("- 根据类名猜测可能的 WAF 类位置\n")
                f.write("- 手动读取相关文件进行确认\n\n")
                return

            f.write("## 📂 候选文件列表\n\n")
            f.write("以下文件可能包含 WAF、Blacklist 或 Whitelist 机制：\n\n")

            for idx, file_path in enumerate(candidates, 1):
                rel_path = file_path.relative_to(self.project_path)
                f.write(f"{idx}. `{rel_path}`\n")

            f.write("\n---\n\n")
            f.write("## 📝 后续步骤 (Next Steps for Bypass)\n\n")
            f.write("请使用大模型详细分析以上文件，寻找 WAF 绕过机会：\n\n")
            f.write("1. **黑名单提取 (Blacklist Extraction)**\n")
            f.write("   - 提取所有被禁止的类名。\n")
            f.write("   - 检查是否有漏网之鱼（如 `commons-collections4` vs `commons-collections`）。\n\n")
            f.write("2. **逻辑漏洞分析 (Logic Analysis)**\n")
            f.write("   - 检查 `resolveClass` 方法的实现逻辑。\n")
            f.write("   - **弱点模式**: \n")
            f.write("     - 只检查类名结尾 (endsWith) -> 可尝试 `com.bad.class.GoodSuffix`\n")
            f.write("     - 正则表达式错误 -> 可尝试换行符或特殊编码\n")
            f.write("     - 包名检查不完整 -> 可尝试子包或同名包\n\n")
            f.write("3. **Gadget 可用性 (Availability)**\n")
            f.write("   - 将黑名单与 `gadget_database.json` 对比。\n")
            f.write("   - 标记出 **未被拦截** 的潜在 Gadget Chain。\n\n")
            f.write("---\n\n")
            f.write("## 📋 文件路径（用于读取）\n\n")
            f.write("```\n")
            for file_path in candidates:
                f.write(f"{file_path}\n")
            f.write("```\n\n")

        print(f"[✓] Report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='搜索可能包含 WAF/Blacklist 的 Java 文件（只搜索不提取）'
    )
    parser.add_argument('project_path', help='Java 项目路径')
    parser.add_argument('output_file', nargs='?', default='waf_candidates.md',
                        help='输出报告文件 (默认: waf_candidates.md)')

    args = parser.parse_args()

    # Validate project path
    if not os.path.exists(args.project_path):
        print(f"[!] Error: Project path does not exist: {args.project_path}")
        return 1

    # Run search
    print("=" * 80)
    print("WAF File Finder")
    print("=" * 80)
    print()

    finder = WAFFileFinder(args.project_path)
    candidates = finder.search_waf_files()

    print()
    finder.generate_report(candidates, args.output_file)

    print()
    print("=" * 80)
    print("Search Complete!")
    print("=" * 80)
    print()
    print("Next Steps:")
    print("  1. Review the candidate files in the report")
    print("  2. Use LLM to read and analyze each file")
    print("  3. Extract blacklist/whitelist class lists")
    print("  4. Perform Gadget coverage analysis (CRITICAL 3.2)")
    print()

    return 0


if __name__ == '__main__':
    exit(main())
