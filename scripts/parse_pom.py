#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
依赖分析脚本 (Dependency Analyzer)
功能：
1. 解析 META-INF/maven/*/pom.properties (优先级最高，Fat JAR 嵌入的准确元数据)
2. 解析 pom.xml 生成依赖清单 (Maven)
3. 解析 gradle.lockfile / *.lockfile (Gradle 锁文件，版本精确)
4. 解析 build.gradle / build.gradle.kts (Gradle DSL，版本可能含变量)
5. 扫描 lib/ 或 BOOT-INF/lib/ 下的 .jar 文件 (针对反编译 Fat JAR)
6. 扫描包目录结构，识别非 Maven 打包的嵌入库（输出 LLM 验证提示）
7. 生成合并的 XML 依赖清单 + LLM 二次校验 Prompt
"""

import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Set

# 已知包前缀 → 库映射（处理非 Maven 打包或 shaded 库）
KNOWN_PACKAGE_MAP = {
    'aj':                        {'groupId': 'org.aspectj',             'artifactId': 'aspectjweaver',       'note': 'AspectJ shaded ASM (aj/ prefix)'},
    'mozilla':                   {'groupId': 'rhino',                   'artifactId': 'js',                  'note': 'Mozilla Rhino JavaScript engine'},
    'com/thoughtworks/xstream':  {'groupId': 'com.thoughtworks.xstream','artifactId': 'xstream',             'note': 'XStream serialization'},
    'com/sun/syndication':       {'groupId': 'rome',                    'artifactId': 'rome',                'note': 'ROME RSS/Atom library'},
    'com/rometools/rome':        {'groupId': 'com.rometools',           'artifactId': 'rome',                'note': 'ROME RSS/Atom library'},
    'javassist':                 {'groupId': 'org.javassist',           'artifactId': 'javassist',           'note': 'Javassist bytecode library'},
    'ognl':                      {'groupId': 'ognl',                    'artifactId': 'ognl',                'note': 'OGNL expression language'},
    'groovy':                    {'groupId': 'org.codehaus.groovy',     'artifactId': 'groovy',              'note': 'Groovy scripting'},
    'bsh':                       {'groupId': 'org.beanshell',           'artifactId': 'bsh',                 'note': 'BeanShell scripting'},
    'com/caucho':                {'groupId': 'com.caucho',              'artifactId': 'resin',               'note': 'Resin/Hessian'},
    'com/esotericsoftware':      {'groupId': 'com.esotericsoftware',    'artifactId': 'kryo',                'note': 'Kryo serialization'},
    'net/sf/json':               {'groupId': 'net.sf.json-lib',        'artifactId': 'json-lib',            'note': 'JSON-lib'},
    'com/fasterxml/jackson':     {'groupId': 'com.fasterxml.jackson.core', 'artifactId': 'jackson-databind', 'note': 'Jackson JSON'},
    'com/alibaba/fastjson':      {'groupId': 'com.alibaba',            'artifactId': 'fastjson',            'note': 'Fastjson'},
    'net/minidev':               {'groupId': 'net.minidev',             'artifactId': 'json-smart',          'note': 'json-smart'},
    'org/yaml/snakeyaml':        {'groupId': 'org.yaml',               'artifactId': 'snakeyaml',           'note': 'SnakeYAML'},
    'org/mvel2':                 {'groupId': 'org.mvel',               'artifactId': 'mvel2',               'note': 'MVEL expression language'},
    'clojure':                   {'groupId': 'org.clojure',            'artifactId': 'clojure',             'note': 'Clojure runtime'},
    'com/sleepycat':             {'groupId': 'com.sleepycat',          'artifactId': 'je',                  'note': 'Berkeley DB Java Edition'},
    'org/h2':                    {'groupId': 'com.h2database',         'artifactId': 'h2',                  'note': 'H2 database'},
}


def find_files(project_path: str, pattern: str) -> List[Path]:
    """递归查找文件"""
    return list(Path(project_path).rglob(pattern))


def parse_meta_inf_maven(project_path: str) -> List[Dict]:
    """
    解析 META-INF/maven/groupId/artifactId/pom.properties
    这是 Fat JAR 中最可靠的依赖来源，具有准确的 groupId/artifactId/version。
    """
    dependencies = []
    props_files = find_files(project_path, 'pom.properties')

    for props_file in props_files:
        # 只处理 META-INF/maven/ 路径下的文件
        parts = props_file.parts
        if 'META-INF' not in parts or 'maven' not in parts:
            continue

        maven_idx = list(parts).index('maven')
        # 期望结构: .../META-INF/maven/<groupId>/<artifactId>/pom.properties
        if len(parts) < maven_idx + 4:
            continue

        group_id_from_path = parts[maven_idx + 1]
        artifact_id_from_path = parts[maven_idx + 2]

        # 读取 properties 文件获取版本
        props = {}
        try:
            with open(props_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        k, _, v = line.partition('=')
                        props[k.strip()] = v.strip()
        except Exception as e:
            print(f"[!] 读取 pom.properties 失败: {props_file} - {e}")
            continue

        group_id = props.get('groupId', group_id_from_path)
        artifact_id = props.get('artifactId', artifact_id_from_path)
        version = props.get('version', 'unknown')

        dependencies.append({
            'source': 'meta_inf',
            'file': str(props_file),
            'groupId': group_id,
            'artifactId': artifact_id,
            'version': version,
            'scope': 'compile'
        })

    print(f"[*] Found {len(dependencies)} deps from META-INF/maven/pom.properties")
    return dependencies


def parse_pom(pom_file: Path) -> List[Dict]:
    """解析单个 POM 文件（跳过 META-INF/maven 下的内嵌 pom.xml，避免重复）"""
    # 跳过 META-INF/maven 路径下的内嵌 pom（已由 parse_meta_inf_maven 处理）
    if 'META-INF' in pom_file.parts and 'maven' in pom_file.parts:
        return []

    dependencies = []
    try:
        tree = ET.parse(pom_file)
        root = tree.getroot()

        ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
        if root.tag.startswith('{'):
            ns_uri = root.tag[1:root.tag.index('}')]
            ns = {'maven': ns_uri}

        for dep in root.findall('.//maven:dependency', ns):
            group = dep.find('maven:groupId', ns)
            artifact = dep.find('maven:artifactId', ns)
            version = dep.find('maven:version', ns)
            scope = dep.find('maven:scope', ns)

            if group is not None and artifact is not None:
                dependencies.append({
                    'source': 'pom',
                    'file': str(pom_file),
                    'groupId': group.text,
                    'artifactId': artifact.text,
                    'version': version.text if version is not None else 'unknown',
                    'scope': scope.text if scope is not None else 'compile'
                })
    except Exception as e:
        print(f"[!] 解析 POM 失败: {pom_file} - {e}")

    return dependencies


def parse_gradle_lockfile(lockfile: Path) -> List[Dict]:
    """
    解析 Gradle lockfile（gradle.lockfile 或 gradle/dependency-locks/*.lockfile）。
    格式: group:artifact:version=configuration1,configuration2,...
    这是 Gradle 项目中最可靠的依赖来源，版本精确。
    """
    dependencies = []
    try:
        with open(lockfile, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # 跳过注释和空行
                if not line or line.startswith('#') or line.startswith('empty='):
                    continue
                # 格式: group:artifact:version=configurations
                match = re.match(r'^([^:]+):([^:]+):([^=]+)=(.+)$', line)
                if not match:
                    continue
                group_id, artifact_id, version, configs = match.groups()
                # 跳过测试专用依赖（testCompileClasspath only）
                config_list = [c.strip() for c in configs.split(',')]
                non_test = [c for c in config_list if 'test' not in c.lower()]
                scope = 'compile' if non_test else 'test'

                dependencies.append({
                    'source': 'gradle_lock',
                    'file': str(lockfile),
                    'groupId': group_id.strip(),
                    'artifactId': artifact_id.strip(),
                    'version': version.strip(),
                    'scope': scope
                })
    except Exception as e:
        print(f"[!] 解析 Gradle lockfile 失败: {lockfile} - {e}")

    return dependencies


def parse_gradle(gradle_file: Path) -> List[Dict]:
    """
    解析 build.gradle（Groovy DSL）或 build.gradle.kts（Kotlin DSL）。
    版本可能含变量引用（如 $springVersion），此时版本标记为 'unknown'。
    优先使用 gradle.lockfile；无锁文件时才依赖此函数。
    """
    dependencies = []
    try:
        with open(gradle_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"[!] 读取 Gradle 文件失败: {gradle_file} - {e}")
        return []

    # 匹配模式1: configuration "group:artifact:version" 或 'group:artifact:version'
    # 覆盖: implementation, compile, api, runtimeOnly, compileOnly,
    #        annotationProcessor, testImplementation, classpath, provided 等
    CONFIGS = (
        r'implementation|compile|api|runtimeOnly|compileOnly|'
        r'annotationProcessor|testImplementation|testCompile|'
        r'classpath|provided|kapt|runtimeClasspath'
    )
    pattern_shorthand = re.compile(
        rf'(?:{CONFIGS})\s*\(?\s*["\']([^"\':\s]+):([^"\':\s]+):([^"\')\s]+)["\']',
        re.MULTILINE
    )
    for m in pattern_shorthand.finditer(content):
        group_id, artifact_id, version = m.group(1), m.group(2), m.group(3)
        # 版本含变量（$ 或 ${}）时标记为 unknown，需 LLM 补全
        if '$' in version:
            version = 'unknown'
        dependencies.append({
            'source': 'gradle',
            'file': str(gradle_file),
            'groupId': group_id,
            'artifactId': artifact_id,
            'version': version,
            'scope': 'compile'
        })

    # 匹配模式2: compile group: 'g', name: 'a', version: 'v'（旧式 Map 语法）
    pattern_map = re.compile(
        rf'(?:{CONFIGS})\s+group\s*:\s*["\']([^"\']+)["\']\s*,'
        rf'\s*name\s*:\s*["\']([^"\']+)["\']\s*,'
        rf'\s*version\s*:\s*["\']([^"\']+)["\']',
        re.MULTILINE
    )
    for m in pattern_map.finditer(content):
        group_id, artifact_id, version = m.group(1), m.group(2), m.group(3)
        if '$' in version:
            version = 'unknown'
        dependencies.append({
            'source': 'gradle',
            'file': str(gradle_file),
            'groupId': group_id,
            'artifactId': artifact_id,
            'version': version,
            'scope': 'compile'
        })

    if dependencies:
        print(f"[*] Found {len(dependencies)} deps from {gradle_file.name}")
    return dependencies



    """从 jar 文件名推断依赖信息"""
    filename = jar_path.name
    match = re.match(r'(.+?)-(\d[\d\w\.-]*)\.jar$', filename)

    if match:
        artifact_id = match.group(1)
        version = match.group(2)
        group_id = artifact_id
    else:
        artifact_id = filename.replace('.jar', '')
        version = 'unknown'
        group_id = artifact_id

    return {
        'source': 'jar',
        'file': str(jar_path),
        'groupId': group_id,
        'artifactId': artifact_id,
        'version': version,
        'scope': 'system'
    }


def scan_package_dirs(project_path: str, identified_artifacts: Set[str]) -> List[Dict]:
    """
    扫描 .class 文件所在的包目录结构，识别非 Maven 打包的嵌入库。
    返回通过已知映射表识别的依赖，以及无法识别的包（输出到 LLM 验证列表）。
    """
    root_path = Path(project_path)
    class_files = list(root_path.rglob('*.class'))

    if not class_files:
        return []

    # 收集所有 .class 文件的顶层包路径（相对于 project_path）
    # 只取前两级包路径用于匹配
    all_pkg_prefixes: Set[str] = set()
    for cf in class_files:
        try:
            rel = cf.relative_to(root_path)
            parts = rel.parts
            # 跳过 META-INF 下的内容
            if parts[0] == 'META-INF':
                continue
            # 取前1-3级目录作为包前缀候选
            if len(parts) >= 2:
                all_pkg_prefixes.add(parts[0])                       # e.g. "aj"
                all_pkg_prefixes.add('/'.join(parts[:2]))            # e.g. "com/app"
            if len(parts) >= 3:
                all_pkg_prefixes.add('/'.join(parts[:3]))            # e.g. "org/aspectj/weaver"
        except ValueError:
            continue

    found_deps = []
    unidentified_pkgs: Set[str] = set()

    # 逐个匹配已知映射表（从最长前缀开始匹配，优先精确匹配）
    matched_pkgs: Set[str] = set()
    for pkg_key in sorted(KNOWN_PACKAGE_MAP.keys(), key=len, reverse=True):
        pkg_normalized = pkg_key.replace('.', '/')
        for prefix in all_pkg_prefixes:
            if prefix == pkg_normalized or prefix.startswith(pkg_normalized + '/'):
                if pkg_key not in matched_pkgs:
                    matched_pkgs.add(pkg_key)
                    info = KNOWN_PACKAGE_MAP[pkg_key]
                    artifact_id = info['artifactId']

                    # 如果已经通过其他来源识别，跳过
                    if artifact_id in identified_artifacts:
                        continue

                    found_deps.append({
                        'source': 'package_dir',
                        'file': f"package:{prefix}",
                        'groupId': info['groupId'],
                        'artifactId': artifact_id,
                        'version': 'unknown',
                        'scope': 'compile',
                        'note': info['note']
                    })
                    print(f"[+] 包目录匹配: {prefix} → {info['groupId']}:{artifact_id} ({info['note']})")

    # 找出未能识别的顶层包
    known_top_levels = set()
    for pkg_key in matched_pkgs:
        known_top_levels.add(pkg_key.split('/')[0])

    # 标准 JDK/EE 包，不需要识别
    SKIP_PACKAGES = {
        'java', 'javax', 'sun', 'com/sun', 'jdk', 'module-info',
        'META-INF', 'resources', 'static', 'templates', 'schema', 'config'
    }

    # 已知在 META-INF/maven 或 pom.xml 中会覆盖的顶层包（大致对应）
    COMMON_KNOWN = {
        'org', 'com', 'io', 'net', 'de', 'ch', 'uk', 'fr', 'ru', 'cn'
    }

    for prefix in sorted(all_pkg_prefixes):
        top = prefix.split('/')[0]
        if top in SKIP_PACKAGES:
            continue
        if top in known_top_levels:
            continue
        # 单字母或特殊顶层包记录下来
        if top not in COMMON_KNOWN:
            unidentified_pkgs.add(prefix)

    if unidentified_pkgs:
        print(f"\n[!] 发现 {len(unidentified_pkgs)} 个未识别包前缀，需要 LLM 二次校验:")
        for pkg in sorted(unidentified_pkgs):
            print(f"    - {pkg}")

    return found_deps


def generate_llm_verification_prompt(deps: List[Dict], unidentified_pkgs: List[str]) -> str:
    """
    生成 LLM 二次校验 Prompt。
    用于：
    1. 验证从 JAR 文件名推断的 groupId 是否正确
    2. 补全 Gradle 中版本为变量引用的依赖
    3. 识别未知包目录对应的库
    4. 补充缺失的版本信息
    """
    jar_inferred = [d for d in deps if d['source'] == 'jar']
    gradle_unknown_ver = [d for d in deps if d['source'] == 'gradle' and d['version'] == 'unknown']
    package_dir_deps = [d for d in deps if d['source'] == 'package_dir']

    prompt = """# Java 依赖二次校验任务

你是一名 Java 依赖分析专家。以下依赖通过自动化工具扫描获得，需要你进行校验和补充。

## 任务一：校验 JAR 文件名推断的 groupId

以下依赖从 JAR 文件名推断，groupId 可能不准确，请根据 artifactId 和版本号给出正确的 Maven 坐标：

| artifactId | 推断版本 | 文件名 | 正确 groupId（请填写） |
|:---|:---|:---|:---|
"""
    for d in jar_inferred:
        fname = Path(d['file']).name
        prompt += f"| {d['artifactId']} | {d['version']} | {fname} | ? |\n"

    if gradle_unknown_ver:
        prompt += """
## 任务二：补全 Gradle 变量版本

以下依赖从 build.gradle 解析，版本为变量引用无法静态获取，请根据 groupId:artifactId 推断常见版本：

| groupId | artifactId | 来源文件 | 版本（请填写） |
|:---|:---|:---|:---|
"""
        for d in gradle_unknown_ver:
            fname = os.path.basename(d['file'])
            prompt += f"| {d['groupId']} | {d['artifactId']} | {fname} | ? |\n"

    if package_dir_deps:
        prompt += """
## 任务三：确认包目录识别的库

以下库通过包目录模式匹配识别，请确认版本号（如果能判断的话）：

| 包前缀 | 推断库 | groupId | 版本（请填写） |
|:---|:---|:---|:---|
"""
        for d in package_dir_deps:
            pkg = d['file'].replace('package:', '')
            prompt += f"| {pkg} | {d['artifactId']} | {d['groupId']} | ? |\n"

    if unidentified_pkgs:
        prompt += """
## 任务四：识别未知包目录

以下包目录无法自动识别，请根据包名推断对应的 Maven 库：

| 包前缀 | 推断库（请填写） | groupId（请填写） | artifactId（请填写） |
|:---|:---|:---|:---|
"""
        for pkg in sorted(unidentified_pkgs):
            prompt += f"| {pkg} | ? | ? | ? |\n"

    prompt += """
## 输出要求

- 只需填写表格中的 ? 字段
- 如果确实无法判断，填写 "无法确定"
- 重点关注有反序列化利用价值的库（Commons Collections, Spring, Xstream, Fastjson 等）
"""
    return prompt


def analyze_dependencies(project_path: str):
    """主分析函数，按优先级收集依赖"""
    all_deps = []
    identified_artifacts: Set[str] = set()

    # 优先级 1: META-INF/maven/pom.properties（最准确，Fat JAR 嵌入元数据）
    meta_inf_deps = parse_meta_inf_maven(project_path)
    all_deps.extend(meta_inf_deps)
    identified_artifacts.update(d['artifactId'] for d in meta_inf_deps)

    # 优先级 2: pom.xml（Maven 项目根 POM）
    pom_files = [p for p in find_files(project_path, 'pom.xml')
                 if 'META-INF' not in p.parts]
    print(f"[*] Found {len(pom_files)} project pom.xml files")
    for pom in pom_files:
        all_deps.extend(parse_pom(pom))

    # 优先级 3: Gradle lockfile（版本精确，Gradle 项目首选）
    lockfile_patterns = ['gradle.lockfile', '*.lockfile']
    gradle_lockfiles = []
    for pat in lockfile_patterns:
        gradle_lockfiles.extend(find_files(project_path, pat))
    # 去重（gradle.lockfile 可能同时被两个 pattern 匹配）
    gradle_lockfiles = list({str(p): p for p in gradle_lockfiles}.values())
    print(f"[*] Found {len(gradle_lockfiles)} Gradle lockfile(s)")
    for lf in gradle_lockfiles:
        all_deps.extend(parse_gradle_lockfile(lf))

    # 优先级 4: build.gradle / build.gradle.kts（无锁文件时的 Gradle 备选）
    gradle_build_files = (
        find_files(project_path, 'build.gradle') +
        find_files(project_path, 'build.gradle.kts')
    )
    print(f"[*] Found {len(gradle_build_files)} Gradle build file(s)")
    for gf in gradle_build_files:
        all_deps.extend(parse_gradle(gf))

    # 优先级 5: JAR 文件名解析（groupId 不准，需 LLM 校验）
    jar_files = find_files(project_path, '*.jar')
    print(f"[*] Found {len(jar_files)} .jar files")
    for jar in jar_files:
        all_deps.append(parse_jar_filename(jar))

    # 优先级 6: 包目录扫描（非 Maven/Gradle 打包的嵌入库）
    package_deps = scan_package_dirs(project_path, identified_artifacts)
    all_deps.extend(package_deps)

    return all_deps


def merge_dependencies(deps: List[Dict]) -> tuple:
    """合并去重，优先级: meta_inf > pom > gradle_lock > gradle > jar > package_dir"""
    SOURCE_PRIORITY = {
        'meta_inf':    0,
        'pom':         1,
        'gradle_lock': 2,
        'gradle':      3,
        'jar':         4,
        'package_dir': 5,
    }
    merged = {}

    for dep in deps:
        key = dep['artifactId']
        if key not in merged:
            merged[key] = dep
        else:
            cur_pri = SOURCE_PRIORITY.get(merged[key]['source'], 99)
            new_pri = SOURCE_PRIORITY.get(dep['source'], 99)
            # 优先级更高的来源替换
            if new_pri < cur_pri:
                merged[key] = dep
            # 同优先级但新条目有版本而当前没有
            elif new_pri == cur_pri and dep['version'] != 'unknown' and merged[key]['version'] == 'unknown':
                merged[key] = dep

    # 收集未识别的包（用于 LLM prompt）
    unidentified_pkgs = []
    for dep in deps:
        if dep['source'] == 'package_dir' and dep.get('note') == '__unidentified__':
            unidentified_pkgs.append(dep['file'].replace('package:', ''))

    return list(merged.values()), unidentified_pkgs


def save_to_xml(deps: List[Dict], output_file: str):
    """保存为 Maven 兼容的 XML"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('<!-- Generated by Java-Deser-Skills -->\n')
        f.write('<dependencies>\n')

        for dep in sorted(deps, key=lambda x: x['artifactId']):
            f.write('    <dependency>\n')
            src = dep['source']
            fname = Path(dep['file']).name
            if src == 'jar':
                f.write(f'        <!-- [VERIFY groupId] Inferred from Jar: {fname} -->\n')
            elif src == 'gradle':
                if dep['version'] == 'unknown':
                    f.write(f'        <!-- [VERIFY version] Gradle var ref, check {fname} -->\n')
                else:
                    f.write(f'        <!-- Source: {fname} -->\n')
            elif src == 'package_dir':
                f.write(f'        <!-- [VERIFY] Detected from package dir: {dep["file"]} ({dep.get("note", "")}) -->\n')

            f.write(f'        <groupId>{dep["groupId"]}</groupId>\n')
            f.write(f'        <artifactId>{dep["artifactId"]}</artifactId>\n')

            if dep['version'] != 'unknown':
                f.write(f'        <version>{dep["version"]}</version>\n')

            f.write('    </dependency>\n')

        f.write('</dependencies>\n')
    print(f"[*] XML dependency list saved to: {output_file}")


def save_to_markdown(deps: List[Dict], output_file: str):
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Dependency Analysis Report\n\n")
        f.write(f"Total Unique Dependencies: {len(deps)}\n\n")
        f.write("| Source | GroupId | ArtifactId | Version | File/Note |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")

        for dep in sorted(deps, key=lambda x: x['artifactId']):
            note = dep.get('note', '')
            file_info = note if note else os.path.basename(dep['file'])
            # 标记需要 LLM 校验的条目
            needs_verify = (
                dep['source'] in ('jar', 'package_dir') or
                (dep['source'] == 'gradle' and dep['version'] == 'unknown')
            )
            verify = ' ⚠️VERIFY' if needs_verify else ''
            f.write(f"| {dep['source']}{verify} | {dep['groupId']} | {dep['artifactId']} | {dep['version']} | {file_info} |\n")

    print(f"[*] Markdown report saved to: {output_file}")


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python parse_pom.py <project_path> [output_prefix]")
        sys.exit(1)

    project_path = sys.argv[1]
    output_prefix = sys.argv[2] if len(sys.argv) > 2 else 'deps'

    print(f"[*] Analyzing dependencies in: {project_path}")

    all_deps = analyze_dependencies(project_path)
    merged_deps, unidentified_pkgs = merge_dependencies(all_deps)

    if not merged_deps:
        print("[!] No dependencies found.")
    else:
        save_to_xml(merged_deps, f"{output_prefix}_dependencies.xml")
        save_to_markdown(merged_deps, f"{output_prefix}_dependencies.md")

        # 生成 LLM 验证 Prompt（当存在需要校验的条目时）
        needs_llm = [d for d in merged_deps if
                     d['source'] in ('jar', 'package_dir') or
                     (d['source'] == 'gradle' and d['version'] == 'unknown')]
        if needs_llm or unidentified_pkgs:
            prompt = generate_llm_verification_prompt(merged_deps, unidentified_pkgs)
            prompt_file = f"{output_prefix}_llm_verify_prompt.md"
            with open(prompt_file, 'w', encoding='utf-8') as f:
                f.write(prompt)
            print(f"[*] LLM verification prompt saved to: {prompt_file}")
            print(f"[!] {len(needs_llm)} 条依赖需要 LLM 二次校验（JAR 推断 or 包目录匹配）")
