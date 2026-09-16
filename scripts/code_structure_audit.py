#!/usr/bin/env python3
"""
Toy SAST Code Structure Audit
=============================

디스크 용량이 아니라 코드 구조를 정리하기 위한 감사 도구.

기본 원칙:
- 아무 파일도 삭제/수정하지 않는다.
- 실제 현재 프로젝트 전체를 대상으로 조사한다.
- "삭제 후보"와 "공통화 후보"만 출력한다.

검사:
1. 큰 소스 파일
2. backend/scans/tasks.py re-export-only import
3. legacy 분석 helper 실제 참조 여부
4. Python 동일 함수 구현 중복
5. frontend api.js export 실제 사용 여부
6. Admin/User ProjectDetail 공통 helper 이름
7. legacy/mock/호환/fallback 표식

실행:
    python3 scripts/code_structure_audit.py
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


COMPOSE_NAMES = {
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
}

LEGACY_MARKERS = re.compile(
    r"\b("
    r"legacy|deprecated|mock|fallback|temporary|compat"
    r")\b|"
    r"기존|호환|전환\s*기간|임시|레거시",
    re.IGNORECASE,
)

KNOWN_PIPELINE_LEGACY = [
    "detect_languages",
    "execute_semgrep",
    "execute_semgrep_for_languages",
    "save_vulnerabilities",
]

TASKS_MOVED_HELPERS = {
    # archive_security
    "normalize_zip_member_path",
    "validate_zip_member_type",
    "validate_zip_members",
    "safely_extract_zip",

    # source acquisition
    "get_upload_zip_path",
    "prepare_upload_target",
    "get_internal_target",
    "prepare_repository_target",
    "prepare_analysis_target",

    # language
    "normalize_language_name",
    "detect_file_language",
    "detect_languages",
    "get_legacy_language_value",
    "save_detected_languages",

    # semgrep
    "get_semgrep_rule_path",
    "execute_semgrep",
    "execute_semgrep_for_languages",

    # vulnerability
    "normalize_severity",
    "normalize_confidence",
    "normalize_text",
    "is_placeholder_value",
    "get_kisa_security_weakness",
    "get_vulnerability_name",
    "resolve_result_file_path",
    "get_display_file_path",
    "extract_evidence",
    "get_recommendation",
    "build_vulnerability",
    "save_vulnerabilities",

    # chunk runtime
    "normalize_chunk_relative_path",
    "copy_verified_chunk_file",
    "prepare_chunk_execution_target",
    "terminate_semgrep_process",
    "execute_semgrep_with_heartbeat",
    "build_vulnerability_fingerprint",
    "build_attempt_vulnerability",
    "save_attempt_vulnerabilities",
}

JS_EXPORT_FUNCTION_RE = re.compile(
    r"(?m)^\s*export\s+"
    r"(?:async\s+)?function\s+"
    r"([A-Za-z_$][\w$]*)\s*\("
)

JS_IMPORT_BLOCK_RE = re.compile(
    r"import\s*\{(?P<names>.*?)\}\s*from\s*"
    r"['\"](?P<path>[^'\"]+)['\"]",
    re.DOTALL,
)

JS_CONST_RE = re.compile(
    r"(?m)^\s*const\s+"
    r"([A-Za-z_$][\w$]*)\s*="
)

JS_FUNCTION_RE = re.compile(
    r"(?m)^\s*(?:export\s+)?"
    r"(?:async\s+)?function\s+"
    r"([A-Za-z_$][\w$]*)\s*\("
)


def find_project_root() -> Path:
    starts = [
        Path.cwd().resolve(),
        Path(__file__).resolve().parent,
    ]

    seen = set()

    for start in starts:
        for candidate in [
            start,
            *start.parents,
        ]:
            if candidate in seen:
                continue

            seen.add(candidate)

            has_backend = (
                candidate
                / "backend"
                / "manage.py"
            ).is_file()

            has_compose = any(
                (
                    candidate
                    / name
                ).is_file()
                for name in COMPOSE_NAMES
            )

            if has_backend and has_compose:
                return candidate

    raise RuntimeError(
        "Toy SAST project root를 찾지 못했습니다."
    )


def iter_source_files(
    root: Path,
    suffixes: set[str],
):
    for current_root, dirs, files in os.walk(
        root,
        topdown=True,
        onerror=lambda _: None,
    ):
        dirs[:] = [
            name
            for name in dirs
            if name not in SKIP_DIRS
        ]

        current = Path(current_root)

        for name in files:
            path = current / name

            if path.suffix.lower() in suffixes:
                yield path


def rel(
    root: Path,
    path: Path,
) -> str:
    try:
        return str(
            path.relative_to(root)
        )
    except ValueError:
        return str(path)


def section(title: str):
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def line_count(path: Path) -> int:
    try:
        return len(
            path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
        )
    except OSError:
        return 0


def parse_python(path: Path):
    try:
        return ast.parse(
            path.read_text(
                encoding="utf-8",
                errors="replace",
            ),
            filename=str(path),
        )
    except (
        OSError,
        SyntaxError,
    ):
        return None


class LoadedNameCollector(ast.NodeVisitor):
    def __init__(self):
        self.names: set[str] = set()

    def visit_Name(self, node):
        if isinstance(
            node.ctx,
            ast.Load,
        ):
            self.names.add(
                node.id
            )

        self.generic_visit(node)


def module_internal_loaded_names(
    tree: ast.Module,
) -> set[str]:
    """
    import statement 자체의 이름은 제외하고
    실제 module 코드에서 Load되는 이름만 구한다.
    """

    names: set[str] = set()

    for node in tree.body:
        if isinstance(
            node,
            (
                ast.Import,
                ast.ImportFrom,
            ),
        ):
            continue

        collector = LoadedNameCollector()
        collector.visit(node)
        names.update(
            collector.names
        )

    return names


def imported_names_from_module(
    tree: ast.Module,
    module_suffix: str,
) -> set[str]:
    result = set()

    for node in tree.body:
        if not isinstance(
            node,
            ast.ImportFrom,
        ):
            continue

        module = node.module or ""

        if not module.endswith(
            module_suffix
        ):
            continue

        for alias in node.names:
            result.add(
                alias.asname
                or alias.name
            )

    return result


def collect_project_python_refs(
    root: Path,
    py_files: list[Path],
):
    loaded_by_file: dict[
        Path,
        set[str],
    ] = {}

    imported_from_tasks: dict[
        str,
        list[tuple[Path, int]],
    ] = defaultdict(list)

    for path in py_files:
        tree = parse_python(path)

        if tree is None:
            continue

        collector = LoadedNameCollector()
        collector.visit(tree)

        loaded_by_file[path] = (
            collector.names
        )

        for node in ast.walk(tree):
            if not isinstance(
                node,
                ast.ImportFrom,
            ):
                continue

            module = node.module or ""

            if module not in {
                "scans.tasks",
                "backend.scans.tasks",
            }:
                continue

            for alias in node.names:
                imported_from_tasks[
                    alias.name
                ].append(
                    (
                        path,
                        node.lineno,
                    )
                )

    return (
        loaded_by_file,
        imported_from_tasks,
    )


def normalized_function_hash(
    node: ast.FunctionDef
    | ast.AsyncFunctionDef,
) -> str:
    """
    함수 이름/위치가 아니라 구현 AST 기준.
    docstring은 제거한다.
    """

    cloned = ast.FunctionDef(
        name="_",
        args=node.args,
        body=list(node.body),
        decorator_list=[],
        returns=node.returns,
        type_comment=getattr(
            node,
            "type_comment",
            None,
        ),
    )

    if (
        cloned.body
        and isinstance(
            cloned.body[0],
            ast.Expr,
        )
        and isinstance(
            cloned.body[0].value,
            ast.Constant,
        )
        and isinstance(
            cloned.body[0].value.value,
            str,
        )
    ):
        cloned.body = (
            cloned.body[1:]
        )

    dump = ast.dump(
        cloned,
        include_attributes=False,
    )

    return hashlib.sha256(
        dump.encode("utf-8")
    ).hexdigest()


def python_duplicate_functions(
    py_files: list[Path],
):
    groups: dict[
        str,
        list[
            tuple[
                Path,
                str,
                int,
                int,
            ]
        ],
    ] = defaultdict(list)

    for path in py_files:
        tree = parse_python(path)

        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                ),
            ):
                continue

            body_lines = (
                getattr(
                    node,
                    "end_lineno",
                    node.lineno,
                )
                - node.lineno
                + 1
            )

            # 너무 작은 assert/helper는 노이즈가 많다.
            if body_lines < 8:
                continue

            digest = (
                normalized_function_hash(
                    node
                )
            )

            groups[digest].append(
                (
                    path,
                    node.name,
                    node.lineno,
                    body_lines,
                )
            )

    return [
        values
        for values in groups.values()
        if len(values) >= 2
    ]


def read_js(path: Path) -> str:
    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return ""


def collect_js_imported_names(
    js_files: list[Path],
):
    refs: dict[
        str,
        list[
            tuple[
                Path,
                str,
            ]
        ],
    ] = defaultdict(list)

    for path in js_files:
        text = read_js(path)

        for match in (
            JS_IMPORT_BLOCK_RE
            .finditer(text)
        ):
            source_path = (
                match.group("path")
            )

            raw_names = (
                match.group("names")
            )

            for item in raw_names.split(
                ","
            ):
                item = item.strip()

                if not item:
                    continue

                original = (
                    item.split(
                        " as "
                    )[0]
                    .strip()
                )

                if original:
                    refs[
                        original
                    ].append(
                        (
                            path,
                            source_path,
                        )
                    )

    return refs


def extract_js_local_names(
    path: Path,
) -> set[str]:
    text = read_js(path)

    names = set(
        JS_CONST_RE.findall(
            text
        )
    )

    names.update(
        JS_FUNCTION_RE.findall(
            text
        )
    )

    # JSX state setter/derived variables 등 너무 많은 const가 잡히므로
    # 공통화 가능성이 높은 helper 형태만 caller가 교집합으로 본다.
    return names


def print_legacy_markers(
    root: Path,
    source_files: list[Path],
):
    matches = []

    for path in source_files:
        try:
            lines = path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
        except OSError:
            continue

        for index, line in enumerate(
            lines,
            start=1,
        ):
            if LEGACY_MARKERS.search(
                line
            ):
                matches.append(
                    (
                        path,
                        index,
                        line.strip(),
                    )
                )

    for path, lineno, line in (
        matches[:120]
    ):
        print(
            f"{rel(root, path)}:"
            f"{lineno}: "
            f"{line[:150]}"
        )

    if len(matches) > 120:
        print(
            f"... +{len(matches) - 120} more"
        )

    if not matches:
        print("(none)")


def main() -> int:
    root = find_project_root()

    backend = (
        root
        / "backend"
    )

    frontend_src = (
        root
        / "frontend"
        / "src"
    )

    py_files = list(
        iter_source_files(
            backend,
            {".py"},
        )
    )

    js_files = (
        list(
            iter_source_files(
                frontend_src,
                {
                    ".js",
                    ".jsx",
                    ".ts",
                    ".tsx",
                },
            )
        )
        if frontend_src.exists()
        else []
    )

    print("=" * 88)
    print(
        "Toy SAST Code Structure Audit"
    )
    print(
        "Project root:",
        root,
    )
    print("=" * 88)


    # ========================================================
    # 1. Large code files
    # ========================================================

    section(
        "1. Large source files"
    )

    large = []

    for path in [
        *py_files,
        *js_files,
    ]:
        lines = line_count(path)

        if lines >= 300:
            large.append(
                (
                    lines,
                    path,
                )
            )

    large.sort(
        reverse=True,
        key=lambda item:
            item[0],
    )

    for lines, path in large[:40]:
        print(
            f"{lines:>6} lines  "
            f"{rel(root, path)}"
        )

    if not large:
        print("(none)")


    # ========================================================
    # 2. tasks.py compatibility re-exports
    # ========================================================

    section(
        "2. scans/tasks.py re-export-only imports"
    )

    tasks_path = (
        backend
        / "scans"
        / "tasks.py"
    )

    (
        loaded_by_file,
        imported_from_tasks,
    ) = collect_project_python_refs(
        root,
        py_files,
    )

    if not tasks_path.is_file():
        print(
            "backend/scans/tasks.py 없음"
        )

    else:
        tasks_tree = (
            parse_python(
                tasks_path
            )
        )

        if tasks_tree is None:
            print(
                "tasks.py parse 실패"
            )

        else:
            internal_names = (
                module_internal_loaded_names(
                    tasks_tree
                )
            )

            reexport_only = []

            for node in tasks_tree.body:
                if not isinstance(
                    node,
                    ast.ImportFrom,
                ):
                    continue

                module = (
                    node.module
                    or ""
                )

                if ".services." not in (
                    "." + module
                ):
                    continue

                for alias in node.names:
                    local_name = (
                        alias.asname
                        or alias.name
                    )

                    if (
                        local_name
                        not in internal_names
                    ):
                        external = (
                            imported_from_tasks
                            .get(
                                local_name,
                                [],
                            )
                        )

                        reexport_only.append(
                            (
                                local_name,
                                module,
                                external,
                            )
                        )

            if not reexport_only:
                print("(none)")
            else:
                for (
                    name,
                    module,
                    external,
                ) in reexport_only:

                    if external:
                        status = (
                            "KEEP: external import"
                        )
                    else:
                        status = (
                            "REMOVE CANDIDATE"
                        )

                    print(
                        f"[{status}] "
                        f"{name} "
                        f"<- {module}"
                    )

                    for (
                        path,
                        lineno,
                    ) in external:
                        if path == tasks_path:
                            continue

                        print(
                            "    used by:",
                            f"{rel(root, path)}:"
                            f"{lineno}",
                        )


    # ========================================================
    # 3. Legacy pipeline helpers
    # ========================================================

    section(
        "3. Legacy analysis helper references"
    )

    for name in (
        KNOWN_PIPELINE_LEGACY
    ):
        locations = []

        for path, names in (
            loaded_by_file.items()
        ):
            if (
                name in names
            ):
                locations.append(
                    path
                )

        # defining module의 자기 내부 호출도 보여준다.
        print(
            f"{name}: "
            f"{len(locations)} file(s)"
        )

        for path in locations:
            print(
                "    -",
                rel(root, path),
            )

    print()
    print(
        "판정 기준:"
    )
    print(
        "- execute_semgrep + "
        "execute_semgrep_for_languages가 "
        "semgrep_executor.py 안에서만 서로 참조되고 "
        "외부 참조가 없으면 legacy direct-run 경로 삭제 후보"
    )
    print(
        "- save_vulnerabilities가 "
        "vulnerability_writer.py 외부에서 참조되지 않으면 "
        "legacy bulk-save 경로 삭제 후보"
    )
    print(
        "- detect_languages가 현재 pipeline에서 "
        "snapshot metadata를 쓰고 외부 참조가 없으면 삭제 후보"
    )


    # ========================================================
    # 4. Exact duplicate Python functions
    # ========================================================

    section(
        "4. Exact duplicate Python function implementations"
    )

    duplicates = (
        python_duplicate_functions(
            py_files
        )
    )

    duplicates.sort(
        key=lambda group:
            max(
                item[3]
                for item in group
            ),
        reverse=True,
    )

    shown = 0

    for group in duplicates:
        # 동일 파일 안의 nested/lambda helper noise보다
        # 여러 파일에 걸친 중복을 우선한다.
        unique_files = {
            item[0]
            for item in group
        }

        if len(unique_files) < 2:
            continue

        lines = max(
            item[3]
            for item in group
        )

        print(
            f"{len(group)} copies, "
            f"~{lines} lines"
        )

        for (
            path,
            name,
            lineno,
            body_lines,
        ) in group:
            print(
                "    -",
                f"{rel(root, path)}:"
                f"{lineno}",
                name,
                f"({body_lines} lines)",
            )

        shown += 1

        if shown >= 30:
            break

    if shown == 0:
        print("(none)")


    # ========================================================
    # 5. API exports usage
    # ========================================================

    section(
        "5. frontend/src/api/api.js exported function usage"
    )

    api_path = (
        frontend_src
        / "api"
        / "api.js"
    )

    imported_js = (
        collect_js_imported_names(
            js_files
        )
    )

    if not api_path.is_file():
        print(
            "frontend/src/api/api.js 없음"
        )

    else:
        api_text = read_js(
            api_path
        )

        exports = (
            JS_EXPORT_FUNCTION_RE
            .findall(
                api_text
            )
        )

        for name in exports:
            importers = [
                (
                    path,
                    source_path,
                )
                for (
                    path,
                    source_path,
                )
                in imported_js.get(
                    name,
                    [],
                )
                if path != api_path
            ]

            if importers:
                print(
                    f"[USED {len(importers):>2}] "
                    f"{name}"
                )
            else:
                print(
                    "[UNUSED CANDIDATE] "
                    f"{name}"
                )


    # ========================================================
    # 6. Admin/User ProjectDetail duplicate names
    # ========================================================

    section(
        "6. Admin/User ProjectDetail common local helpers/state names"
    )

    admin_candidates = [
        frontend_src
        / "components"
        / "Admin"
        / "Project"
        / "ProjectDetail.jsx",

        frontend_src
        / "components"
        / "Admin"
        / "ProjectDetail.jsx",
    ]

    user_candidates = [
        frontend_src
        / "components"
        / "User"
        / "Project"
        / "UserProjectDetail.jsx",

        frontend_src
        / "components"
        / "User"
        / "UserProjectDetail.jsx",
    ]

    admin_path = next(
        (
            path
            for path in admin_candidates
            if path.is_file()
        ),
        None,
    )

    user_path = next(
        (
            path
            for path in user_candidates
            if path.is_file()
        ),
        None,
    )

    if not admin_path or not user_path:
        print(
            "Admin/User ProjectDetail 현재 경로를 "
            "둘 다 찾지 못했습니다."
        )

    else:
        admin_names = (
            extract_js_local_names(
                admin_path
            )
        )

        user_names = (
            extract_js_local_names(
                user_path
            )
        )

        common = sorted(
            admin_names
            & user_names
        )

        interesting = [
            name
            for name in common
            if (
                name.startswith(
                    "get"
                )
                or
                "Vulnerab" in name
                or
                "vulnerab" in name
                or
                "Severity" in name
                or
                "severity" in name
                or
                "Confidence" in name
                or
                "confidence" in name
                or
                "Analysis" in name
                or
                "analysis" in name
            )
        ]

        print(
            "Admin:",
            rel(root, admin_path),
        )
        print(
            "User :",
            rel(root, user_path),
        )
        print()

        for name in interesting:
            print(
                "[COMMON]",
                name,
            )

        print()
        print(
            "공통 이름이 많을수록 "
            "VulnerabilityTable / "
            "VulnerabilityDetailModal / "
            "pagination helper 공통화 우선순위가 높습니다."
        )


    # ========================================================
    # 7. Legacy markers
    # ========================================================

    section(
        "7. Legacy / compatibility / mock markers"
    )

    print_legacy_markers(
        root,
        [
            *py_files,
            *js_files,
        ],
    )


    # ========================================================
    # Suggested order
    # ========================================================

    section(
        "8. Recommended cleanup order"
    )

    print(
        "1) scans.tasks의 외부 사용 없는 re-export-only import 제거"
    )
    print(
        "2) legacy direct Semgrep 경로 "
        "(execute_semgrep_for_languages / save_vulnerabilities) 제거"
    )
    print(
        "3) 제거 후 불필요 import/constants 추가 정리"
    )
    print(
        "4) Admin/User 취약점 결과 UI를 공통 컴포넌트로 통합"
    )
    print(
        "5) api.js에서 UNUSED CANDIDATE export 제거"
    )
    print(
        "6) 마지막에 api.js를 domain module로 분리 "
        "(이건 코드 삭제보다 구조 개선)"
    )

    print()
    print(
        "이 스크립트는 아무 코드도 삭제하지 않았습니다."
    )

    return 0


if __name__ == "__main__":
    sys.exit(
        main()
    )
