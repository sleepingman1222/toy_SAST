#!/usr/bin/env python3
"""
Toy SAST Frontend API Import Refactor
=====================================

Phase 2E에서 남겨둔 compatibility facade:

    frontend/src/api/api.js

를 사용하는 Component import를 실제 domain API module로 바꾼다.

기본 실행은 DRY-RUN이며 파일을 수정하지 않는다.

예:
    python3 scripts/refactor_frontend_api_imports.py

실제 적용:
    python3 scripts/refactor_frontend_api_imports.py --apply

facade 참조가 0개인 것을 확인한 뒤 api.js까지 삭제:
    python3 scripts/refactor_frontend_api_imports.py --apply --remove-facade

주의:
- 함수 호출부/JSX/body는 수정하지 않는다.
- facade named import만 domain별 import로 바꾼다.
- 알 수 없는 export가 있으면 전체 적용을 중단한다.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


COMPOSE_FILES = {
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
}

SOURCE_SUFFIXES = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "__pycache__",
}


SYMBOL_TO_MODULE = {
    "authFetch": "client",

    "initializeCsrf": "authApi",
    "logoutRequest": "authApi",
    "changeMyPassword": "authApi",

    "getAdminSummary": "adminApi",

    "getProjects": "projectApi",
    "createProject": "projectApi",
    "updateProject": "projectApi",
    "createSourceVersion": "projectApi",
    "updateSourceVersion": "projectApi",
    "grantProjectAccess": "projectApi",
    "revokeProjectAccess": "projectApi",
    "deleteProject": "projectApi",

    "getProjectAnalysisRuns": "analysisApi",
    "createAnalysisRun": "analysisApi",
    "getAdminProjectAnalysisProgress": "analysisApi",

    "getUsers": "userApi",
    "createUser": "userApi",
    "updateUserStatus": "userApi",
    "deleteUser": "userApi",
}


MODULE_ORDER = [
    "client",
    "authApi",
    "adminApi",
    "projectApi",
    "analysisApi",
    "userApi",
]


# 중요:
# names 영역을 [^{}]* 로 제한해서 다른 import block의
# "}"를 넘어가지 않도록 한다.
#
# 예:
#   import { useEffect } from "react";
#   import { authFetch } from "../../../api/api";
#
# 첫 번째 React import까지 같이 먹는 문제를 방지한다.
#
FACADE_IMPORT_RE = re.compile(
    r"""
    (?P<full>
        import
        \s*
        \{
            (?P<names>
                [^{}]*
            )
        \}
        \s*
        from
        \s*
        (?P<quote>["'])
        (?P<specifier>
            [^"']*?/api/api(?:\.js)?
        )
        (?P=quote)
        \s*;
    )
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class ImportName:
    original: str
    rendered: str


@dataclass
class FileChange:
    path: Path
    before: str
    after: str
    replacements: int


def find_project_root() -> Path:
    starts = [
        Path.cwd().resolve(),
        Path(__file__).resolve().parent,
    ]

    seen: set[Path] = set()

    for start in starts:
        for candidate in [
            start,
            *start.parents,
        ]:
            if candidate in seen:
                continue

            seen.add(candidate)

            has_frontend = (
                candidate
                / "frontend"
                / "src"
            ).is_dir()

            has_compose = any(
                (
                    candidate
                    / name
                ).is_file()
                for name in COMPOSE_FILES
            )

            if (
                has_frontend
                and
                has_compose
            ):
                return candidate

    raise RuntimeError(
        "Toy SAST project root를 찾지 못했습니다. "
        "~/toy_sast 에서 실행해주세요."
    )


def iter_source_files(
    frontend_src: Path,
):
    for (
        current_root,
        dirs,
        files,
    ) in os.walk(
        frontend_src,
        topdown=True,
        onerror=lambda _: None,
    ):
        dirs[:] = [
            name
            for name in dirs
            if name not in SKIP_DIRS
        ]

        current = Path(
            current_root
        )

        for name in files:
            path = current / name

            if (
                path.suffix.lower()
                in SOURCE_SUFFIXES
            ):
                yield path


def split_named_imports(
    raw_names: str,
) -> list[ImportName]:
    if (
        "/*" in raw_names
        or
        "//" in raw_names
    ):
        raise ValueError(
            "facade import 내부 comment는 자동 변환하지 않습니다."
        )

    result: list[
        ImportName
    ] = []

    for raw_item in raw_names.split(
        ","
    ):
        item = raw_item.strip()

        if not item:
            continue

        match = re.fullmatch(
            r"""
            (?P<original>
                [A-Za-z_$]
                [A-Za-z0-9_$]*
            )
            (?:
                \s+as\s+
                (?P<alias>
                    [A-Za-z_$]
                    [A-Za-z0-9_$]*
                )
            )?
            """,
            item,
            re.VERBOSE,
        )

        if not match:
            raise ValueError(
                f"지원하지 않는 named import 문법: {item!r}"
            )

        original = match.group(
            "original"
        )

        alias = match.group(
            "alias"
        )

        rendered = (
            f"{original} as {alias}"
            if alias
            else original
        )

        result.append(
            ImportName(
                original=
                    original,
                rendered=
                    rendered,
            )
        )

    if not result:
        raise ValueError(
            "비어 있는 facade import를 발견했습니다."
        )

    return result


def target_specifier(
    old_specifier: str,
    module_name: str,
) -> str:
    suffix = (
        "/api/api.js"
        if old_specifier.endswith(
            "/api/api.js"
        )
        else "/api/api"
    )

    prefix = old_specifier[
        :-len(suffix)
    ]

    return (
        f"{prefix}/api/"
        f"{module_name}"
    )


def render_domain_import(
    names: list[ImportName],
    specifier: str,
) -> str:
    body = "\n".join(
        f"  {item.rendered},"
        for item in names
    )

    return (
        "import {\n"
        f"{body}\n"
        f'}} from "{specifier}";'
    )


def transform_import_match(
    match: re.Match,
) -> str:
    names = split_named_imports(
        match.group(
            "names"
        )
    )

    grouped: dict[
        str,
        list[ImportName],
    ] = {}

    unknown = []

    for item in names:
        module_name = (
            SYMBOL_TO_MODULE.get(
                item.original
            )
        )

        if not module_name:
            unknown.append(
                item.original
            )
            continue

        grouped.setdefault(
            module_name,
            [],
        ).append(
            item
        )

    if unknown:
        raise ValueError(
            "domain mapping이 없는 facade export: "
            + ", ".join(
                sorted(
                    unknown
                )
            )
        )

    old_specifier = (
        match.group(
            "specifier"
        )
    )

    rendered_blocks = []

    for module_name in (
        MODULE_ORDER
    ):
        module_names = (
            grouped.get(
                module_name
            )
        )

        if not module_names:
            continue

        rendered_blocks.append(
            render_domain_import(
                module_names,
                target_specifier(
                    old_specifier,
                    module_name,
                ),
            )
        )

    return "\n\n".join(
        rendered_blocks
    )


def transform_file(
    path: Path,
) -> FileChange | None:
    before = path.read_text(
        encoding="utf-8",
    )

    replacements = 0

    def replacement(
        match: re.Match,
    ) -> str:
        nonlocal replacements

        replacements += 1

        return transform_import_match(
            match
        )

    after = FACADE_IMPORT_RE.sub(
        replacement,
        before,
    )

    if before == after:
        return None

    return FileChange(
        path=path,
        before=before,
        after=after,
        replacements=
            replacements,
    )


def find_facade_references(
    frontend_src: Path,
) -> list[
    tuple[
        Path,
        int,
        str,
    ]
]:
    references = []

    for path in iter_source_files(
        frontend_src
    ):
        if (
            path
            ==
            frontend_src
            / "api"
            / "api.js"
        ):
            continue

        text = path.read_text(
            encoding="utf-8",
        )

        for match in (
            FACADE_IMPORT_RE.finditer(
                text
            )
        ):
            line = (
                text.count(
                    "\n",
                    0,
                    match.start(),
                )
                + 1
            )

            references.append(
                (
                    path,
                    line,
                    match.group(
                        "specifier"
                    ),
                )
            )

    return references


def validate_domain_modules(
    frontend_src: Path,
):
    api_root = (
        frontend_src
        / "api"
    )

    required = [
        "client.js",
        "authApi.js",
        "adminApi.js",
        "projectApi.js",
        "analysisApi.js",
        "userApi.js",
        "normalizers.js",
    ]

    missing = [
        name
        for name in required
        if not (
            api_root
            / name
        ).is_file()
    ]

    if missing:
        raise RuntimeError(
            "Phase 2E domain API file이 없습니다: "
            + ", ".join(
                missing
            )
        )


def relative(
    root: Path,
    path: Path,
) -> str:
    try:
        return str(
            path.relative_to(
                root
            )
        )
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "frontend api/api facade import를 "
            "domain API import로 변경"
        )
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "실제 source file에 변경 적용"
        ),
    )

    parser.add_argument(
        "--remove-facade",
        action="store_true",
        help=(
            "변환 후 facade reference가 0이면 "
            "frontend/src/api/api.js 삭제"
        ),
    )

    args = parser.parse_args()

    if (
        args.remove_facade
        and
        not args.apply
    ):
        parser.error(
            "--remove-facade는 --apply와 함께 사용해주세요."
        )

    root = find_project_root()

    frontend_src = (
        root
        / "frontend"
        / "src"
    )

    validate_domain_modules(
        frontend_src
    )

    changes = []

    try:
        for path in iter_source_files(
            frontend_src
        ):
            facade_path = (
                frontend_src
                / "api"
                / "api.js"
            )

            if path == facade_path:
                continue

            change = transform_file(
                path
            )

            if change:
                changes.append(
                    change
                )

    except ValueError as error:
        print(
            "[ABORT]",
            error,
            file=sys.stderr,
        )
        print(
            "어떤 파일도 수정하지 않았습니다.",
            file=sys.stderr,
        )
        return 2

    print("=" * 78)
    print(
        "Frontend API Import Refactor"
    )
    print(
        "Project root:",
        root,
    )
    print(
        "Mode:",
        "APPLY"
        if args.apply
        else "DRY-RUN",
    )
    print("=" * 78)

    if not changes:
        print(
            "[INFO] 변경할 api/api import가 없습니다."
        )

    else:
        print(
            f"[INFO] 변경 대상: "
            f"{len(changes)} file(s)"
        )
        print()

        for change in changes:
            print(
                "[CHANGE]",
                relative(
                    root,
                    change.path,
                ),
                f"({change.replacements} import block)"
            )

    if not args.apply:
        print()
        print(
            "파일은 수정하지 않았습니다."
        )
        print()
        print(
            "실제 적용:"
        )
        print(
            "  python3 "
            "scripts/refactor_frontend_api_imports.py "
            "--apply"
        )
        return 0

    for change in changes:
        change.path.write_text(
            change.after,
            encoding="utf-8",
        )

    references = (
        find_facade_references(
            frontend_src
        )
    )

    if references:
        print()
        print(
            "[FAIL] 적용 후에도 "
            "api/api reference가 남아 있습니다."
        )

        for (
            path,
            line,
            specifier,
        ) in references:
            print(
                "  -",
                f"{relative(root, path)}:"
                f"{line}",
                specifier,
            )

        print()
        print(
            "facade는 삭제하지 않았습니다."
        )

        return 3

    print()
    print(
        "[PASS] facade import references: 0"
    )

    facade_path = (
        frontend_src
        / "api"
        / "api.js"
    )

    if args.remove_facade:
        if facade_path.exists():
            facade_path.unlink()

            print(
                "[DELETED]",
                relative(
                    root,
                    facade_path,
                )
            )

        else:
            print(
                "[INFO] facade api.js는 이미 없습니다."
            )

    else:
        print(
            "[KEEP] frontend/src/api/api.js"
        )
        print(
            "       build 확인 후 삭제하려면:"
        )
        print(
            "       python3 "
            "scripts/refactor_frontend_api_imports.py "
            "--apply --remove-facade"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
