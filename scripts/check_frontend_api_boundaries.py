#!/usr/bin/env python3
"""
Toy SAST Frontend API Boundary Checker
======================================

실행:
    python3 scripts/check_frontend_api_boundaries.py

facade 파일 자체도 없어야 PASS 처리:
    python3 scripts/check_frontend_api_boundaries.py \
      --require-facade-removed
"""

from __future__ import annotations

import argparse
import os
import re
import sys
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

FACADE_RE = re.compile(
    r"""from\s*["'][^"']*?/api/api(?:\.js)?["']"""
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

            if (
                (
                    candidate
                    / "frontend"
                    / "src"
                ).is_dir()
                and
                any(
                    (
                        candidate
                        / name
                    ).is_file()
                    for name
                    in COMPOSE_FILES
                )
            ):
                return candidate

    raise RuntimeError(
        "Toy SAST project root를 찾지 못했습니다."
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
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--require-facade-removed",
        action="store_true",
    )

    args = parser.parse_args()

    root = find_project_root()

    frontend_src = (
        root
        / "frontend"
        / "src"
    )

    api_root = (
        frontend_src
        / "api"
    )

    required_modules = [
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
        for name
        in required_modules
        if not (
            api_root
            / name
        ).is_file()
    ]

    facade_refs = []

    for path in iter_source_files(
        frontend_src
    ):
        if path == (
            api_root
            / "api.js"
        ):
            continue

        text = path.read_text(
            encoding="utf-8",
        )

        for match in (
            FACADE_RE.finditer(
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

            facade_refs.append(
                (
                    path,
                    line,
                )
            )

    failed = False

    print("=" * 78)
    print(
        "Frontend API Boundary Check"
    )
    print("=" * 78)

    if missing:
        failed = True
        print(
            "[FAIL] missing domain modules:"
        )

        for name in missing:
            print(
                "  -",
                name,
            )
    else:
        print(
            "[PASS] domain API modules"
        )

    if facade_refs:
        failed = True

        print(
            "[FAIL] api/api import remains:"
        )

        for (
            path,
            line,
        ) in facade_refs:
            print(
                "  -",
                f"{relative(root, path)}:"
                f"{line}",
            )
    else:
        print(
            "[PASS] api/api imports: 0"
        )

    facade_path = (
        api_root
        / "api.js"
    )

    if args.require_facade_removed:
        if facade_path.exists():
            failed = True
            print(
                "[FAIL] compatibility facade still exists:",
                relative(
                    root,
                    facade_path,
                ),
            )
        else:
            print(
                "[PASS] compatibility facade removed"
            )
    else:
        print(
            "[INFO] compatibility facade:",
            (
                "exists"
                if facade_path.exists()
                else "removed"
            ),
        )

    return (
        1
        if failed
        else 0
    )


if __name__ == "__main__":
    sys.exit(
        main()
    )
