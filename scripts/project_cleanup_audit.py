#!/usr/bin/env python3
"""
Toy SAST Project Cleanup Audit
==============================

목적
----
프로젝트 경량화 전에:
1. 상위 디렉터리별 용량 확인
2. 안전하게 재생성 가능한 파일/폴더 탐지
3. 검토가 필요한 백업/복사본/로그/리포트 탐지
4. 큰 파일 탐지
5. 중복 파일 탐지

기본 실행은 "절대 삭제하지 않는다".

사용:
    python3 scripts/project_cleanup_audit.py

안전 생성물만 삭제:
    python3 scripts/project_cleanup_audit.py --delete-safe

node_modules까지 삭제:
    python3 scripts/project_cleanup_audit.py --delete-safe --include-node-modules

주의:
- DB migration
- KISA rule
- Semgrep fixture
- 실제 source/media 데이터
는 자동 삭제하지 않는다.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
from collections import defaultdict
from pathlib import Path


COMPOSE_FILES = {
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
}

SAFE_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".vite",
    "htmlcov",
}

SAFE_FILE_SUFFIXES = {
    ".pyc",
    ".pyo",
}

SAFE_FILE_NAMES = {
    ".coverage",
    ".DS_Store",
    "Thumbs.db",
    ".eslintcache",
}

REVIEW_SUFFIXES = {
    ".bak",
    ".old",
    ".orig",
    ".rej",
    ".tmp",
    ".temp",
    ".log",
}

REVIEW_NAME_MARKERS = (
    "(1)",
    "(2)",
    "(3)",
    "_copy",
    "-copy",
    " copy",
    "_backup",
    "-backup",
    ".backup",
)

EXCLUDED_FROM_DUPLICATE_SCAN = {
    ".git",
    "node_modules",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

NEVER_AUTO_DELETE_PARTS = {
    "migrations",
    "semgrep_rules",
    "media",
    "uploads",
}


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024

    return f"{size} B"


def find_project_root() -> Path:
    starts = [
        Path.cwd().resolve(),
        Path(__file__).resolve().parent,
    ]

    seen: set[Path] = set()

    for start in starts:
        for candidate in [start, *start.parents]:
            if candidate in seen:
                continue
            seen.add(candidate)

            has_backend = (
                candidate / "backend" / "manage.py"
            ).is_file()

            has_compose = any(
                (candidate / name).is_file()
                for name in COMPOSE_FILES
            )

            if has_backend and has_compose:
                return candidate

    raise RuntimeError(
        "Toy SAST 프로젝트 root를 찾지 못했습니다. "
        "~/toy_sast 에서 실행해 주세요."
    )


def path_size(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0

    total = 0

    for root, dirs, files in os.walk(
        path,
        onerror=lambda _: None,
    ):
        root_path = Path(root)

        if ".git" in root_path.parts:
            continue

        for file_name in files:
            file_path = root_path / file_name
            try:
                total += file_path.stat().st_size
            except OSError:
                pass

    return total


def is_inside_never_auto_delete(path: Path) -> bool:
    lowered_parts = {
        part.lower()
        for part in path.parts
    }
    return bool(
        lowered_parts
        & NEVER_AUTO_DELETE_PARTS
    )


def collect_candidates(
    root: Path,
    include_node_modules: bool,
):
    safe_dirs: list[Path] = []
    safe_files: list[Path] = []
    review_files: list[Path] = []
    large_files: list[tuple[int, Path]] = []

    for current_root, dirs, files in os.walk(
        root,
        topdown=True,
        onerror=lambda _: None,
    ):
        current = Path(current_root)

        # ----------------------------------------------------
        # Never inspect .git
        # ----------------------------------------------------

        if ".git" in current.parts:
            dirs[:] = []
            continue


        # ----------------------------------------------------
        # node_modules
        #
        # IMPORTANT:
        # 패키지 내부의 dist/는 build 잔여물이 아니라
        # 실제 설치된 패키지 코드일 수 있다.
        #
        # 따라서 node_modules 내부를 절대 개별 정리하지 않는다.
        #
        # --include-node-modules가 있으면
        # frontend/node_modules 전체만 삭제 후보로 추가한다.
        # ----------------------------------------------------

        if "node_modules" in current.parts:
            dirs[:] = []
            continue


        if "node_modules" in dirs:

            node_modules_path = (
                current
                / "node_modules"
            )

            if (
                include_node_modules
                and current.name == "frontend"
            ):
                safe_dirs.append(
                    node_modules_path
                )

            # 내부 패키지 파일은 더 이상 순회하지 않는다.
            dirs.remove(
                "node_modules"
            )


        # ----------------------------------------------------
        # Project-generated safe directories
        # ----------------------------------------------------

        for dir_name in list(dirs):
            path = current / dir_name

            if dir_name in SAFE_DIR_NAMES:
                if not is_inside_never_auto_delete(path):
                    safe_dirs.append(path)

                dirs.remove(dir_name)
                continue


            # frontend/dist만 Vite build 산출물로 취급한다.
            # dependency package의 dist/와 혼동하지 않는다.
            if (
                dir_name == "dist"
                and current == (
                    root
                    / "frontend"
                )
            ):
                safe_dirs.append(path)
                dirs.remove(dir_name)
                continue


        # ----------------------------------------------------
        # Files
        # ----------------------------------------------------

        for file_name in files:
            path = current / file_name

            try:
                size = path.stat().st_size
            except OSError:
                continue

            lower_name = (
                file_name.lower()
            )


            if (
                path.suffix.lower()
                in SAFE_FILE_SUFFIXES
                or file_name
                in SAFE_FILE_NAMES
            ):
                if not is_inside_never_auto_delete(path):
                    safe_files.append(path)

                continue


            if (
                path.suffix.lower()
                in REVIEW_SUFFIXES
                or any(
                    marker in lower_name
                    for marker
                    in REVIEW_NAME_MARKERS
                )
            ):
                review_files.append(path)


            # Root-level ZIP security artifacts are review-only.
            if (
                current == root
                and (
                    file_name
                    == "zip_slip_test.zip"
                )
            ):
                review_files.append(path)


            if size >= 5 * 1024 * 1024:
                large_files.append(
                    (
                        size,
                        path,
                    )
                )


    # --------------------------------------------------------
    # Known generated security test artifact directory
    #
    # 자동 삭제는 하지 않고 REVIEW로만 보여준다.
    # --------------------------------------------------------

    zip_security_dir = (
        root
        / "zip_security_tests"
    )

    if zip_security_dir.exists():
        review_files.append(
            zip_security_dir
        )


    safe_dirs = sorted(
        set(safe_dirs),
        key=lambda p: str(p),
    )

    safe_files = sorted(
        set(safe_files),
        key=lambda p: str(p),
    )

    review_files = sorted(
        set(review_files),
        key=lambda p: str(p),
    )

    large_files.sort(
        reverse=True
    )


    return (
        safe_dirs,
        safe_files,
        review_files,
        large_files,
    )

def file_hash(path: Path) -> str | None:
    digest = hashlib.sha256()

    try:
        with path.open("rb") as file:
            while True:
                chunk = file.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return None

    return digest.hexdigest()


def find_duplicates(
    root: Path,
    min_size: int = 64 * 1024,
):
    by_size: dict[int, list[Path]] = defaultdict(list)

    for current_root, dirs, files in os.walk(
        root,
        topdown=True,
        onerror=lambda _: None,
    ):
        current = Path(current_root)

        dirs[:] = [
            name
            for name in dirs
            if name not in EXCLUDED_FROM_DUPLICATE_SCAN
        ]

        if any(
            part in EXCLUDED_FROM_DUPLICATE_SCAN
            for part in current.parts
        ):
            continue

        for file_name in files:
            path = current / file_name

            try:
                size = path.stat().st_size
            except OSError:
                continue

            if size >= min_size:
                by_size[size].append(path)

    duplicates: list[
        tuple[int, str, list[Path]]
    ] = []

    for size, paths in by_size.items():
        if len(paths) < 2:
            continue

        by_hash: dict[str, list[Path]] = defaultdict(list)

        for path in paths:
            digest = file_hash(path)
            if digest:
                by_hash[digest].append(path)

        for digest, same_files in by_hash.items():
            if len(same_files) >= 2:
                duplicates.append(
                    (size, digest, same_files)
                )

    duplicates.sort(
        key=lambda item:
            item[0] * (len(item[2]) - 1),
        reverse=True,
    )

    return duplicates


def delete_path(path: Path) -> int:
    before = path_size(path)

    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()

    return before


def relative(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def print_section(title: str):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Toy SAST 프로젝트 경량화 감사 도구"
        )
    )

    parser.add_argument(
        "--delete-safe",
        action="store_true",
        help=(
            "재생성 가능한 cache/build 산출물만 삭제"
        ),
    )

    parser.add_argument(
        "--include-node-modules",
        action="store_true",
        help=(
            "--delete-safe 사용 시 frontend/node_modules도 삭제. "
            "이후 npm ci 필요."
        ),
    )

    parser.add_argument(
        "--skip-duplicates",
        action="store_true",
        help=(
            "중복 파일 SHA-256 검사를 건너뜀"
        ),
    )

    args = parser.parse_args()

    root = find_project_root()

    print("=" * 78)
    print("Toy SAST Project Cleanup Audit")
    print(f"Project root: {root}")
    print("=" * 78)

    # --------------------------------------------------------
    # Top-level sizes
    # --------------------------------------------------------

    print_section("1. Top-level size")

    top_entries = []

    for path in root.iterdir():
        if path.name == ".git":
            continue

        size = path_size(path)
        top_entries.append((size, path))

    top_entries.sort(reverse=True)

    for size, path in top_entries:
        print(
            f"{human_size(size):>12}  "
            f"{relative(root, path)}"
        )

    # --------------------------------------------------------
    # Candidates
    # --------------------------------------------------------

    (
        safe_dirs,
        safe_files,
        review_files,
        large_files,
    ) = collect_candidates(
        root,
        args.include_node_modules,
    )

    print_section(
        "2. SAFE generated candidates"
    )

    safe_total = 0

    for path in [
        *safe_dirs,
        *safe_files,
    ]:
        size = path_size(path)
        safe_total += size
        print(
            f"{human_size(size):>12}  "
            f"{relative(root, path)}"
        )

    if not safe_dirs and not safe_files:
        print("(none)")

    print()
    print(
        "Safe candidate total:",
        human_size(safe_total),
    )

    if not args.include_node_modules:
        node_modules = (
            root
            / "frontend"
            / "node_modules"
        )

        if node_modules.exists():
            node_size = path_size(
                node_modules
            )
            print()
            print(
                "[INFO] frontend/node_modules:",
                human_size(node_size),
            )
            print(
                "       재설치 가능하지만 기본 자동삭제 대상에서는 제외."
            )
            print(
                "       node_modules 내부의 package dist/는 "
                "개별 삭제하지 않습니다."
            )
            print(
                "       전체 삭제하려면 "
                "--delete-safe --include-node-modules"
            )

    # --------------------------------------------------------
    # Review files
    # --------------------------------------------------------

    print_section(
        "3. REVIEW candidates - 자동 삭제하지 않음"
    )

    if review_files:
        for path in review_files:
            print(
                f"{human_size(path_size(path)):>12}  "
                f"{relative(root, path)}"
            )
    else:
        print("(none)")

    # --------------------------------------------------------
    # Large files
    # --------------------------------------------------------

    print_section(
        "4. Large files >= 5 MB"
    )

    if large_files:
        for size, path in large_files[:50]:
            print(
                f"{human_size(size):>12}  "
                f"{relative(root, path)}"
            )
    else:
        print("(none)")

    # --------------------------------------------------------
    # Duplicate files
    # --------------------------------------------------------

    if not args.skip_duplicates:
        print_section(
            "5. Duplicate files >= 64 KB"
        )

        duplicates = find_duplicates(
            root
        )

        if not duplicates:
            print("(none)")
        else:
            for index, (
                size,
                digest,
                paths,
            ) in enumerate(
                duplicates[:30],
                start=1,
            ):
                reclaim = (
                    size
                    * (len(paths) - 1)
                )

                print(
                    f"[{index}] "
                    f"{len(paths)} copies | "
                    f"{human_size(size)} each | "
                    f"potential reclaim "
                    f"{human_size(reclaim)}"
                )

                print(
                    f"    sha256={digest}"
                )

                for path in paths:
                    print(
                        "    -",
                        relative(root, path),
                    )

                print()

    # --------------------------------------------------------
    # Safe deletion
    # --------------------------------------------------------

    if args.delete_safe:
        print_section(
            "6. Delete SAFE generated candidates"
        )

        deleted_total = 0

        # deeper path first
        targets = sorted(
            [
                *safe_dirs,
                *safe_files,
            ],
            key=lambda p:
                len(p.parts),
            reverse=True,
        )

        for path in targets:
            if not path.exists():
                continue

            size = delete_path(path)
            deleted_total += size

            print(
                "[DELETED]",
                relative(root, path),
                f"({human_size(size)})",
            )

        print()
        print(
            "Deleted total:",
            human_size(deleted_total),
        )

        if args.include_node_modules:
            print()
            print(
                "frontend/node_modules를 삭제했다면:"
            )
            print(
                "  cd frontend && npm ci"
            )

    else:
        print_section(
            "6. No deletion performed"
        )

        print(
            "현재 실행은 audit-only 입니다."
        )
        print(
            "위 SAFE 항목만 지우려면:"
        )
        print()
        print(
            "  python3 scripts/project_cleanup_audit.py "
            "--delete-safe"
        )

    print()
    print(
        "[IMPORTANT] 자동 삭제하지 않는 항목:"
    )
    print(
        "- backend/**/migrations"
    )
    print(
        "- backend/semgrep_rules"
    )
    print(
        "- Semgrep/KISA fixtures"
    )
    print(
        "- media/uploads"
    )
    print(
        "- DB / Docker volume"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
