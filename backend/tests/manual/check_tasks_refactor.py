#!/usr/bin/env python3
"""
Phase 2B scans.tasks cleanup smoke checker.

Host:
    python3 backend/tests/manual/check_tasks_refactor.py

Docker:
    docker compose exec backend \
    python tests/manual/check_tasks_refactor.py
"""

from __future__ import annotations

import os
import sys

from pathlib import Path


def find_backend_root() -> Path:

    starts = [
        Path.cwd().resolve(),
        Path(__file__).resolve().parent,
    ]

    checked = []

    for start in starts:

        for candidate in [
            start,
            *start.parents,
        ]:

            if candidate in checked:
                continue

            checked.append(
                candidate
            )

            if (
                candidate
                / "manage.py"
            ).is_file():

                return candidate

            nested_backend = (
                candidate
                / "backend"
            )

            if (
                nested_backend
                / "manage.py"
            ).is_file():

                return nested_backend

    raise RuntimeError(
        "Django backend root를 찾을 수 없습니다."
    )


BACKEND_ROOT = (
    find_backend_root()
)

if str(BACKEND_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(BACKEND_ROOT),
    )


os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    "config.settings",
)


import django

django.setup()


from scans import tasks


REQUIRED_TASKS = {
    "run_analysis":
        "scans.tasks.run_analysis",

    "run_analysis_chunk":
        tasks.ANALYSIS_CHUNK_TASK_NAME,

    "dispatch_analysis_outboxes":
        "scans.tasks.dispatch_analysis_outboxes",

    "run_analysis_recovery":
        "scans.tasks.run_analysis_recovery",
}


REQUIRED_RUNTIME_HELPERS = [
    "dispatch_available_outboxes",
    "get_snapshot_languages",
    "record_analysis_start_failure",
    "prepare_analysis_target",
    "materialize_analysis_workspace",
    "get_semgrep_rule_path",
    "execute_semgrep_with_heartbeat",
]


REMOVED_COMPATIBILITY_EXPORTS = [
    "detect_languages",
    "execute_semgrep",
    "execute_semgrep_for_languages",
    "save_vulnerabilities",
    "normalize_zip_member_path",
    "safely_extract_zip",
    "build_vulnerability",
]


def main() -> int:

    missing = [
        name
        for name
        in REQUIRED_RUNTIME_HELPERS
        if not callable(
            getattr(
                tasks,
                name,
                None,
            )
        )
    ]

    if missing:

        print(
            "[FAIL] required runtime helpers missing:",
            ", ".join(
                missing
            ),
        )

        return 1


    for (
        attribute_name,
        expected_name,
    ) in REQUIRED_TASKS.items():

        task = getattr(
            tasks,
            attribute_name,
            None,
        )

        if task is None:

            print(
                "[FAIL] task missing:",
                attribute_name,
            )

            return 1


        actual_name = getattr(
            task,
            "name",
            None,
        )

        if actual_name != expected_name:

            print(
                "[FAIL]",
                attribute_name,
                "task name:",
                actual_name,
                "expected:",
                expected_name,
            )

            return 1


    stale_exports = [
        name
        for name
        in REMOVED_COMPATIBILITY_EXPORTS
        if hasattr(
            tasks,
            name,
        )
    ]

    if stale_exports:

        print(
            "[FAIL] stale compatibility exports remain:",
            ", ".join(
                stale_exports
            ),
        )

        return 1


    print(
        "[PASS] Django backend root:",
        BACKEND_ROOT,
    )

    print(
        "[PASS] scans.tasks import"
    )

    print(
        "[PASS] runtime orchestration imports"
    )

    print(
        "[PASS] Celery task names"
    )

    print(
        "[PASS] stale compatibility exports removed"
    )

    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
