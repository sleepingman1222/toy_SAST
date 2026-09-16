#!/usr/bin/env python3
"""
Toy SAST RFP TST-001 ~ TST-008 Automation Tester
=================================================

RFP 테스트 요구사항(TST)만을 대상으로 하는 자동화 프로그램.

검증 범위
---------
TST-001 인증 기능 시험
- 관리자/일반 사용자 로그인
- Access Token 발급
- /api/me/ 인증 확인
- 비인증 보호 API 접근 차단

TST-002 역할 권한 시험
- 일반 사용자 프로젝트 생성 차단
- 일반 사용자 분석 실행 차단
- 일반 사용자 권한 변경 차단
- 관리자 프로젝트/관리 기능 허용

TST-003 프로젝트 접근 시험
- 권한 부여 전 프로젝트 접근 차단
- 권한 부여 후 완료 분석 프로젝트 조회 허용
- 권한 회수 후 다시 접근 차단

TST-004 분석 처리 시험
- 테스트 ZIP 소스 생성/업로드
- Java / JavaScript / Python 자동 식별
- 분석 실행/상태 전이
- 진단 결과 정규화 확인

TST-005 진단 항목 시험
- KISA-SEC-06(원본 KISA 23) fixture를 실제 분석에 투입
- Java / JavaScript / Python 기대 Rule ID 탐지 확인
- 위치/메타데이터 확인
- 선택적으로 Semgrep 전체 fixture test(49 x 3) 실행

TST-006 개발보안 가이드 진단 기준 카탈로그 시험
- check_kisa_rule_catalog --full-coverage 실행
- KISA Master 49 / Rule 147 / Language 49 x 3 검증
- DB KisaSecurityWeakness 49개 필드 및 새 카탈로그 식별자 검증

TST-007 분석 결과 관리 시험
- 분석 상태/진단 결과 저장 확인
- severity / KISA identifier 기준 필터 가능한 데이터 확인
- 결과 상세 필드 확인
- KISA 진단 기준 연결 확인
- 일반 사용자 읽기 전용 결과 조회 확인

TST-008 오류 처리 시험
- 존재하지 않는 SourceVersion 분석 실행 차단
- 손상 ZIP 분석 시 오류 차단 또는 failed 상태/오류 정보 확인
- 오류 후 기존 정상 분석 결과 재조회 가능 확인

의존성
------
- Python 표준 라이브러리만 사용한다.
- requests 패키지가 필요하지 않다.
- Docker 기반 내부 검증(TST-005/006)을 위해 docker compose가 실행 가능해야 한다.
- backend / worker가 실행 중이어야 TST-004/007/008의 실제 분석 시험이 가능하다.

권장 파일 위치
--------------
backend/tests/manual/tst_automation_tester.py

실행 예
-------
python backend/tests/manual/tst_automation_tester.py

환경변수
--------
SAST_TEST_BASE_URL
SAST_TEST_ADMIN_USERNAME
SAST_TEST_ADMIN_PASSWORD

예:
export SAST_TEST_ADMIN_USERNAME=admin
export SAST_TEST_ADMIN_PASSWORD='your-password'
python backend/tests/manual/tst_automation_tester.py

종료 코드
---------
0: FAIL / ERROR 없음
1: FAIL 또는 ERROR 존재
"""

from __future__ import annotations

import argparse
import getpass
import io
import json
import mimetypes
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_HTTP_TIMEOUT = 20
DEFAULT_ANALYSIS_TIMEOUT = 300
DEFAULT_POLL_INTERVAL = 2.0
MAX_RESPONSE_PREVIEW = 800
MAX_COMMAND_OUTPUT = 6000

TERMINAL_ANALYSIS_STATUSES = {
    "completed",
    "failed",
    "cancelled",
}

EXPECTED_LANGUAGES = {
    "java",
    "javascript",
    "python",
}

KISA_IDENTIFIER_RE = re.compile(
    r"^KISA-(INP|SEC|TIM|ERR|COD|ENC|API)-\d{2}$"
)

KISA_CATEGORY_RANGES = (
    (1, 17, "INP", "입력데이터 검증 및 표현"),
    (18, 33, "SEC", "보안기능"),
    (34, 35, "TIM", "시간 및 상태"),
    (36, 38, "ERR", "에러처리"),
    (39, 43, "COD", "코드오류"),
    (44, 47, "ENC", "캡슐화"),
    (48, 49, "API", "API 오용"),
)

TST_REQUIREMENTS = {
    "TST-001": "인증 기능 시험",
    "TST-002": "역할 권한 시험",
    "TST-003": "프로젝트 접근 시험",
    "TST-004": "분석 처리 시험",
    "TST-005": "진단 항목 시험",
    "TST-006": "개발보안 가이드 진단 기준 카탈로그 시험",
    "TST-007": "분석 결과 관리 시험",
    "TST-008": "오류 처리 시험",
}

# 실제 end-to-end 분석에 사용하는 대표 fixture.
# 원본 KISA 23 = 새 서비스 카탈로그 KISA-SEC-06.
REPRESENTATIVE_FIXTURES = {
    "java": Path(
        "backend/semgrep_rules/tests/java/"
        "kisa_sw_23_hardcoded_secret.java"
    ),
    "javascript": Path(
        "backend/semgrep_rules/tests/javascript/"
        "kisa_sw_23_hardcoded_secret.js"
    ),
    "python": Path(
        "backend/semgrep_rules/tests/python/"
        "kisa_sw_23_hardcoded_secret.py"
    ),
}

EXPECTED_RULE_IDS = {
    "java": "kisa.sw23.java.hardcoded-sensitive-value",
    "javascript": "kisa.sw23.javascript.hardcoded-sensitive-value",
    "python": "kisa.sw23.python.hardcoded-sensitive-value",
}

EXPECTED_KISA_IDENTIFIER = "KISA-SEC-06"
EXPECTED_KISA_NAME = "하드코드된 중요정보"


@dataclass
class ApiResponse:
    status: int
    data: Any
    text: str
    headers: dict[str, str]


@dataclass
class TestResult:
    tst_id: str
    name: str
    status: str
    detail: str = ""
    http_status: int | None = None


@dataclass
class FixtureExpectation:
    language: str
    filename: str
    rule_id: str
    expected_line: int | None


class TstAutomationTester:
    def __init__(
        self,
        *,
        base_url: str,
        admin_username: str,
        admin_password: str,
        project_root: Path,
        backend_service: str,
        http_timeout: int,
        analysis_timeout: int,
        poll_interval: float,
        keep_artifacts: bool,
        skip_full_rule_tests: bool,
        json_report_path: Path | None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.project_root = project_root.resolve()
        self.backend_service = backend_service
        self.http_timeout = max(1, http_timeout)
        self.analysis_timeout = max(10, analysis_timeout)
        self.poll_interval = max(0.5, poll_interval)
        self.keep_artifacts = keep_artifacts
        self.skip_full_rule_tests = skip_full_rule_tests
        self.json_report_path = json_report_path

        self.results: list[TestResult] = []

        self.admin_token: str | None = None
        self.user_token: str | None = None

        self.temp_user_id: int | None = None
        self.temp_username: str | None = None
        self.temp_password: str | None = None

        self.temp_project_id: int | None = None
        self.created_access_grants: list[tuple[int, int]] = []

        self.valid_source_version_id: int | None = None
        self.valid_analysis_id: int | None = None
        self.valid_analysis_detail: dict[str, Any] | None = None

        self.invalid_source_version_id: int | None = None
        self.invalid_analysis_id: int | None = None

        self.fixture_expectations: list[FixtureExpectation] = []

        self.started_at = datetime.now(timezone.utc)

    # ============================================================
    # Result helpers
    # ============================================================

    def add_result(
        self,
        tst_id: str,
        name: str,
        status: str,
        detail: str = "",
        http_status: int | None = None,
    ) -> None:
        result = TestResult(
            tst_id=tst_id,
            name=name,
            status=status,
            detail=detail,
            http_status=http_status,
        )
        self.results.append(result)

        marker = {
            "PASS": "[PASS]",
            "FAIL": "[FAIL]",
            "SKIP": "[SKIP]",
            "ERROR": "[ERROR]",
        }.get(status, f"[{status}]")

        suffix = f" - {detail}" if detail else ""
        print(f"{marker} {tst_id} {name}{suffix}")

    def pass_result(
        self,
        tst_id: str,
        name: str,
        detail: str = "",
        http_status: int | None = None,
    ) -> None:
        self.add_result(
            tst_id,
            name,
            "PASS",
            detail,
            http_status,
        )

    def fail_result(
        self,
        tst_id: str,
        name: str,
        detail: str = "",
        http_status: int | None = None,
    ) -> None:
        self.add_result(
            tst_id,
            name,
            "FAIL",
            detail,
            http_status,
        )

    def skip_result(
        self,
        tst_id: str,
        name: str,
        detail: str = "",
    ) -> None:
        self.add_result(
            tst_id,
            name,
            "SKIP",
            detail,
        )

    def error_result(
        self,
        tst_id: str,
        name: str,
        detail: str = "",
    ) -> None:
        self.add_result(
            tst_id,
            name,
            "ERROR",
            detail,
        )

    def expect_status(
        self,
        tst_id: str,
        name: str,
        response: ApiResponse,
        expected: int | Iterable[int],
    ) -> bool:
        expected_set = (
            {expected}
            if isinstance(expected, int)
            else set(expected)
        )

        if response.status in expected_set:
            self.pass_result(
                tst_id,
                name,
                f"HTTP {response.status}",
                http_status=response.status,
            )
            return True

        self.fail_result(
            tst_id,
            name,
            (
                f"expected HTTP {sorted(expected_set)}, "
                f"got HTTP {response.status}; "
                f"response={self._preview(response)}"
            ),
            http_status=response.status,
        )
        return False

    # ============================================================
    # HTTP
    # ============================================================

    @staticmethod
    def _parse_json(text: str) -> Any:
        if not text:
            return None

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _list_from_response(data: Any) -> list[Any]:
        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            results = data.get("results")
            if isinstance(results, list):
                return results

        return []

    @staticmethod
    def _preview(response: ApiResponse) -> str:
        if response.data is not None:
            try:
                value = json.dumps(
                    response.data,
                    ensure_ascii=False,
                )
            except Exception:
                value = str(response.data)
        else:
            value = response.text

        value = value.replace("\n", " ")
        return value[:MAX_RESPONSE_PREVIEW]

    @staticmethod
    def _encode_multipart(
        fields: dict[str, str],
        files: list[tuple[str, str, bytes, str]],
    ) -> tuple[bytes, str]:
        boundary = (
            "----ToySastTstBoundary"
            + uuid.uuid4().hex
        )

        chunks: list[bytes] = []

        for name, value in fields.items():
            chunks.extend([
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; '
                    f'name="{name}"\r\n\r\n'
                ).encode(),
                str(value).encode("utf-8"),
                b"\r\n",
            ])

        for field_name, filename, content, content_type in files:
            chunks.extend([
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; '
                    f'name="{field_name}"; '
                    f'filename="{filename}"\r\n'
                ).encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode(),
                content,
                b"\r\n",
            ])

        chunks.append(
            f"--{boundary}--\r\n".encode()
        )

        body = b"".join(chunks)
        content_type = (
            f"multipart/form-data; boundary={boundary}"
        )
        return body, content_type

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json_body: Any | None = None,
        multipart_fields: dict[str, str] | None = None,
        multipart_files: list[
            tuple[str, str, bytes, str]
        ] | None = None,
    ) -> ApiResponse:
        url = f"{self.base_url}{path}"

        headers = {
            "Accept": "application/json",
        }

        body: bytes | None = None

        if multipart_fields is not None or multipart_files is not None:
            body, content_type = self._encode_multipart(
                multipart_fields or {},
                multipart_files or [],
            )
            headers["Content-Type"] = content_type

        elif json_body is not None:
            body = json.dumps(
                json_body,
                ensure_ascii=False,
            ).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if token:
            headers["Authorization"] = f"Bearer {token}"

        request = urllib.request.Request(
            url=url,
            data=body,
            headers=headers,
            method=method.upper(),
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.http_timeout,
            ) as response:
                raw = response.read()
                text = raw.decode(
                    "utf-8",
                    errors="replace",
                )
                return ApiResponse(
                    status=response.status,
                    data=self._parse_json(text),
                    text=text,
                    headers=dict(response.headers.items()),
                )

        except urllib.error.HTTPError as exc:
            raw = exc.read()
            text = raw.decode(
                "utf-8",
                errors="replace",
            )
            return ApiResponse(
                status=exc.code,
                data=self._parse_json(text),
                text=text,
                headers=dict(exc.headers.items()),
            )

        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Backend 연결 실패: {url} ({exc})"
            ) from exc

    # ============================================================
    # Docker / management commands
    # ============================================================

    def run_backend_command(
        self,
        args: list[str],
        *,
        timeout: int = 180,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "docker",
            "compose",
            "exec",
            "-T",
            self.backend_service,
            *args,
        ]

        return subprocess.run(
            command,
            cwd=self.project_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )

    @staticmethod
    def _trim_command_output(value: str) -> str:
        value = value.strip()
        if len(value) <= MAX_COMMAND_OUTPUT:
            return value
        return (
            value[:MAX_COMMAND_OUTPUT]
            + "\n...[truncated]"
        )

    # ============================================================
    # Authentication / setup
    # ============================================================

    def login(
        self,
        username: str,
        password: str,
    ) -> tuple[ApiResponse, str | None]:
        response = self.request(
            "POST",
            "/api/login/",
            json_body={
                "username": username,
                "password": password,
            },
        )

        token = None
        if isinstance(response.data, dict):
            access = response.data.get("access")
            if access:
                token = str(access)

        return response, token

    def create_temp_user(self) -> bool:
        if not self.admin_token:
            return False

        suffix = secrets.token_hex(4)
        username = f"tst_auto_{suffix}"
        password = (
            "Tst!"
            + secrets.token_urlsafe(16)
            + "a9"
        )

        response = self.request(
            "POST",
            "/api/users/",
            token=self.admin_token,
            json_body={
                "username": username,
                "password": password,
                "role": "user",
            },
        )

        if not self.expect_status(
            "TST-001",
            "관리자 - 임시 일반 사용자 생성",
            response,
            201,
        ):
            return False

        data = (
            response.data
            if isinstance(response.data, dict)
            else {}
        )
        user_id = data.get("id")

        if not isinstance(user_id, int):
            self.fail_result(
                "TST-001",
                "임시 일반 사용자 ID 확인",
                f"정수 id 없음: {self._preview(response)}",
            )
            return False

        self.temp_user_id = user_id
        self.temp_username = username
        self.temp_password = password

        self.pass_result(
            "TST-001",
            "임시 일반 사용자 ID 확인",
            f"user_id={user_id}",
        )
        return True

    def create_temp_project(self) -> bool:
        if not self.admin_token:
            return False

        suffix = secrets.token_hex(4)

        response = self.request(
            "POST",
            "/api/projects/",
            token=self.admin_token,
            json_body={
                "name": f"[TST-AUTO] {suffix}",
                "description": (
                    "RFP TST-001~008 자동화 시험용 "
                    "임시 프로젝트"
                ),
            },
        )

        if not self.expect_status(
            "TST-002",
            "관리자 - 프로젝트 생성 허용",
            response,
            201,
        ):
            return False

        data = (
            response.data
            if isinstance(response.data, dict)
            else {}
        )
        project_id = data.get("id")

        if not isinstance(project_id, int):
            self.fail_result(
                "TST-002",
                "임시 프로젝트 ID 확인",
                f"정수 id 없음: {self._preview(response)}",
            )
            return False

        self.temp_project_id = project_id

        self.pass_result(
            "TST-002",
            "임시 프로젝트 ID 확인",
            f"project_id={project_id}",
        )
        return True

    # ============================================================
    # ProjectAccess
    # ============================================================

    def grant_access(
        self,
        *,
        tst_id: str,
        test_name: str,
    ) -> bool:
        if (
            not self.admin_token
            or not self.temp_project_id
            or not self.temp_user_id
        ):
            return False

        response = self.request(
            "POST",
            (
                f"/api/projects/"
                f"{self.temp_project_id}/access/"
            ),
            token=self.admin_token,
            json_body={
                "user_id": self.temp_user_id,
            },
        )

        if not self.expect_status(
            tst_id,
            test_name,
            response,
            201,
        ):
            return False

        pair = (
            self.temp_project_id,
            self.temp_user_id,
        )
        if pair not in self.created_access_grants:
            self.created_access_grants.append(pair)

        return True

    def revoke_access(
        self,
        *,
        tst_id: str,
        test_name: str,
    ) -> bool:
        if (
            not self.admin_token
            or not self.temp_project_id
            or not self.temp_user_id
        ):
            return False

        response = self.request(
            "DELETE",
            (
                f"/api/projects/"
                f"{self.temp_project_id}/access/"
                f"{self.temp_user_id}/"
            ),
            token=self.admin_token,
        )

        if not self.expect_status(
            tst_id,
            test_name,
            response,
            {200, 204},
        ):
            return False

        pair = (
            self.temp_project_id,
            self.temp_user_id,
        )
        try:
            self.created_access_grants.remove(pair)
        except ValueError:
            pass

        return True

    # ============================================================
    # Fixture / ZIP
    # ============================================================

    @staticmethod
    def _next_code_line(
        lines: list[str],
        start_index: int,
    ) -> int | None:
        for idx in range(start_index, len(lines)):
            stripped = lines[idx].strip()
            if not stripped:
                continue
            if stripped.startswith(
                ("#", "//", "/*", "*")
            ):
                continue
            return idx + 1
        return None

    def _parse_fixture_expectation(
        self,
        language: str,
        path: Path,
    ) -> FixtureExpectation:
        text = path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        lines = text.splitlines()

        expected_rule_id = EXPECTED_RULE_IDS[language]
        expected_line = None

        for idx, line in enumerate(lines):
            if (
                "ruleid:" in line
                and expected_rule_id in line
            ):
                expected_line = self._next_code_line(
                    lines,
                    idx + 1,
                )
                break

        return FixtureExpectation(
            language=language,
            filename=path.name,
            rule_id=expected_rule_id,
            expected_line=expected_line,
        )

    def build_valid_test_zip(
        self,
    ) -> bytes | None:
        self.fixture_expectations = []

        missing: list[str] = []
        fixture_paths: dict[str, Path] = {}

        for language, relative_path in (
            REPRESENTATIVE_FIXTURES.items()
        ):
            absolute_path = (
                self.project_root / relative_path
            )
            fixture_paths[language] = absolute_path

            if not absolute_path.is_file():
                missing.append(
                    str(relative_path)
                )

        if missing:
            self.fail_result(
                "TST-004",
                "대표 진단 fixture 확인",
                "누락: " + ", ".join(missing),
            )
            return None

        buffer = io.BytesIO()

        with zipfile.ZipFile(
            buffer,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            for language, path in fixture_paths.items():
                arcname = (
                    f"samples/{language}/{path.name}"
                )
                archive.writestr(
                    arcname,
                    path.read_bytes(),
                )

                self.fixture_expectations.append(
                    self._parse_fixture_expectation(
                        language,
                        path,
                    )
                )

        self.pass_result(
            "TST-004",
            "대표 진단 fixture 확인",
            (
                "Java/JavaScript/Python "
                "KISA-SEC-06 fixture 준비 완료"
            ),
        )

        return buffer.getvalue()

    @staticmethod
    def build_corrupt_zip_bytes() -> bytes:
        return (
            b"THIS IS NOT A ZIP FILE\n"
            b"TST-008 INVALID ANALYSIS SOURCE\n"
        )

    # ============================================================
    # Source / Analysis API
    # ============================================================

    def upload_source(
        self,
        filename: str,
        content: bytes,
        *,
        tst_id: str,
        test_name: str,
        expected_status: int | Iterable[int] = 201,
    ) -> ApiResponse:
        if (
            not self.admin_token
            or not self.temp_project_id
        ):
            raise RuntimeError(
                "source upload prerequisite missing"
            )

        content_type = (
            mimetypes.guess_type(filename)[0]
            or "application/octet-stream"
        )

        response = self.request(
            "POST",
            (
                f"/api/projects/"
                f"{self.temp_project_id}/sources/"
            ),
            token=self.admin_token,
            multipart_fields={
                "source_type": "upload",
            },
            multipart_files=[
                (
                    "source_file",
                    filename,
                    content,
                    content_type,
                )
            ],
        )

        self.expect_status(
            tst_id,
            test_name,
            response,
            expected_status,
        )
        return response

    def create_analysis(
        self,
        source_version_id: int,
        *,
        tst_id: str,
        test_name: str,
        expected_status: int | Iterable[int] = 201,
        token: str | None = None,
    ) -> ApiResponse:
        if not self.temp_project_id:
            raise RuntimeError(
                "analysis project prerequisite missing"
            )

        response = self.request(
            "POST",
            (
                f"/api/projects/"
                f"{self.temp_project_id}/analyses/"
            ),
            token=(
                token
                if token is not None
                else self.admin_token
            ),
            json_body={
                "source_version_id":
                    source_version_id,
            },
        )

        self.expect_status(
            tst_id,
            test_name,
            response,
            expected_status,
        )
        return response

    def get_analysis_detail(
        self,
        analysis_id: int,
        *,
        token: str | None = None,
    ) -> ApiResponse:
        if not self.temp_project_id:
            raise RuntimeError(
                "analysis project prerequisite missing"
            )

        return self.request(
            "GET",
            (
                f"/api/projects/"
                f"{self.temp_project_id}/analyses/"
                f"{analysis_id}/"
            ),
            token=(
                token
                if token is not None
                else self.admin_token
            ),
        )

    def wait_for_analysis(
        self,
        analysis_id: int,
        *,
        tst_id: str,
        label: str,
    ) -> dict[str, Any] | None:
        deadline = (
            time.monotonic()
            + self.analysis_timeout
        )

        last_status: str | None = None

        while time.monotonic() < deadline:
            response = self.get_analysis_detail(
                analysis_id
            )

            if response.status != 200:
                self.fail_result(
                    tst_id,
                    f"{label} 상태 조회",
                    (
                        f"HTTP {response.status}: "
                        f"{self._preview(response)}"
                    ),
                    http_status=response.status,
                )
                return None

            data = (
                response.data
                if isinstance(response.data, dict)
                else {}
            )
            status_value = str(
                data.get("status") or ""
            ).lower()

            if status_value != last_status:
                print(
                    f"       {label}: "
                    f"status={status_value or '-'}"
                )
                last_status = status_value

            if status_value in TERMINAL_ANALYSIS_STATUSES:
                self.pass_result(
                    tst_id,
                    f"{label} terminal 상태 도달",
                    f"status={status_value}",
                )
                return data

            time.sleep(self.poll_interval)

        self.fail_result(
            tst_id,
            f"{label} 완료 대기",
            (
                f"{self.analysis_timeout}초 내 "
                "terminal 상태에 도달하지 못했습니다."
            ),
        )
        return None

    # ============================================================
    # TST-001
    # ============================================================

    def test_tst_001(self) -> None:
        tst_id = "TST-001"
        print(
            "\n=== TST-001 인증 기능 시험 ==="
        )

        for name, method, path in [
            (
                "비인증 /api/me/ 접근 차단",
                "GET",
                "/api/me/",
            ),
            (
                "비인증 프로젝트 목록 접근 차단",
                "GET",
                "/api/projects/",
            ),
            (
                "비인증 관리자 요약 접근 차단",
                "GET",
                "/api/admin/summary/",
            ),
        ]:
            self.expect_status(
                tst_id,
                name,
                self.request(method, path),
                {401, 403},
            )

        invalid_response, _ = self.login(
            self.admin_username,
            self.admin_password
            + "__invalid_tst_password",
        )

        self.expect_status(
            tst_id,
            "잘못된 비밀번호 로그인 차단",
            invalid_response,
            {400, 401, 403, 429},
        )

        login_response, token = self.login(
            self.admin_username,
            self.admin_password,
        )

        if not self.expect_status(
            tst_id,
            "관리자 로그인",
            login_response,
            200,
        ):
            return

        if not token:
            self.fail_result(
                tst_id,
                "관리자 인증 수단 발급",
                "로그인 응답에 access token이 없습니다.",
            )
            return

        self.admin_token = token
        self.pass_result(
            tst_id,
            "관리자 인증 수단 발급",
            "access token 발급 확인",
        )

        me = self.request(
            "GET",
            "/api/me/",
            token=self.admin_token,
        )

        if self.expect_status(
            tst_id,
            "관리자 인증 정보 검증",
            me,
            200,
        ):
            role = (
                me.data.get("role")
                if isinstance(me.data, dict)
                else None
            )
            if role == "admin":
                self.pass_result(
                    tst_id,
                    "관리자 역할 확인",
                    "role=admin",
                )
            else:
                self.fail_result(
                    tst_id,
                    "관리자 역할 확인",
                    f"expected admin, got {role!r}",
                )

        if not self.create_temp_user():
            return

        assert self.temp_username is not None
        assert self.temp_password is not None

        user_login, user_token = self.login(
            self.temp_username,
            self.temp_password,
        )

        if not self.expect_status(
            tst_id,
            "일반 사용자 로그인",
            user_login,
            200,
        ):
            return

        if not user_token:
            self.fail_result(
                tst_id,
                "일반 사용자 인증 수단 발급",
                "access token 없음",
            )
            return

        self.user_token = user_token
        self.pass_result(
            tst_id,
            "일반 사용자 인증 수단 발급",
            "access token 발급 확인",
        )

        user_me = self.request(
            "GET",
            "/api/me/",
            token=self.user_token,
        )

        if self.expect_status(
            tst_id,
            "일반 사용자 인증 정보 검증",
            user_me,
            200,
        ):
            role = (
                user_me.data.get("role")
                if isinstance(user_me.data, dict)
                else None
            )
            if role == "user":
                self.pass_result(
                    tst_id,
                    "일반 사용자 역할 확인",
                    "role=user",
                )
            else:
                self.fail_result(
                    tst_id,
                    "일반 사용자 역할 확인",
                    f"expected user, got {role!r}",
                )

    # ============================================================
    # TST-002
    # ============================================================

    def test_tst_002(self) -> None:
        tst_id = "TST-002"
        print(
            "\n=== TST-002 역할 권한 시험 ==="
        )

        if not self.admin_token or not self.user_token:
            self.skip_result(
                tst_id,
                "역할 권한 시험",
                "관리자/일반 사용자 인증 prerequisite 없음",
            )
            return

        if not self.create_temp_project():
            return

        assert self.temp_project_id is not None

        self.expect_status(
            tst_id,
            "일반 사용자 - 프로젝트 생성 제한",
            self.request(
                "POST",
                "/api/projects/",
                token=self.user_token,
                json_body={
                    "name": "forbidden-tst-project",
                    "description": "must not create",
                },
            ),
            403,
        )

        self.expect_status(
            tst_id,
            "일반 사용자 - 프로젝트 수정 제한",
            self.request(
                "PATCH",
                (
                    f"/api/projects/"
                    f"{self.temp_project_id}/"
                ),
                token=self.user_token,
                json_body={
                    "name": "forbidden-update",
                },
            ),
            {403, 404},
        )

        self.expect_status(
            tst_id,
            "일반 사용자 - 권한 변경 제한",
            self.request(
                "POST",
                (
                    f"/api/projects/"
                    f"{self.temp_project_id}/access/"
                ),
                token=self.user_token,
                json_body={
                    "user_id": self.temp_user_id,
                },
            ),
            {403, 404},
        )

        self.expect_status(
            tst_id,
            "일반 사용자 - 분석 실행 제한",
            self.request(
                "POST",
                (
                    f"/api/projects/"
                    f"{self.temp_project_id}/analyses/"
                ),
                token=self.user_token,
                json_body={
                    "source_version_id": 999999999,
                },
            ),
            {403, 404},
        )

        self.expect_status(
            tst_id,
            "관리자 - 프로젝트 수정 허용",
            self.request(
                "PATCH",
                (
                    f"/api/projects/"
                    f"{self.temp_project_id}/"
                ),
                token=self.admin_token,
                json_body={
                    "description":
                        "TST-002 관리자 수정 허용 확인",
                },
            ),
            200,
        )

        self.expect_status(
            tst_id,
            "관리자 - 관리자 요약 조회 허용",
            self.request(
                "GET",
                "/api/admin/summary/",
                token=self.admin_token,
            ),
            200,
        )

    # ============================================================
    # TST-003 pre-access
    # ============================================================

    def test_tst_003_pre_access(self) -> None:
        tst_id = "TST-003"
        print(
            "\n=== TST-003 프로젝트 접근 시험 (권한 부여 전) ==="
        )

        if (
            not self.user_token
            or not self.temp_project_id
        ):
            self.skip_result(
                tst_id,
                "권한 부여 전 프로젝트 접근",
                "필수 prerequisite 없음",
            )
            return

        self.expect_status(
            tst_id,
            "미할당 프로젝트 직접 조회 제한",
            self.request(
                "GET",
                (
                    f"/api/projects/"
                    f"{self.temp_project_id}/"
                ),
                token=self.user_token,
            ),
            {403, 404},
        )

        response = self.request(
            "GET",
            "/api/projects/",
            token=self.user_token,
        )

        if self.expect_status(
            tst_id,
            "일반 사용자 프로젝트 목록 API",
            response,
            200,
        ):
            projects = self._list_from_response(
                response.data
            )
            visible = any(
                isinstance(item, dict)
                and item.get("id")
                == self.temp_project_id
                for item in projects
            )

            if visible:
                self.fail_result(
                    tst_id,
                    "미할당 프로젝트 목록 비노출",
                    (
                        f"project_id={self.temp_project_id} "
                        "가 목록에 노출됨"
                    ),
                )
            else:
                self.pass_result(
                    tst_id,
                    "미할당 프로젝트 목록 비노출",
                    "목록에서 숨김 확인",
                )

    # ============================================================
    # TST-004
    # ============================================================

    @staticmethod
    def _extract_languages(
        analysis: dict[str, Any],
    ) -> set[str]:
        values: list[str] = []

        raw_list = (
            analysis.get("analysis_languages")
            or analysis.get("analysisLanguages")
            or []
        )

        if isinstance(raw_list, list):
            values.extend(
                str(item)
                for item in raw_list
            )
        elif isinstance(raw_list, str):
            values.extend(
                re.split(
                    r"[,/\s]+",
                    raw_list,
                )
            )

        raw_single = (
            analysis.get("analysis_language")
            or analysis.get("analysisLanguage")
            or ""
        )

        if isinstance(raw_single, str):
            values.extend(
                re.split(
                    r"[,/\s]+",
                    raw_single,
                )
            )

        normalized = {
            value.strip().lower()
            for value in values
            if value.strip()
        }

        normalized = {
            (
                "javascript"
                if item in {"js", "javascript"}
                else "python"
                if item in {"py", "python"}
                else "java"
                if item == "java"
                else item
            )
            for item in normalized
        }

        return normalized

    @staticmethod
    def _vulnerabilities_from_analysis(
        analysis: dict[str, Any],
    ) -> list[dict[str, Any]]:
        raw = analysis.get("vulnerabilities") or []
        if not isinstance(raw, list):
            return []
        return [
            item
            for item in raw
            if isinstance(item, dict)
        ]

    def test_tst_004(self) -> None:
        tst_id = "TST-004"
        print(
            "\n=== TST-004 분석 처리 시험 ==="
        )

        if (
            not self.admin_token
            or not self.temp_project_id
        ):
            self.skip_result(
                tst_id,
                "분석 처리 시험",
                "관리자/프로젝트 prerequisite 없음",
            )
            return

        zip_bytes = self.build_valid_test_zip()
        if zip_bytes is None:
            return

        upload = self.upload_source(
            "tst_valid_sources.zip",
            zip_bytes,
            tst_id=tst_id,
            test_name="테스트 소스 ZIP 업로드",
        )

        if upload.status != 201:
            return

        upload_data = (
            upload.data
            if isinstance(upload.data, dict)
            else {}
        )
        source_id = upload_data.get("id")

        if not isinstance(source_id, int):
            self.fail_result(
                tst_id,
                "SourceVersion ID 확인",
                f"id 없음: {self._preview(upload)}",
            )
            return

        self.valid_source_version_id = source_id
        self.pass_result(
            tst_id,
            "SourceVersion 생성 확인",
            f"source_version_id={source_id}",
        )

        analysis_response = self.create_analysis(
            source_id,
            tst_id=tst_id,
            test_name="정적 분석 실행 요청",
        )

        if analysis_response.status != 201:
            return

        analysis_data = (
            analysis_response.data
            if isinstance(analysis_response.data, dict)
            else {}
        )
        analysis_id = analysis_data.get("id")

        if not isinstance(analysis_id, int):
            self.fail_result(
                tst_id,
                "AnalysisRun ID 확인",
                f"id 없음: {self._preview(analysis_response)}",
            )
            return

        self.valid_analysis_id = analysis_id
        self.pass_result(
            tst_id,
            "AnalysisRun 생성 확인",
            f"analysis_id={analysis_id}",
        )

        detail = self.wait_for_analysis(
            analysis_id,
            tst_id=tst_id,
            label="정상 분석",
        )

        if detail is None:
            return

        self.valid_analysis_detail = detail

        status_value = str(
            detail.get("status") or ""
        ).lower()

        if status_value == "completed":
            self.pass_result(
                tst_id,
                "분석 완료 상태",
                "status=completed",
            )
        else:
            self.fail_result(
                tst_id,
                "분석 완료 상태",
                (
                    f"expected completed, "
                    f"got {status_value}; "
                    f"failure_reason="
                    f"{detail.get('failure_reason')!r}"
                ),
            )
            return

        languages = self._extract_languages(
            detail
        )

        if EXPECTED_LANGUAGES.issubset(
            languages
        ):
            self.pass_result(
                tst_id,
                "분석 대상 언어 자동 식별",
                (
                    "detected="
                    + ",".join(sorted(languages))
                ),
            )
        else:
            self.fail_result(
                tst_id,
                "분석 대상 언어 자동 식별",
                (
                    f"expected={sorted(EXPECTED_LANGUAGES)}, "
                    f"got={sorted(languages)}"
                ),
            )

        vulnerabilities = (
            self._vulnerabilities_from_analysis(
                detail
            )
        )

        if vulnerabilities:
            self.pass_result(
                tst_id,
                "진단 항목 실행 결과 생성",
                f"{len(vulnerabilities)} findings",
            )
        else:
            self.fail_result(
                tst_id,
                "진단 항목 실행 결과 생성",
                "취약점 결과가 0건입니다.",
            )
            return

        required_keys = {
            "id",
            "name",
            "severity",
            "confidence",
            "file_path",
            "message",
            "evidence",
            "recommendation",
        }

        sample = vulnerabilities[0]
        missing = sorted(
            key
            for key in required_keys
            if key not in sample
        )

        if missing:
            self.fail_result(
                tst_id,
                "분석 결과 표준화 필드",
                "missing=" + ",".join(missing),
            )
        else:
            self.pass_result(
                tst_id,
                "분석 결과 표준화 필드",
                "공통 취약점 필드 확인",
            )

    # ============================================================
    # TST-003 positive / revoke
    # ============================================================

    def test_tst_003_post_analysis(self) -> None:
        tst_id = "TST-003"
        print(
            "\n=== TST-003 프로젝트 접근 시험 (권한 부여/회수) ==="
        )

        if (
            not self.user_token
            or not self.temp_project_id
            or not self.valid_analysis_id
        ):
            self.skip_result(
                tst_id,
                "권한 부여 후 완료 프로젝트 조회",
                "완료 분석 prerequisite 없음",
            )
            return

        if not self.grant_access(
            tst_id=tst_id,
            test_name="관리자 - 프로젝트 접근 권한 부여",
        ):
            return

        self.expect_status(
            tst_id,
            "권한 부여 후 프로젝트 직접 조회",
            self.request(
                "GET",
                (
                    f"/api/projects/"
                    f"{self.temp_project_id}/"
                ),
                token=self.user_token,
            ),
            200,
        )

        project_list_response = self.request(
            "GET",
            "/api/projects/",
            token=self.user_token,
        )

        if self.expect_status(
            tst_id,
            "권한 부여 후 프로젝트 목록 조회",
            project_list_response,
            200,
        ):
            projects = self._list_from_response(
                project_list_response.data
            )
            visible = any(
                isinstance(item, dict)
                and item.get("id")
                == self.temp_project_id
                for item in projects
            )

            if visible:
                self.pass_result(
                    tst_id,
                    "할당 프로젝트 목록 노출",
                    f"project_id={self.temp_project_id}",
                )
            else:
                self.fail_result(
                    tst_id,
                    "할당 프로젝트 목록 노출",
                    "완료 분석 프로젝트가 목록에 없습니다.",
                )

        self.expect_status(
            tst_id,
            "권한 부여 후 완료 분석 상세 조회",
            self.get_analysis_detail(
                self.valid_analysis_id,
                token=self.user_token,
            ),
            200,
        )

        # TST-007 일반 사용자 읽기 전용 시험에서 재사용하기 위해
        # 여기서는 권한을 유지한다.
        self.pass_result(
            tst_id,
            "프로젝트 권한 유지",
            "TST-007 읽기 전용 시험 후 회수 예정",
        )

    # ============================================================
    # TST-005
    # ============================================================

    @staticmethod
    def _get_rule_id(
        vulnerability: dict[str, Any],
    ) -> str:
        return str(
            vulnerability.get("rule_id")
            or vulnerability.get("ruleId")
            or ""
        )

    @staticmethod
    def _get_identifier(
        vulnerability: dict[str, Any],
    ) -> str:
        return str(
            vulnerability.get(
                "security_weakness_identifier"
            )
            or vulnerability.get(
                "securityWeaknessIdentifier"
            )
            or ""
        )

    @staticmethod
    def _get_line(
        vulnerability: dict[str, Any],
    ) -> int | None:
        for key in (
            "start_line",
            "startLine",
            "line",
        ):
            value = vulnerability.get(key)
            if isinstance(value, int):
                return value
        return None

    @staticmethod
    def _get_file_path(
        vulnerability: dict[str, Any],
    ) -> str:
        return str(
            vulnerability.get("file_path")
            or vulnerability.get("filePath")
            or ""
        )

    @staticmethod
    def _canonicalize_semgrep_rule_id(
        rule_id: Any,
    ) -> str:
        """
        Semgrep runtime check_id를 YAML의 canonical Rule ID로 정규화한다.

        Semgrep는 --config에 디렉터리/파일 경로를 넘겨 실행할 때
        실제 check_id 앞에 config 경로 namespace를 붙일 수 있다.

        예:
        semgrep_rules.kisa.java.kisa.sw23.java.hardcoded-sensitive-value
            ->
        kisa.sw23.java.hardcoded-sensitive-value

        원본 DB 값은 변경하지 않고 tester의 비교에만 사용한다.
        """

        value = str(
            rule_id
            or ""
        ).strip()

        if not value:
            return ""

        match = re.search(
            (
                r"(kisa\.sw\d+\."
                r"(?:java|javascript|python)\."
                r".+)$"
            ),
            value,
        )

        if match is not None:
            return match.group(1)

        return value

    def _load_analysis_vulnerabilities_from_db(
        self,
        analysis_id: int,
    ) -> list[dict[str, Any]] | None:
        """
        TST-005 내부 진단 정확도 검증용 DB 조회.

        현재 API 응답 정책은 일반 사용자 응답에서
        기술적인 Semgrep Rule ID를 의도적으로 제외한다.
        TST-005는 Rule ID 자체의 정확성을 시험해야 하므로
        저장 원본인 Vulnerability.rule_id를 직접 검증한다.
        """

        shell_code = (
            "import json; "
            "from scans.models import Vulnerability; "
            f"analysis_id={int(analysis_id)}; "
            "rows=list("
            "Vulnerability.objects"
            ".filter(analysis_run_id=analysis_id)"
            ".select_related('security_weakness')"
            ".order_by('id')"
            ".values("
            "'id',"
            "'analysis_language',"
            "'rule_id',"
            "'name',"
            "'severity',"
            "'confidence',"
            "'file_path',"
            "'line',"
            "'security_weakness__identifier',"
            "'security_weakness__item_number',"
            "'security_weakness__name'"
            ")"
            "); "
            "print(json.dumps(rows, ensure_ascii=False))"
        )

        try:
            result = self.run_backend_command(
                [
                    "python",
                    "manage.py",
                    "shell",
                    "-c",
                    shell_code,
                ],
                timeout=120,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ) as exc:
            self.error_result(
                "TST-005",
                "대표 fixture DB 결과 조회",
                f"{type(exc).__name__}: {exc}",
            )
            return None

        if result.returncode != 0:
            self.fail_result(
                "TST-005",
                "대표 fixture DB 결과 조회",
                (
                    f"exit={result.returncode}\n"
                    + self._trim_command_output(
                        result.stdout
                    )
                ),
            )
            return None

        rows = self._extract_json_array_from_output(
            result.stdout
        )

        if not isinstance(rows, list):
            self.fail_result(
                "TST-005",
                "대표 fixture DB 결과 파싱",
                self._trim_command_output(
                    result.stdout
                ),
            )
            return None

        normalized = [
            row
            for row in rows
            if isinstance(row, dict)
        ]

        self.pass_result(
            "TST-005",
            "대표 fixture DB 결과 조회",
            f"{len(normalized)} findings",
        )

        return normalized

    def _test_representative_fixture_findings(
        self,
    ) -> None:
        tst_id = "TST-005"

        if not self.valid_analysis_id:
            self.skip_result(
                tst_id,
                "대표 fixture 탐지 결과",
                "정상 분석 결과 prerequisite 없음",
            )
            return

        vulnerabilities = (
            self._load_analysis_vulnerabilities_from_db(
                self.valid_analysis_id
            )
        )

        if vulnerabilities is None:
            return

        if not vulnerabilities:
            self.fail_result(
                tst_id,
                "대표 fixture 탐지 결과",
                "DB Vulnerability 결과가 0건입니다.",
            )
            return

        for expectation in self.fixture_expectations:
            candidates = [
                vuln
                for vuln in vulnerabilities
                if (
                    self._canonicalize_semgrep_rule_id(
                        vuln.get("rule_id")
                    )
                    == expectation.rule_id
                )
                and Path(
                    str(
                        vuln.get("file_path")
                        or ""
                    )
                ).name
                == expectation.filename
            ]

            label = (
                f"{expectation.language} "
                f"{expectation.rule_id}"
            )

            if not candidates:
                observed = [
                    (
                        str(
                            vuln.get("analysis_language")
                            or ""
                        ),
                        str(
                            vuln.get("rule_id")
                            or ""
                        ),
                        self._canonicalize_semgrep_rule_id(
                            vuln.get("rule_id")
                        ),
                        Path(
                            str(
                                vuln.get("file_path")
                                or ""
                            )
                        ).name,
                    )
                    for vuln in vulnerabilities
                ]

                self.fail_result(
                    tst_id,
                    f"{label} 기대 취약점 탐지",
                    (
                        "DB에서 기대 Rule ID/파일 조합을 "
                        f"찾지 못했습니다. observed={observed}"
                    ),
                )
                continue

            self.pass_result(
                tst_id,
                f"{label} 기대 취약점 탐지",
                f"{len(candidates)} finding(s)",
            )

            finding = candidates[0]

            raw_rule_id = str(
                finding.get("rule_id")
                or ""
            )
            canonical_rule_id = (
                self._canonicalize_semgrep_rule_id(
                    raw_rule_id
                )
            )

            if canonical_rule_id == expectation.rule_id:
                self.pass_result(
                    tst_id,
                    f"{label} canonical Rule ID",
                    (
                        f"raw={raw_rule_id} -> "
                        f"canonical={canonical_rule_id}"
                    ),
                )
            else:
                self.fail_result(
                    tst_id,
                    f"{label} canonical Rule ID",
                    (
                        f"raw={raw_rule_id!r}, "
                        f"canonical={canonical_rule_id!r}, "
                        f"expected={expectation.rule_id!r}"
                    ),
                )

            actual_language = str(
                finding.get("analysis_language")
                or ""
            ).lower()

            if actual_language == expectation.language:
                self.pass_result(
                    tst_id,
                    f"{label} 분석 언어",
                    f"language={actual_language}",
                )
            else:
                self.fail_result(
                    tst_id,
                    f"{label} 분석 언어",
                    (
                        f"expected={expectation.language}, "
                        f"actual={actual_language!r}"
                    ),
                )

            actual_line = finding.get("line")

            if not isinstance(actual_line, int):
                self.fail_result(
                    tst_id,
                    f"{label} 위치 정보",
                    f"line={actual_line!r}",
                )
            elif (
                expectation.expected_line is None
                or abs(
                    actual_line
                    - expectation.expected_line
                ) <= 2
            ):
                self.pass_result(
                    tst_id,
                    f"{label} 위치 정보",
                    (
                        f"actual={actual_line}, "
                        f"expected≈{expectation.expected_line}"
                    ),
                )
            else:
                self.fail_result(
                    tst_id,
                    f"{label} 위치 정보",
                    (
                        f"actual={actual_line}, "
                        f"expected≈{expectation.expected_line}"
                    ),
                )

            identifier = str(
                finding.get(
                    "security_weakness__identifier"
                )
                or ""
            )

            item_number = finding.get(
                "security_weakness__item_number"
            )

            kisa_name = str(
                finding.get(
                    "security_weakness__name"
                )
                or ""
            )

            if (
                identifier
                == EXPECTED_KISA_IDENTIFIER
                and item_number == 23
                and kisa_name == EXPECTED_KISA_NAME
            ):
                self.pass_result(
                    tst_id,
                    f"{label} KISA 메타데이터",
                    (
                        f"{identifier} · "
                        f"{kisa_name} · "
                        f"item_number={item_number}"
                    ),
                )
            else:
                self.fail_result(
                    tst_id,
                    f"{label} KISA 메타데이터",
                    (
                        f"identifier={identifier!r}, "
                        f"item_number={item_number!r}, "
                        f"name={kisa_name!r}"
                    ),
                )

            severity = str(
                finding.get("severity") or ""
            )
            confidence = str(
                finding.get("confidence") or ""
            )

            if severity and confidence:
                self.pass_result(
                    tst_id,
                    f"{label} severity/confidence",
                    (
                        f"severity={severity}, "
                        f"confidence={confidence}"
                    ),
                )
            else:
                self.fail_result(
                    tst_id,
                    f"{label} severity/confidence",
                    (
                        f"severity={severity!r}, "
                        f"confidence={confidence!r}"
                    ),
                )

    def _run_full_semgrep_fixture_tests(
        self,
    ) -> None:
        tst_id = "TST-005"

        if self.skip_full_rule_tests:
            self.skip_result(
                tst_id,
                "Semgrep 전체 fixture test",
                "--skip-full-rule-tests 옵션",
            )
            return

        all_passed = True

        for language in (
            "java",
            "javascript",
            "python",
        ):
            try:
                result = self.run_backend_command(
                    [
                        "semgrep",
                        "--test",
                        "--config",
                        (
                            f"/app/semgrep_rules/kisa/"
                            f"{language}"
                        ),
                        (
                            f"/app/semgrep_rules/tests/"
                            f"{language}"
                        ),
                    ],
                    timeout=max(
                        180,
                        self.analysis_timeout,
                    ),
                )
            except (
                OSError,
                subprocess.TimeoutExpired,
            ) as exc:
                self.error_result(
                    tst_id,
                    f"Semgrep {language} fixture test",
                    f"{type(exc).__name__}: {exc}",
                )
                all_passed = False
                continue

            if result.returncode == 0:
                self.pass_result(
                    tst_id,
                    f"Semgrep {language} fixture test",
                    "exit=0",
                )
            else:
                self.fail_result(
                    tst_id,
                    f"Semgrep {language} fixture test",
                    (
                        f"exit={result.returncode}\n"
                        + self._trim_command_output(
                            result.stdout
                        )
                    ),
                )
                all_passed = False

        if all_passed:
            self.pass_result(
                tst_id,
                "Semgrep 전체 진단 fixture",
                "Java/JavaScript/Python 전체 fixture PASS",
            )

    def test_tst_005(self) -> None:
        print(
            "\n=== TST-005 진단 항목 시험 ==="
        )
        self._test_representative_fixture_findings()
        self._run_full_semgrep_fixture_tests()

    # ============================================================
    # TST-006
    # ============================================================

    @staticmethod
    def _expected_identifier_for_item(
        item_number: int,
    ) -> tuple[str, str]:
        for (
            start,
            end,
            prefix,
            category,
        ) in KISA_CATEGORY_RANGES:
            if start <= item_number <= end:
                local_number = (
                    item_number - start + 1
                )
                return (
                    f"KISA-{prefix}-{local_number:02d}",
                    category,
                )

        raise ValueError(
            f"unsupported KISA item_number={item_number}"
        )

    @staticmethod
    def _extract_json_array_from_output(
        output: str,
    ) -> Any:
        lines = [
            line.strip()
            for line in output.splitlines()
            if line.strip()
        ]

        for line in reversed(lines):
            if line.startswith("["):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue

        return None

    def test_tst_006(self) -> None:
        tst_id = "TST-006"
        print(
            "\n=== TST-006 개발보안 가이드 진단 기준 카탈로그 시험 ==="
        )

        try:
            result = self.run_backend_command(
                [
                    "python",
                    "manage.py",
                    "check_kisa_rule_catalog",
                    "--full-coverage",
                ],
                timeout=180,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ) as exc:
            self.error_result(
                tst_id,
                "KISA Rule Catalog validator 실행",
                f"{type(exc).__name__}: {exc}",
            )
            return

        output = result.stdout

        if result.returncode == 0:
            self.pass_result(
                tst_id,
                "KISA Rule Catalog validator 실행",
                "exit=0",
            )
        else:
            self.fail_result(
                tst_id,
                "KISA Rule Catalog validator 실행",
                (
                    f"exit={result.returncode}\n"
                    + self._trim_command_output(
                        output
                    )
                ),
            )
            return

        expected_fragments = [
            "KISA Master       : 49/49",
            "Rule Files        : 147",
            "Rules             : 147",
            "KISA Covered      : 49/49",
            "- java: 49",
            "- javascript: 49",
            "- python: 49",
        ]

        missing_fragments = [
            fragment
            for fragment in expected_fragments
            if fragment not in output
        ]

        if missing_fragments:
            self.fail_result(
                tst_id,
                "KISA 49/147/언어별 coverage",
                (
                    "missing="
                    + ", ".join(missing_fragments)
                ),
            )
        else:
            self.pass_result(
                tst_id,
                "KISA 49/147/언어별 coverage",
                "49 Master / 147 Rules / 49x3 확인",
            )

        shell_code = (
            "import json; "
            "from scans.models import KisaSecurityWeakness; "
            "print(json.dumps(list("
            "KisaSecurityWeakness.objects.order_by('item_number')"
            ".values("
            "'item_number','identifier','category','name',"
            "'implementation_status'"
            ")), ensure_ascii=False))"
        )

        try:
            db_result = self.run_backend_command(
                [
                    "python",
                    "manage.py",
                    "shell",
                    "-c",
                    shell_code,
                ],
                timeout=120,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ) as exc:
            self.error_result(
                tst_id,
                "KISA Master DB 필드 조회",
                f"{type(exc).__name__}: {exc}",
            )
            return

        if db_result.returncode != 0:
            self.fail_result(
                tst_id,
                "KISA Master DB 필드 조회",
                (
                    f"exit={db_result.returncode}\n"
                    + self._trim_command_output(
                        db_result.stdout
                    )
                ),
            )
            return

        rows = self._extract_json_array_from_output(
            db_result.stdout
        )

        if not isinstance(rows, list):
            self.fail_result(
                tst_id,
                "KISA Master DB JSON 파싱",
                self._trim_command_output(
                    db_result.stdout
                ),
            )
            return

        if len(rows) == 49:
            self.pass_result(
                tst_id,
                "KISA Master DB 49개",
                "rows=49",
            )
        else:
            self.fail_result(
                tst_id,
                "KISA Master DB 49개",
                f"rows={len(rows)}",
            )

        row_errors: list[str] = []

        for row in rows:
            if not isinstance(row, dict):
                row_errors.append(
                    "non-dict row"
                )
                continue

            item_number = row.get("item_number")

            if not isinstance(item_number, int):
                row_errors.append(
                    f"invalid item_number={item_number!r}"
                )
                continue

            try:
                (
                    expected_identifier,
                    expected_category,
                ) = self._expected_identifier_for_item(
                    item_number
                )
            except ValueError as exc:
                row_errors.append(str(exc))
                continue

            identifier = str(
                row.get("identifier") or ""
            )
            category = str(
                row.get("category") or ""
            )
            name = str(
                row.get("name") or ""
            )
            implementation_status = str(
                row.get("implementation_status")
                or ""
            )

            if identifier != expected_identifier:
                row_errors.append(
                    (
                        f"item={item_number} "
                        f"identifier={identifier!r} "
                        f"expected={expected_identifier!r}"
                    )
                )

            if not KISA_IDENTIFIER_RE.match(
                identifier
            ):
                row_errors.append(
                    (
                        f"item={item_number} "
                        f"identifier syntax invalid"
                    )
                )

            if category != expected_category:
                row_errors.append(
                    (
                        f"item={item_number} "
                        f"category={category!r} "
                        f"expected={expected_category!r}"
                    )
                )

            if not name:
                row_errors.append(
                    f"item={item_number} empty name"
                )

            if not implementation_status:
                row_errors.append(
                    (
                        f"item={item_number} "
                        "empty implementation_status"
                    )
                )

        if row_errors:
            self.fail_result(
                tst_id,
                "KISA Master 식별자/분류/번호/명칭/구현상태",
                "; ".join(row_errors[:10]),
            )
        else:
            self.pass_result(
                tst_id,
                "KISA Master 식별자/분류/번호/명칭/구현상태",
                (
                    "49개 모두 새 KISA 카탈로그 "
                    "코드 체계와 일치"
                ),
            )

    # ============================================================
    # TST-007
    # ============================================================

    def test_tst_007(self) -> None:
        tst_id = "TST-007"
        print(
            "\n=== TST-007 분석 결과 관리 시험 ==="
        )

        if (
            not self.valid_analysis_id
            or not self.valid_analysis_detail
            or not self.temp_project_id
        ):
            self.skip_result(
                tst_id,
                "분석 결과 관리 시험",
                "정상 completed 분석 prerequisite 없음",
            )
            return

        detail_response = self.get_analysis_detail(
            self.valid_analysis_id
        )

        if not self.expect_status(
            tst_id,
            "관리자 분석 결과 상세 재조회",
            detail_response,
            200,
        ):
            return

        detail = (
            detail_response.data
            if isinstance(detail_response.data, dict)
            else {}
        )

        if (
            str(detail.get("status") or "").lower()
            == "completed"
        ):
            self.pass_result(
                tst_id,
                "분석 실행 상태 저장",
                "completed 상태 재조회 확인",
            )
        else:
            self.fail_result(
                tst_id,
                "분석 실행 상태 저장",
                f"status={detail.get('status')!r}",
            )

        vulnerabilities = (
            self._vulnerabilities_from_analysis(
                detail
            )
        )

        if vulnerabilities:
            self.pass_result(
                tst_id,
                "진단 결과 저장/조회",
                f"{len(vulnerabilities)} findings",
            )
        else:
            self.fail_result(
                tst_id,
                "진단 결과 저장/조회",
                "findings=0",
            )
            return

        # 조건별 필터링에 필요한 데이터가 실제로 존재하고,
        # 해당 조건으로 안정적으로 부분집합을 만들 수 있는지 검증.
        first_severity = str(
            vulnerabilities[0].get("severity") or ""
        )

        severity_filtered = [
            item
            for item in vulnerabilities
            if str(
                item.get("severity") or ""
            ) == first_severity
        ]

        if first_severity and severity_filtered:
            self.pass_result(
                tst_id,
                "심각도 조건 필터 데이터",
                (
                    f"severity={first_severity}, "
                    f"matched={len(severity_filtered)}"
                ),
            )
        else:
            self.fail_result(
                tst_id,
                "심각도 조건 필터 데이터",
                "severity 필터 기준값 없음",
            )

        first_identifier = ""

        for item in vulnerabilities:
            candidate = self._get_identifier(item)
            if candidate:
                first_identifier = candidate
                break

        identifier_filtered = [
            item
            for item in vulnerabilities
            if self._get_identifier(item)
            == first_identifier
        ]

        if (
            first_identifier
            and identifier_filtered
        ):
            self.pass_result(
                tst_id,
                "KISA 카탈로그 코드 조건 필터 데이터",
                (
                    f"identifier={first_identifier}, "
                    f"matched={len(identifier_filtered)}"
                ),
            )
        else:
            self.fail_result(
                tst_id,
                "KISA 카탈로그 코드 조건 필터 데이터",
                "KISA identifier 필터 기준값 없음",
            )

        sample = vulnerabilities[0]

        detail_fields = [
            "name",
            "severity",
            "confidence",
            "message",
            "evidence",
            "recommendation",
        ]

        missing = [
            field
            for field in detail_fields
            if field not in sample
        ]

        location_present = any(
            sample.get(key) is not None
            for key in (
                "line",
                "start_line",
                "startLine",
            )
        )

        file_path_present = bool(
            self._get_file_path(sample)
        )

        if (
            not missing
            and location_present
            and file_path_present
        ):
            self.pass_result(
                tst_id,
                "진단 결과 상세 정보",
                "파일/위치/메시지/근거/권고 필드 확인",
            )
        else:
            self.fail_result(
                tst_id,
                "진단 결과 상세 정보",
                (
                    f"missing={missing}, "
                    f"location={location_present}, "
                    f"file_path={file_path_present}"
                ),
            )

        kisa_linked = [
            item
            for item in vulnerabilities
            if self._get_identifier(item)
        ]

        if kisa_linked:
            self.pass_result(
                tst_id,
                "진단 기준 정보 연결",
                (
                    f"{len(kisa_linked)} finding(s) "
                    "KISA identifier 연결"
                ),
            )
        else:
            self.fail_result(
                tst_id,
                "진단 기준 정보 연결",
                "KISA identifier 연결 결과 없음",
            )

        if self.user_token:
            user_detail = self.get_analysis_detail(
                self.valid_analysis_id,
                token=self.user_token,
            )

            self.expect_status(
                tst_id,
                "일반 사용자 완료 분석 읽기",
                user_detail,
                200,
            )

            self.create_analysis(
                self.valid_source_version_id or 0,
                tst_id=tst_id,
                test_name="일반 사용자 분석 재실행 제한",
                expected_status={403, 404},
                token=self.user_token,
            )

            progress_response = self.request(
                "GET",
                (
                    f"/api/projects/"
                    f"{self.temp_project_id}/analyses/"
                    f"{self.valid_analysis_id}/progress/"
                ),
                token=self.user_token,
            )

            self.expect_status(
                tst_id,
                "일반 사용자 내부 progress 조회 제한",
                progress_response,
                {403, 404},
            )

        # TST-003의 권한 회수 후 차단 검증
        if self.created_access_grants:
            if self.revoke_access(
                tst_id="TST-003",
                test_name="관리자 - 프로젝트 접근 권한 회수",
            ):
                self.expect_status(
                    "TST-003",
                    "권한 회수 후 프로젝트 조회 재차단",
                    self.request(
                        "GET",
                        (
                            f"/api/projects/"
                            f"{self.temp_project_id}/"
                        ),
                        token=self.user_token,
                    ),
                    {403, 404},
                )

    # ============================================================
    # TST-008
    # ============================================================

    def test_tst_008(self) -> None:
        tst_id = "TST-008"
        print(
            "\n=== TST-008 오류 처리 시험 ==="
        )

        if (
            not self.admin_token
            or not self.temp_project_id
        ):
            self.skip_result(
                tst_id,
                "오류 처리 시험",
                "관리자/프로젝트 prerequisite 없음",
            )
            return

        bogus = self.request(
            "POST",
            (
                f"/api/projects/"
                f"{self.temp_project_id}/analyses/"
            ),
            token=self.admin_token,
            json_body={
                "source_version_id": 2147483647,
            },
        )

        self.expect_status(
            tst_id,
            "존재하지 않는 분석 대상 차단",
            bogus,
            {400, 404},
        )

        if (
            isinstance(bogus.data, dict)
            and bogus.data
        ):
            self.pass_result(
                tst_id,
                "유효하지 않은 분석 대상 오류 정보",
                self._preview(bogus),
            )
        else:
            self.fail_result(
                tst_id,
                "유효하지 않은 분석 대상 오류 정보",
                "구조화된 오류 응답이 없습니다.",
            )

        corrupt = self.build_corrupt_zip_bytes()

        upload = self.upload_source(
            "tst_corrupt_source.zip",
            corrupt,
            tst_id=tst_id,
            test_name="손상 ZIP 등록 요청",
            expected_status={201, 400, 415},
        )

        if upload.status in {400, 415}:
            self.pass_result(
                tst_id,
                "손상 ZIP 조기 차단",
                (
                    "분석 실행 전 업로드 검증 단계에서 "
                    "차단됨"
                ),
            )

        elif upload.status == 201:
            data = (
                upload.data
                if isinstance(upload.data, dict)
                else {}
            )
            source_id = data.get("id")

            if not isinstance(source_id, int):
                self.fail_result(
                    tst_id,
                    "손상 ZIP SourceVersion ID",
                    "정수 id 없음",
                )
            else:
                self.invalid_source_version_id = (
                    source_id
                )

                analysis_response = self.request(
                    "POST",
                    (
                        f"/api/projects/"
                        f"{self.temp_project_id}/analyses/"
                    ),
                    token=self.admin_token,
                    json_body={
                        "source_version_id": source_id,
                    },
                )

                if analysis_response.status in {
                    400,
                    404,
                    409,
                    422,
                }:
                    self.pass_result(
                        tst_id,
                        "손상 ZIP 분석 실행 조기 차단",
                        (
                            f"HTTP {analysis_response.status}: "
                            f"{self._preview(analysis_response)}"
                        ),
                    )
                elif analysis_response.status == 201:
                    self.pass_result(
                        tst_id,
                        "손상 ZIP AnalysisRun 생성",
                        "worker 오류 처리 lifecycle 확인",
                    )

                    analysis_data = (
                        analysis_response.data
                        if isinstance(
                            analysis_response.data,
                            dict,
                        )
                        else {}
                    )
                    analysis_id = (
                        analysis_data.get("id")
                    )

                    if isinstance(analysis_id, int):
                        self.invalid_analysis_id = (
                            analysis_id
                        )

                        detail = self.wait_for_analysis(
                            analysis_id,
                            tst_id=tst_id,
                            label="손상 ZIP 분석",
                        )

                        if detail is not None:
                            status_value = str(
                                detail.get("status")
                                or ""
                            ).lower()

                            if status_value == "failed":
                                self.pass_result(
                                    tst_id,
                                    "실행 오류 failed 상태 관리",
                                    "status=failed",
                                )
                            else:
                                self.fail_result(
                                    tst_id,
                                    "실행 오류 failed 상태 관리",
                                    (
                                        f"expected failed, "
                                        f"got {status_value}"
                                    ),
                                )

                            failure_reason = str(
                                detail.get(
                                    "failure_reason"
                                )
                                or detail.get(
                                    "failureReason"
                                )
                                or ""
                            )
                            logs = str(
                                detail.get("logs")
                                or ""
                            )

                            if failure_reason or logs:
                                self.pass_result(
                                    tst_id,
                                    "실행 오류 정보 저장",
                                    (
                                        "failure_reason/logs "
                                        "확인"
                                    ),
                                )
                            else:
                                self.fail_result(
                                    tst_id,
                                    "실행 오류 정보 저장",
                                    (
                                        "failed 결과에 "
                                        "오류 정보가 없습니다."
                                    ),
                                )

                            recheck = (
                                self.get_analysis_detail(
                                    analysis_id
                                )
                            )

                            if self.expect_status(
                                tst_id,
                                "실패 분석 재확인",
                                recheck,
                                200,
                            ):
                                recheck_status = (
                                    str(
                                        (
                                            recheck.data
                                            or {}
                                        ).get(
                                            "status"
                                        )
                                    ).lower()
                                    if isinstance(
                                        recheck.data,
                                        dict,
                                    )
                                    else ""
                                )

                                if (
                                    recheck_status
                                    == "failed"
                                ):
                                    self.pass_result(
                                        tst_id,
                                        "실패 상태 재현성",
                                        "재조회 시 failed 유지",
                                    )
                                else:
                                    self.fail_result(
                                        tst_id,
                                        "실패 상태 재현성",
                                        (
                                            f"status="
                                            f"{recheck_status!r}"
                                        ),
                                    )
                    else:
                        self.fail_result(
                            tst_id,
                            "손상 ZIP AnalysisRun ID",
                            "정수 id 없음",
                        )
                else:
                    self.fail_result(
                        tst_id,
                        "손상 ZIP 분석 실행 응답",
                        (
                            f"HTTP {analysis_response.status}: "
                            f"{self._preview(analysis_response)}"
                        ),
                    )

        # 오류 후 기존 정상 결과가 여전히 조회되는지 확인.
        if self.valid_analysis_id:
            stable = self.get_analysis_detail(
                self.valid_analysis_id
            )

            if self.expect_status(
                tst_id,
                "오류 후 기존 정상 분석 재조회",
                stable,
                200,
            ):
                data = (
                    stable.data
                    if isinstance(stable.data, dict)
                    else {}
                )
                if (
                    str(
                        data.get("status") or ""
                    ).lower()
                    == "completed"
                ):
                    self.pass_result(
                        tst_id,
                        "오류 후 정상 결과 정합성",
                        "기존 completed 결과 유지",
                    )
                else:
                    self.fail_result(
                        tst_id,
                        "오류 후 정상 결과 정합성",
                        f"status={data.get('status')!r}",
                    )

    # ============================================================
    # Cleanup
    # ============================================================

    def cleanup(self) -> None:
        print(
            "\n=== Cleanup ==="
        )

        if self.keep_artifacts:
            print(
                "[SKIP] --keep-artifacts: "
                "테스트 리소스를 유지합니다."
            )
            print(
                f"       user_id={self.temp_user_id}, "
                f"project_id={self.temp_project_id}"
            )
            return

        if not self.admin_token:
            print(
                "[WARN] 관리자 토큰이 없어 "
                "자동 정리를 수행할 수 없습니다."
            )
            return

        for project_id, user_id in list(
            reversed(self.created_access_grants)
        ):
            response = self.request(
                "DELETE",
                (
                    f"/api/projects/{project_id}/access/"
                    f"{user_id}/"
                ),
                token=self.admin_token,
            )

            if response.status in {
                200,
                204,
                404,
            }:
                print(
                    "[CLEAN] ProjectAccess 제거 "
                    f"project={project_id}, "
                    f"user={user_id}"
                )
            else:
                print(
                    "[WARN] ProjectAccess 제거 실패 "
                    f"HTTP={response.status}"
                )

        self.created_access_grants.clear()

        if self.temp_project_id is not None:
            response = self.request(
                "DELETE",
                (
                    f"/api/projects/"
                    f"{self.temp_project_id}/"
                ),
                token=self.admin_token,
            )

            if response.status in {
                200,
                204,
                404,
            }:
                print(
                    "[CLEAN] 임시 프로젝트 제거 "
                    f"project_id={self.temp_project_id}"
                )
            else:
                print(
                    "[WARN] 임시 프로젝트 제거 실패 "
                    f"HTTP={response.status} "
                    f"{self._preview(response)}"
                )

        if self.temp_user_id is not None:
            response = self.request(
                "DELETE",
                f"/api/users/{self.temp_user_id}/",
                token=self.admin_token,
            )

            if response.status in {
                200,
                204,
                404,
            }:
                print(
                    "[CLEAN] 임시 사용자 제거 "
                    f"user_id={self.temp_user_id}"
                )
            else:
                print(
                    "[WARN] 임시 사용자 제거 실패 "
                    f"HTTP={response.status} "
                    f"{self._preview(response)}"
                )

    # ============================================================
    # Report
    # ============================================================

    def summary_counts(
        self,
    ) -> dict[str, int]:
        counts = {
            "PASS": 0,
            "FAIL": 0,
            "SKIP": 0,
            "ERROR": 0,
        }

        for result in self.results:
            if result.status in counts:
                counts[result.status] += 1

        return counts

    def tst_summary(
        self,
    ) -> dict[str, dict[str, int | str]]:
        output: dict[
            str,
            dict[str, int | str],
        ] = {}

        for tst_id, title in (
            TST_REQUIREMENTS.items()
        ):
            group = [
                result
                for result in self.results
                if result.tst_id == tst_id
            ]

            counts = {
                "PASS": sum(
                    1
                    for item in group
                    if item.status == "PASS"
                ),
                "FAIL": sum(
                    1
                    for item in group
                    if item.status == "FAIL"
                ),
                "SKIP": sum(
                    1
                    for item in group
                    if item.status == "SKIP"
                ),
                "ERROR": sum(
                    1
                    for item in group
                    if item.status == "ERROR"
                ),
            }

            if (
                counts["FAIL"] > 0
                or counts["ERROR"] > 0
            ):
                overall = "FAIL"
            elif counts["PASS"] > 0:
                overall = "PASS"
            else:
                overall = "SKIP"

            output[tst_id] = {
                "title": title,
                "result": overall,
                **counts,
            }

        return output

    def print_summary(self) -> None:
        print(
            "\n"
            + "=" * 76
        )
        print(
            "RFP TST Automation Summary"
        )
        print(
            "=" * 76
        )

        for tst_id, summary in (
            self.tst_summary().items()
        ):
            print(
                f"{tst_id} "
                f"{summary['title']:<26} "
                f"{summary['result']:<5} "
                f"(PASS={summary['PASS']}, "
                f"FAIL={summary['FAIL']}, "
                f"SKIP={summary['SKIP']}, "
                f"ERROR={summary['ERROR']})"
            )

        counts = self.summary_counts()

        print(
            "-" * 76
        )
        print(
            "TOTAL "
            f"PASS={counts['PASS']} "
            f"FAIL={counts['FAIL']} "
            f"SKIP={counts['SKIP']} "
            f"ERROR={counts['ERROR']}"
        )
        print(
            "=" * 76
        )

    def write_report(self) -> None:
        if self.json_report_path is None:
            return

        finished_at = datetime.now(
            timezone.utc
        )

        payload = {
            "tester":
                "toy_sast_rfp_tst_automation",
            "base_url":
                self.base_url,
            "project_root":
                str(self.project_root),
            "started_at":
                self.started_at.isoformat(),
            "finished_at":
                finished_at.isoformat(),
            "summary":
                self.summary_counts(),
            "tst_summary":
                self.tst_summary(),
            "artifacts": {
                "temp_user_id":
                    self.temp_user_id,
                "temp_project_id":
                    self.temp_project_id,
                "valid_source_version_id":
                    self.valid_source_version_id,
                "valid_analysis_id":
                    self.valid_analysis_id,
                "invalid_source_version_id":
                    self.invalid_source_version_id,
                "invalid_analysis_id":
                    self.invalid_analysis_id,
                "kept":
                    self.keep_artifacts,
            },
            "tests": [
                asdict(result)
                for result in self.results
            ],
        }

        self.json_report_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.json_report_path.write_text(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        print(
            f"JSON report: "
            f"{self.json_report_path}"
        )

    def exit_code(self) -> int:
        return (
            1
            if any(
                result.status
                in {"FAIL", "ERROR"}
                for result in self.results
            )
            else 0
        )

    # ============================================================
    # Run
    # ============================================================

    def run(self) -> int:
        print(
            "=" * 76
        )
        print(
            "Toy SAST - RFP TST-001 ~ TST-008 Automation"
        )
        print(
            f"Backend: {self.base_url}"
        )
        print(
            f"Project root: {self.project_root}"
        )
        print(
            "=" * 76
        )

        try:
            self.test_tst_001()

            if self.admin_token and self.user_token:
                self.test_tst_002()

            if self.temp_project_id:
                self.test_tst_003_pre_access()
                self.test_tst_004()
                self.test_tst_003_post_analysis()

            self.test_tst_005()
            self.test_tst_006()
            self.test_tst_007()

            if self.temp_project_id:
                self.test_tst_008()

        except KeyboardInterrupt:
            self.error_result(
                "TST-008",
                "테스트 실행 중단",
                "사용자에 의해 중단되었습니다.",
            )

        except Exception as exc:
            self.error_result(
                "TST-008",
                "테스트 실행 예외",
                (
                    f"{type(exc).__name__}: "
                    f"{exc}"
                ),
            )

        finally:
            try:
                self.cleanup()
            except Exception as exc:
                self.error_result(
                    "TST-008",
                    "Cleanup",
                    (
                        f"{type(exc).__name__}: "
                        f"{exc}"
                    ),
                )

            self.print_summary()

            try:
                self.write_report()
            except Exception as exc:
                print(
                    "[WARN] JSON report 저장 실패: "
                    f"{type(exc).__name__}: {exc}"
                )

        return self.exit_code()


def _looks_like_project_root(
    path: Path,
) -> bool:
    """
    Toy SAST 프로젝트 root인지 확인한다.

    최소 조건:
    - backend/manage.py 존재
    - docker compose 파일 중 하나 존재

    테스트 파일이
    backend/tests/tst_automation_tester.py 또는
    backend/tests/manual/tst_automation_tester.py 어디에 있더라도
    고정 parents[n]에 의존하지 않도록 한다.
    """

    compose_candidates = (
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    )

    has_backend = (
        path / "backend" / "manage.py"
    ).is_file()

    has_compose = any(
        (path / filename).is_file()
        for filename in compose_candidates
    )

    return (
        has_backend
        and has_compose
    )


def _walk_up(
    start: Path,
) -> list[Path]:
    """
    start부터 filesystem root까지 후보 경로를 반환한다.
    """

    resolved = start.resolve()

    if resolved.is_file():
        resolved = resolved.parent

    return [
        resolved,
        *resolved.parents,
    ]


def default_project_root() -> Path:
    """
    프로젝트 root를 자동 탐색한다.

    탐색 우선순위:
    1. 현재 실행 디렉터리(Path.cwd())
    2. 이 테스트 파일의 실제 위치

    예:
      ~/toy_sast 에서 실행
        -> /home/veam2/toy_sast

      backend/tests/tst_automation_tester.py 에 위치
        -> /home/veam2/toy_sast

      backend/tests/manual/tst_automation_tester.py 에 위치
        -> /home/veam2/toy_sast
    """

    candidates: list[Path] = []

    for start in (
        Path.cwd(),
        Path(__file__).resolve(),
    ):
        for candidate in _walk_up(start):
            if candidate not in candidates:
                candidates.append(candidate)

    for candidate in candidates:
        if _looks_like_project_root(
            candidate
        ):
            return candidate

    # 탐색 실패 시 기존처럼 조용히 잘못된 위치에서
    # docker compose를 실행하지 않고, 실행 초기에
    # 명확한 진단이 가능하도록 cwd를 반환한다.
    # main 실행 시 validate_project_root()가 상세 오류를 낸다.
    return Path.cwd().resolve()


def validate_project_root(
    project_root: Path,
) -> Path:
    """
    자동 탐색 또는 --project-root로 받은 경로를 검증한다.
    """

    resolved = project_root.expanduser().resolve()

    if _looks_like_project_root(
        resolved
    ):
        return resolved

    compose_candidates = (
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    )

    compose_text = ", ".join(
        compose_candidates
    )

    raise SystemExit(
        "Toy SAST 프로젝트 root를 찾지 못했습니다.\\n"
        f"현재 후보: {resolved}\\n"
        "다음 파일이 함께 존재하는 디렉터리를 "
        "프로젝트 root로 사용해야 합니다.\\n"
        "  - backend/manage.py\\n"
        f"  - {compose_text}\\n\\n"
        "프로젝트 루트에서 실행하거나 다음처럼 지정하세요.\\n"
        "  python3 backend/tests/tst_automation_tester.py "
        "--project-root ~/toy_sast"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Toy SAST RFP TST-001~TST-008 "
            "자동화 시험"
        ),
    )

    parser.add_argument(
        "--base-url",
        default=os.environ.get(
            "SAST_TEST_BASE_URL",
            DEFAULT_BASE_URL,
        ),
        help=(
            "Backend base URL "
            f"(default: {DEFAULT_BASE_URL})"
        ),
    )

    parser.add_argument(
        "--admin-username",
        default=os.environ.get(
            "SAST_TEST_ADMIN_USERNAME",
            "",
        ),
        help=(
            "관리자 username "
            "(기본: SAST_TEST_ADMIN_USERNAME)"
        ),
    )

    parser.add_argument(
        "--admin-password",
        default=os.environ.get(
            "SAST_TEST_ADMIN_PASSWORD",
            "",
        ),
        help=(
            "관리자 password. "
            "명령행 노출을 피하려면 "
            "환경변수/프롬프트 사용 권장."
        ),
    )

    parser.add_argument(
        "--project-root",
        type=Path,
        default=default_project_root(),
        help=(
            "toy_sast 프로젝트 root. "
            "기본값은 이 파일 위치에서 자동 계산."
        ),
    )

    parser.add_argument(
        "--backend-service",
        default="backend",
        help=(
            "docker compose backend service name "
            "(default: backend)"
        ),
    )

    parser.add_argument(
        "--http-timeout",
        type=int,
        default=DEFAULT_HTTP_TIMEOUT,
        help=(
            "개별 HTTP timeout seconds "
            f"(default: {DEFAULT_HTTP_TIMEOUT})"
        ),
    )

    parser.add_argument(
        "--analysis-timeout",
        type=int,
        default=DEFAULT_ANALYSIS_TIMEOUT,
        help=(
            "AnalysisRun terminal 상태 대기 최대 seconds "
            f"(default: {DEFAULT_ANALYSIS_TIMEOUT})"
        ),
    )

    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help=(
            "AnalysisRun polling interval seconds "
            f"(default: {DEFAULT_POLL_INTERVAL})"
        ),
    )

    parser.add_argument(
        "--skip-full-rule-tests",
        action="store_true",
        help=(
            "Semgrep --test 기반 Java/JS/Python "
            "전체 fixture 시험을 건너뜁니다. "
            "대표 end-to-end fixture 시험은 유지됩니다."
        ),
    )

    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help=(
            "임시 사용자/프로젝트/분석 결과를 "
            "자동 삭제하지 않습니다."
        ),
    )

    parser.add_argument(
        "--json-report",
        type=Path,
        default=None,
        help=(
            "결과 JSON 저장 경로. "
            "예: tst-report.json"
        ),
    )

    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help=(
            "관리자 credential 입력 프롬프트를 "
            "사용하지 않습니다."
        ),
    )

    return parser.parse_args()


def resolve_admin_credentials(
    args: argparse.Namespace,
) -> tuple[str, str]:
    username = args.admin_username.strip()
    password = args.admin_password

    if not username:
        if args.non_interactive:
            raise SystemExit(
                "관리자 username이 필요합니다. "
                "--admin-username 또는 "
                "SAST_TEST_ADMIN_USERNAME을 설정하세요."
            )

        username = input(
            "Admin username: "
        ).strip()

    if not password:
        if args.non_interactive:
            raise SystemExit(
                "관리자 password가 필요합니다. "
                "--admin-password 또는 "
                "SAST_TEST_ADMIN_PASSWORD를 설정하세요."
            )

        password = getpass.getpass(
            "Admin password: "
        )

    if not username or not password:
        raise SystemExit(
            "관리자 username/password가 비어 있습니다."
        )

    return username, password


def main() -> int:
    args = parse_args()

    username, password = (
        resolve_admin_credentials(
            args
        )
    )

    project_root = validate_project_root(
        args.project_root
    )

    tester = TstAutomationTester(
        base_url=args.base_url,
        admin_username=username,
        admin_password=password,
        project_root=project_root,
        backend_service=args.backend_service,
        http_timeout=args.http_timeout,
        analysis_timeout=args.analysis_timeout,
        poll_interval=args.poll_interval,
        keep_artifacts=args.keep_artifacts,
        skip_full_rule_tests=(
            args.skip_full_rule_tests
        ),
        json_report_path=args.json_report,
    )

    return tester.run()


if __name__ == "__main__":
    sys.exit(main())
