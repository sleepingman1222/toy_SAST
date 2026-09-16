# backend/scans/services/chunk_runtime.py

import hashlib
import json
import subprocess
import tempfile
import time

from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from django.db import transaction

from ..constants import CHUNK_HEARTBEAT_INTERVAL_SECONDS
from ..models import (
    AnalysisChunk,
    AnalysisChunkAttempt,
    AnalysisChunkFile,
    AnalysisRun,
    Vulnerability,
)
from .chunk_executor import heartbeat_attempt
from .execution_utils import truncate_log
from .semgrep_executor import SEMGREP_TIMEOUT
from .source_snapshot import get_analysis_workspace_source_root
from .vulnerability_writer import build_vulnerability, get_display_file_path


class ChunkOwnershipLostError(
    RuntimeError
):

    pass

class NonRetryableChunkError(
    RuntimeError
):

    pass

def normalize_chunk_relative_path(
    relative_path
):

    value = str(
        relative_path
        or ""
    )


    if not value:

        raise NonRetryableChunkError(
            "Chunk File 상대 경로가 비어 있습니다."
        )


    if (
        "\\" in value
        or
        "\x00" in value
    ):

        raise NonRetryableChunkError(
            "Chunk File 경로에 허용되지 않는 문자가 "
            "포함되어 있습니다."
        )


    posix_path = PurePosixPath(
        value
    )


    if posix_path.is_absolute():

        raise NonRetryableChunkError(
            "Chunk File에 절대 경로를 사용할 수 없습니다."
        )


    normalized_parts = []


    for part in posix_path.parts:

        if part in (
            "",
            ".",
        ):

            continue


        if part == "..":

            raise NonRetryableChunkError(
                "Chunk File 경로에 상위 경로 이동(..)이 "
                "포함되어 있습니다."
            )


        normalized_parts.append(
            part
        )


    if not normalized_parts:

        raise NonRetryableChunkError(
            "Chunk File 상대 경로가 올바르지 않습니다."
        )


    return PurePosixPath(
        *normalized_parts
    )

def copy_verified_chunk_file(
    chunk_file,
    workspace_source_root,
    execution_source_root,
):

    relative_path = (
        normalize_chunk_relative_path(
            chunk_file.relative_path
        )
    )


    if (
        chunk_file.file_class
        ==
        AnalysisChunkFile.FileClass.OVERSIZED
    ):

        raise NonRetryableChunkError(
            "실행 가능한 Chunk에 Oversized File이 "
            "포함되어 있습니다. "
            f"file={relative_path}"
        )


    expected_hash = str(
        chunk_file.content_sha256
        or ""
    ).lower()


    if (
        len(expected_hash)
        !=
        64
    ):

        raise NonRetryableChunkError(
            "Chunk File SHA-256 Snapshot이 올바르지 않습니다. "
            f"file={relative_path}"
        )


    source_path = (
        workspace_source_root
        /
        Path(
            *relative_path.parts
        )
    )


    if source_path.is_symlink():

        raise NonRetryableChunkError(
            "Workspace Source에 Symbolic Link가 감지되었습니다. "
            f"file={relative_path}"
        )


    try:

        resolved_source_path = (
            source_path.resolve(
                strict=True
            )
        )

    except (
        OSError,
        RuntimeError,
    ) as error:

        raise NonRetryableChunkError(
            "Workspace Source File을 찾을 수 없습니다. "
            f"file={relative_path}, "
            f"error={error}"
        )


    try:

        resolved_source_path.relative_to(
            workspace_source_root
        )

    except ValueError:

        raise NonRetryableChunkError(
            "Workspace Source File이 허용 경로를 벗어났습니다. "
            f"file={relative_path}"
        )


    if not resolved_source_path.is_file():

        raise NonRetryableChunkError(
            "Workspace Source가 일반 파일이 아닙니다. "
            f"file={relative_path}"
        )


    try:

        before_stat = (
            resolved_source_path.stat()
        )

    except OSError as error:

        raise NonRetryableChunkError(
            "Workspace Source File 정보를 읽을 수 없습니다. "
            f"file={relative_path}, "
            f"error={error}"
        )


    if (
        before_stat.st_size
        !=
        chunk_file.size_bytes
    ):

        raise NonRetryableChunkError(
            "Workspace Source File 크기가 Snapshot과 "
            "일치하지 않습니다. "
            f"file={relative_path}"
        )


    destination_path = (
        execution_source_root
        /
        Path(
            *relative_path.parts
        )
    )


    try:

        destination_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    except OSError as error:

        raise RuntimeError(
            "Chunk 실행 Directory를 생성할 수 없습니다. "
            f"error={error}"
        )


    sha256 = hashlib.sha256()

    copied_size = 0


    try:

        with (
            resolved_source_path.open(
                mode="rb"
            )
            as source_file,

            destination_path.open(
                mode="xb"
            )
            as destination_file
        ):

            while True:

                data = (
                    source_file.read(
                        1024
                        * 1024
                    )
                )


                if not data:

                    break


                destination_file.write(
                    data
                )


                sha256.update(
                    data
                )


                copied_size += (
                    len(
                        data
                    )
                )


        destination_path.chmod(
            0o600
        )

    except OSError as error:

        raise RuntimeError(
            "Chunk 실행용 Source File을 복사할 수 없습니다. "
            f"file={relative_path}, "
            f"error={error}"
        )


    if (
        copied_size
        !=
        chunk_file.size_bytes
    ):

        raise NonRetryableChunkError(
            "Chunk 실행용 Source File 크기가 Snapshot과 "
            "일치하지 않습니다. "
            f"file={relative_path}"
        )


    actual_hash = (
        sha256.hexdigest()
    )


    if (
        actual_hash
        !=
        expected_hash
    ):

        raise NonRetryableChunkError(
            "Workspace Source File SHA-256이 Snapshot과 "
            "일치하지 않습니다. "
            f"file={relative_path}"
        )


    try:

        after_stat = (
            resolved_source_path.stat()
        )

    except OSError as error:

        raise NonRetryableChunkError(
            "Chunk 복사 후 Workspace Source 정보를 "
            "확인할 수 없습니다. "
            f"file={relative_path}, "
            f"error={error}"
        )


    if (
        before_stat.st_size
        !=
        after_stat.st_size
        or
        before_stat.st_mtime_ns
        !=
        after_stat.st_mtime_ns
    ):

        raise NonRetryableChunkError(
            "Chunk 실행 준비 중 Workspace Source File이 "
            "변경되었습니다. "
            f"file={relative_path}"
        )


    return destination_path

@contextmanager
def prepare_chunk_execution_target(
    chunk
):

    workspace_source_root = (
        get_analysis_workspace_source_root(
            chunk.analysis_run_id
        )
    )


    try:

        workspace_source_root = (
            workspace_source_root.resolve(
                strict=True
            )
        )

    except (
        OSError,
        RuntimeError,
    ) as error:

        raise NonRetryableChunkError(
            "Analysis Workspace Source를 찾을 수 없습니다. "
            f"error={error}"
        )


    if not workspace_source_root.is_dir():

        raise NonRetryableChunkError(
            "Analysis Workspace Source가 올바른 "
            "Directory가 아닙니다."
        )


    chunk_files = list(
        chunk.files
        .all()
        .order_by(
            "id"
        )
    )


    if not chunk_files:

        raise NonRetryableChunkError(
            "Chunk에 분석할 Source File이 없습니다."
        )


    if (
        len(chunk_files)
        !=
        chunk.file_count
    ):

        raise NonRetryableChunkError(
            "Chunk File Count가 DB Snapshot과 "
            "일치하지 않습니다."
        )


    actual_total_bytes = sum(
        chunk_file.size_bytes
        for chunk_file
        in chunk_files
    )


    if (
        actual_total_bytes
        !=
        chunk.total_bytes
    ):

        raise NonRetryableChunkError(
            "Chunk Total Bytes가 DB Snapshot과 "
            "일치하지 않습니다."
        )


    with tempfile.TemporaryDirectory(
        prefix=(
            f"sast_chunk_"
            f"{chunk.id}_"
        )
    ) as temp_directory:

        execution_source_root = (
            Path(
                temp_directory
            )
            /
            "source"
        )


        execution_source_root.mkdir(
            parents=True,
            exist_ok=False,
        )


        for chunk_file in chunk_files:

            copy_verified_chunk_file(
                chunk_file,
                workspace_source_root,
                execution_source_root,
            )


        yield execution_source_root

def terminate_semgrep_process(
    process
):

    if process.poll() is not None:

        return


    try:

        process.terminate()


        process.wait(
            timeout=5
        )

    except subprocess.TimeoutExpired:

        process.kill()


        process.wait()

    except OSError:

        pass

def execute_semgrep_with_heartbeat(
    target_path,
    rule_path,
    attempt_id,
    execution_token,
):

    command = [
        "semgrep",
        "scan",

        "--config",
        str(
            rule_path
        ),

        "--metrics=off",
        "--json",

        str(
            target_path
        ),
    ]


    try:

        with (
            tempfile.TemporaryFile(
                mode="w+t",
                encoding="utf-8",
            )
            as stdout_file,

            tempfile.TemporaryFile(
                mode="w+t",
                encoding="utf-8",
            )
            as stderr_file
        ):

            try:

                process = subprocess.Popen(
                    command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    text=True,
                )

            except OSError as error:

                raise RuntimeError(
                    "Semgrep을 실행할 수 없습니다. "
                    f"{error}"
                )


            started_monotonic = (
                time.monotonic()
            )


            last_heartbeat_monotonic = (
                started_monotonic
            )


            while True:

                return_code = (
                    process.poll()
                )


                if return_code is not None:

                    break


                current_monotonic = (
                    time.monotonic()
                )


                if (
                    current_monotonic
                    -
                    started_monotonic
                    >
                    SEMGREP_TIMEOUT
                ):

                    terminate_semgrep_process(
                        process
                    )


                    raise RuntimeError(
                        "Semgrep 분석 시간이 초과되었습니다."
                    )


                if (
                    current_monotonic
                    -
                    last_heartbeat_monotonic
                    >=
                    CHUNK_HEARTBEAT_INTERVAL_SECONDS
                ):

                    heartbeat_result = (
                        heartbeat_attempt(
                            attempt_id,
                            execution_token,
                        )
                    )


                    if not heartbeat_result.get(
                        "updated"
                    ):

                        terminate_semgrep_process(
                            process
                        )


                        raise ChunkOwnershipLostError(
                            "Chunk Attempt 실행권을 잃어 "
                            "Semgrep 실행을 중단합니다. "
                            f"reason="
                            f"{heartbeat_result.get('reason')}"
                        )


                    last_heartbeat_monotonic = (
                        current_monotonic
                    )


                time.sleep(
                    1
                )


            stdout_file.seek(
                0
            )


            stderr_file.seek(
                0
            )


            stdout = (
                stdout_file.read()
                or ""
            ).strip()


            stderr = (
                stderr_file.read()
                or ""
            ).strip()


    except ChunkOwnershipLostError:

        raise


    if not stdout:

        raise RuntimeError(
            "Semgrep이 JSON 결과를 반환하지 않았습니다."
            + (
                "\n"
                + truncate_log(
                    stderr
                )
                if stderr
                else ""
            )
        )


    try:

        raw_result = json.loads(
            stdout
        )

    except json.JSONDecodeError:

        raise RuntimeError(
            "Semgrep 결과를 JSON으로 해석할 수 없습니다."
            + (
                "\n"
                + truncate_log(
                    stderr
                )
                if stderr
                else ""
            )
        )


    if return_code != 0:

        error_message = (
            stderr
            or
            raw_result.get(
                "errors"
            )
            or
            "알 수 없는 Semgrep 오류"
        )


        raise RuntimeError(
            "Semgrep 분석에 실패했습니다.\n"
            + truncate_log(
                str(
                    error_message
                )
            )
        )


    return {
        "raw_result":
            raw_result,

        "logs":
            truncate_log(
                stderr
            ),
    }

def build_vulnerability_fingerprint(
    semgrep_result,
    analysis_target
):

    rule_id = str(
        semgrep_result.get(
            "check_id"
        )
        or
        "unknown-rule"
    )


    file_path = (
        get_display_file_path(
            semgrep_result,
            analysis_target,
        )
    )


    start = (
        semgrep_result.get(
            "start"
        )
        or {}
    )


    end = (
        semgrep_result.get(
            "end"
        )
        or {}
    )


    payload = {
        "rule_id":
            rule_id,

        "file_path":
            str(
                file_path
            ).replace(
                "\\",
                "/",
            ),

        "start_line":
            start.get(
                "line"
            ),

        "start_col":
            start.get(
                "col"
            ),

        "end_line":
            end.get(
                "line"
            ),

        "end_col":
            end.get(
                "col"
            ),
    }


    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    )


    return (
        hashlib.sha256(
            serialized.encode(
                "utf-8"
            )
        )
        .hexdigest()
    )

def build_attempt_vulnerability(
    analysis_run,
    analysis_attempt,
    semgrep_result,
    analysis_target,
    analysis_language,
):

    vulnerability = (
        build_vulnerability(
            analysis_run,
            semgrep_result,
            analysis_target,
            analysis_language,
        )
    )


    vulnerability.analysis_attempt = (
        analysis_attempt
    )


    vulnerability.fingerprint = (
        build_vulnerability_fingerprint(
            semgrep_result,
            analysis_target,
        )
    )


    return vulnerability

def save_attempt_vulnerabilities(
    analysis_run_id,
    attempt_id,
    execution_token,
    raw_result,
    analysis_target,
    analysis_language,
):

    try:

        analysis_run = (
            AnalysisRun.objects
            .get(
                pk=
                    analysis_run_id
            )
        )


        analysis_attempt = (
            AnalysisChunkAttempt.objects
            .select_related(
                "chunk"
            )
            .get(
                pk=
                    attempt_id
            )
        )

    except (
        AnalysisRun.DoesNotExist,
        AnalysisChunkAttempt.DoesNotExist,
    ):

        raise ChunkOwnershipLostError(
            "취약점 저장 전에 AnalysisRun 또는 "
            "AnalysisChunkAttempt를 찾을 수 없습니다."
        )


    results = (
        raw_result.get(
            "results"
        )
        or []
    )


    vulnerability_objects = []


    for semgrep_result in results:

        vulnerability_objects.append(
            build_attempt_vulnerability(
                analysis_run,
                analysis_attempt,
                semgrep_result,
                analysis_target,
                analysis_language,
            )
        )


    # ====================================
    # 실제 DB Publish 전 실행권 재확인
    # ====================================

    with transaction.atomic():

        locked_analysis_run = (
            AnalysisRun.objects
            .select_for_update()
            .get(
                pk=
                    analysis_run_id
            )
        )


        locked_chunk = (
            AnalysisChunk.objects
            .select_for_update()
            .get(
                pk=
                    analysis_attempt.chunk_id
            )
        )


        locked_attempt = (
            AnalysisChunkAttempt.objects
            .select_for_update()
            .get(
                pk=
                    attempt_id
            )
        )


        if (
            locked_analysis_run.status
            !=
            AnalysisRun.Status.RUNNING
        ):

            raise ChunkOwnershipLostError(
                "AnalysisRun이 더 이상 running 상태가 아닙니다."
            )


        if (
            locked_chunk.status
            !=
            AnalysisChunk.Status.RUNNING
        ):

            raise ChunkOwnershipLostError(
                "AnalysisChunk가 더 이상 running 상태가 아닙니다."
            )


        if (
            locked_attempt.status
            !=
            AnalysisChunkAttempt.Status.RUNNING
        ):

            raise ChunkOwnershipLostError(
                "AnalysisChunkAttempt가 더 이상 running 상태가 아닙니다."
            )


        if (
            str(
                locked_attempt.execution_token
            )
            !=
            str(
                execution_token
                or ""
            )
        ):

            raise ChunkOwnershipLostError(
                "AnalysisChunkAttempt execution_token이 "
                "일치하지 않습니다."
            )


        # --------------------------------
        # 같은 Attempt 안의 이전 Partial 결과는
        # 현재 결과로 원자적으로 교체한다.
        # --------------------------------

        locked_attempt.vulnerabilities.all().delete()


        for vulnerability in vulnerability_objects:

            vulnerability.analysis_run = (
                locked_analysis_run
            )


            vulnerability.analysis_attempt = (
                locked_attempt
            )


        if vulnerability_objects:

            Vulnerability.objects.bulk_create(
                vulnerability_objects
            )


    return len(
        vulnerability_objects
    )
