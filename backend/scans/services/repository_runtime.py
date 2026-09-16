import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from django.db import transaction
from django.utils import timezone

from ..constants import (
    MAX_ANALYZABLE_FILE_BYTES,
    REPOSITORY_ARTIFACT_SAFETY_MARGIN_BYTES,
    REPOSITORY_MAX_ARTIFACT_BYTES,
    REPOSITORY_MAX_TARGET_BYTES,
    REPOSITORY_SCAN_JOBS,
    REPOSITORY_SCAN_MAX_MEMORY_MIB,
    REPOSITORY_SCAN_TIMEOUT_SECONDS,
)
from ..models import ScanArtifact, ScanAttempt
from .repository_manifest import load_repository_manifest
from .semgrep_executor import get_semgrep_rule_path
from .source_snapshot import (
    get_analysis_workspace_run_root,
    get_analysis_workspace_source_root,
)


SEMGREP_PINNED_VERSION = "1.175.0"


class RepositoryRuntimeError(RuntimeError):
    pass


def build_repository_semgrep_command(source_root, languages):
    source_root = Path(source_root).resolve(strict=True)
    if MAX_ANALYZABLE_FILE_BYTES != REPOSITORY_MAX_TARGET_BYTES:
        raise RepositoryRuntimeError("max target bytes does not match snapshot policy")
    command = ["semgrep", "--json", "--metrics=off"]
    for language in languages:
        command.extend(["--config", str(Path(get_semgrep_rule_path(language)).resolve(strict=True))])
    command.extend([
        "--jobs", str(REPOSITORY_SCAN_JOBS),
        "--timeout", str(REPOSITORY_SCAN_TIMEOUT_SECONDS),
        "--max-memory", str(REPOSITORY_SCAN_MAX_MEMORY_MIB),
        "--max-target-bytes", str(REPOSITORY_MAX_TARGET_BYTES),
        str(source_root),
    ])
    return command


def _verify_semgrep_pin():
    result = subprocess.run(
        ["semgrep", "--version"], capture_output=True, text=True, timeout=15, check=False
    )
    version = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    if result.returncode != 0 or SEMGREP_PINNED_VERSION not in version:
        raise RepositoryRuntimeError(
            f"Semgrep pin mismatch: expected {SEMGREP_PINNED_VERSION}, received {version or 'unknown'}"
        )


def _terminate_process_group(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def _artifact_root(run_id):
    root = get_analysis_workspace_run_root(run_id) / "artifacts"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def _publish_artifact(attempt, temporary_path):
    size = temporary_path.stat().st_size
    if size <= 0 or size > REPOSITORY_MAX_ARTIFACT_BYTES:
        raise RepositoryRuntimeError("raw artifact size is outside configured bounds")
    digest = hashlib.sha256(temporary_path.read_bytes()).hexdigest()
    try:
        payload = json.loads(temporary_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RepositoryRuntimeError("Semgrep output is not valid JSON") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("results", []), list):
        raise RepositoryRuntimeError("Semgrep output schema is invalid")

    final_name = f"semgrep-attempt-{attempt.attempt_no}.json"
    final_path = temporary_path.parent / final_name
    os.replace(temporary_path, final_path)
    final_path.chmod(0o600)
    relative_path = final_path.relative_to(get_analysis_workspace_run_root(
        attempt.execution.analysis_run_id
    )).as_posix()

    with transaction.atomic():
        locked = ScanAttempt.objects.select_for_update().get(pk=attempt.pk)
        if locked.status != ScanAttempt.Status.RUNNING or locked.execution_token != attempt.execution_token:
            final_path.unlink(missing_ok=True)
            raise RepositoryRuntimeError("engine ownership was lost before artifact publication")
        artifact = ScanArtifact.objects.create(
            execution=locked.execution,
            attempt=locked,
            kind=ScanArtifact.Kind.SEMGREP_JSON,
            state=ScanArtifact.State.READY,
            is_canonical=True,
            relative_path=relative_path,
            sha256=digest,
            size_bytes=size,
            schema_version=1,
            content_type="application/json",
            published_at=timezone.now(),
        )
    return artifact


def execute_repository_scan(attempt):
    execution = attempt.execution
    run_id = execution.analysis_run_id
    source_root = get_analysis_workspace_source_root(run_id).resolve(strict=True)
    load_repository_manifest(run_id)
    expected_root = get_analysis_workspace_source_root(run_id).resolve(strict=True)
    if source_root != expected_root:
        raise RepositoryRuntimeError("repository scan root is not the immutable workspace")

    usage = shutil.disk_usage(_artifact_root(run_id))
    required = REPOSITORY_MAX_ARTIFACT_BYTES + REPOSITORY_ARTIFACT_SAFETY_MARGIN_BYTES
    if usage.free < required:
        raise RepositoryRuntimeError("insufficient disk for bounded raw artifact")
    _verify_semgrep_pin()
    command = build_repository_semgrep_command(source_root, execution.analysis_run.analysis_languages)

    artifact_root = _artifact_root(run_id)
    output_handle = tempfile.NamedTemporaryFile(
        mode="w+b", prefix=".semgrep-", suffix=".json", dir=artifact_root, delete=False
    )
    error_handle = tempfile.NamedTemporaryFile(
        mode="w+b", prefix=".semgrep-", suffix=".stderr", dir=artifact_root, delete=False
    )
    temporary_path = Path(output_handle.name)
    error_path = Path(error_handle.name)
    temporary_path.chmod(0o600)
    error_path.chmod(0o600)
    process = None
    try:
        process = subprocess.Popen(
            command,
            cwd=source_root,
            stdout=output_handle,
            stderr=error_handle,
            start_new_session=True,
        )
        updated = ScanAttempt.objects.filter(
            pk=attempt.pk,
            status=ScanAttempt.Status.RUNNING,
            execution_token=attempt.execution_token,
        ).update(process_group_id=process.pid)
        if updated != 1:
            _terminate_process_group(process)
            raise RepositoryRuntimeError("engine ownership was lost before launch")
        deadline = time.monotonic() + REPOSITORY_SCAN_TIMEOUT_SECONDS
        while process.poll() is None:
            output_handle.flush()
            if temporary_path.stat().st_size > REPOSITORY_MAX_ARTIFACT_BYTES:
                _terminate_process_group(process)
                raise RepositoryRuntimeError("Semgrep raw output exceeded artifact limit")
            if time.monotonic() >= deadline:
                _terminate_process_group(process)
                raise RepositoryRuntimeError("Semgrep repository scan timed out")
            locked = ScanAttempt.objects.filter(
                pk=attempt.pk,
                status=ScanAttempt.Status.RUNNING,
                execution_token=attempt.execution_token,
            ).exists()
            if not locked:
                _terminate_process_group(process)
                raise RepositoryRuntimeError("engine ownership was lost")
            time.sleep(0.25)
        output_handle.flush()
        os.fsync(output_handle.fileno())
        error_handle.flush()
        os.fsync(error_handle.fileno())
        if process.returncode not in (0, 1):
            error_handle.seek(0)
            raise RepositoryRuntimeError(
                error_handle.read(8192).decode("utf-8", errors="replace")
                or f"Semgrep exited with {process.returncode}"
            )
        return _publish_artifact(attempt, temporary_path)
    finally:
        if process is not None:
            _terminate_process_group(process)
        output_handle.close()
        error_handle.close()
        temporary_path.unlink(missing_ok=True)
        error_path.unlink(missing_ok=True)
