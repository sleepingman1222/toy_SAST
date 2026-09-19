import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import timedelta
from enum import Enum
from pathlib import Path, PurePosixPath

from django.db import transaction
from django.utils import timezone

from ..constants import (
    LANGUAGE_EXTENSIONS,
    MAX_ANALYZABLE_FILE_BYTES,
    REPOSITORY_ARTIFACT_SAFETY_MARGIN_BYTES,
    REPOSITORY_ATTEMPT_LEASE_SECONDS,
    REPOSITORY_MAX_ARTIFACT_BYTES,
    REPOSITORY_MAX_TARGET_BYTES,
    REPOSITORY_SCAN_JOBS,
    REPOSITORY_SCAN_MAX_MEMORY_MIB,
    REPOSITORY_SCAN_TIMEOUT_SECONDS,
)
from ..models import AnalysisRun, ScanArtifact, ScanAttempt, ScanExecution
from .repository_manifest import (
    _is_marker,
    _sha256_file,
    load_repository_manifest,
)
from .semgrep_executor import get_semgrep_rule_path
from .source_snapshot import (
    get_analysis_workspace_run_root,
    get_analysis_workspace_source_root,
)


SEMGREP_PINNED_VERSION = "1.175.0"
# Stderr is diagnostic-only. Reusing the reserved disk safety margin keeps it
# bounded without reducing the configured maximum size of the JSON artifact.
SEMGREP_DIAGNOSTIC_STDERR_MAX_BYTES = REPOSITORY_ARTIFACT_SAFETY_MARGIN_BYTES


class RepositoryRuntimeError(RuntimeError):
    pass


class ProcessOwnership(str, Enum):
    ABSENT = "absent"
    OWNED = "owned"
    FOREIGN = "foreign"
    UNVERIFIABLE = "unverifiable"


def _manifest_relative_path(value):
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise RepositoryRuntimeError("repository manifest contains an unsafe path")
    return path


def _is_scan_relevant_workspace_file(path):
    return (
        path.suffix.lower() in LANGUAGE_EXTENSIONS
        or path.name == ".semgrepignore"
        or _is_marker(path.name)
    )


def verify_repository_snapshot(source_root, manifest):
    """Fail closed when the repository-v2 immutable input has drifted."""
    source_root = Path(source_root).resolve(strict=True)
    expected = {}
    for item in manifest.get("inventory", []):
        kind = item.get("kind")
        if kind == "supported_source" and not item.get("eligibility"):
            continue
        if kind not in ("supported_source", "semgrep_ignore", "project_marker"):
            continue
        relative_path = _manifest_relative_path(item.get("path", ""))
        if relative_path.as_posix() in expected:
            raise RepositoryRuntimeError("repository manifest contains duplicate paths")
        expected[relative_path.as_posix()] = item

    actual = {}
    for current_root, directory_names, file_names in os.walk(source_root, followlinks=False):
        current_path = Path(current_root)
        for directory_name in directory_names:
            if (current_path / directory_name).is_symlink():
                raise RepositoryRuntimeError("immutable workspace contains a symbolic link")
        for file_name in file_names:
            path = current_path / file_name
            if not _is_scan_relevant_workspace_file(path):
                continue
            relative_path = path.relative_to(source_root).as_posix()
            if path.is_symlink() or not path.is_file():
                raise RepositoryRuntimeError("immutable workspace contains an invalid input")
            actual[relative_path] = path

    unexpected = sorted(set(actual) - set(expected))
    if unexpected:
        raise RepositoryRuntimeError(
            f"immutable workspace contains unexpected scan input: {unexpected[0]}"
        )
    missing = sorted(set(expected) - set(actual))
    if missing:
        raise RepositoryRuntimeError(
            f"immutable workspace input is missing: {missing[0]}"
        )
    for relative_path, item in expected.items():
        path = actual[relative_path]
        if (
            path.stat().st_size != item.get("size")
            or _sha256_file(path) != item.get("content_sha256")
        ):
            raise RepositoryRuntimeError(
                f"immutable workspace input does not match manifest: {relative_path}"
            )


def _renew_attempt_lease(attempt):
    now = timezone.now()
    return ScanAttempt.objects.filter(
        pk=attempt.pk,
        status=ScanAttempt.Status.RUNNING,
        execution_token=attempt.execution_token,
    ).update(
        heartbeat_at=now,
        lease_expires_at=now + timedelta(seconds=REPOSITORY_ATTEMPT_LEASE_SECONDS),
    ) == 1


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
    if result.returncode != 0 or version != SEMGREP_PINNED_VERSION:
        raise RepositoryRuntimeError(
            f"Semgrep pin mismatch: expected {SEMGREP_PINNED_VERSION}, received {version or 'unknown'}"
        )


def _read_process_identity(process_id):
    try:
        process_stat = (Path("/proc") / str(process_id) / "stat").read_text()
        stat_tail = process_stat.rsplit(")", 1)[1].split()
        return int(stat_tail[3]), int(stat_tail[19])
    except (IndexError, OSError, ValueError) as error:
        raise RepositoryRuntimeError(
            "engine process identity could not be established"
        ) from error


def repository_attempt_process_ownership(attempt, execution):
    """Classify the registered process group without signalling reused PIDs."""
    process_group_id = attempt.process_group_id
    process_session_id = attempt.process_session_id
    process_start_ticks = attempt.process_start_ticks
    if not process_group_id:
        return ProcessOwnership.ABSENT
    if not _process_group_exists(process_group_id):
        return ProcessOwnership.ABSENT
    if not process_session_id or process_start_ticks is None:
        return ProcessOwnership.UNVERIFIABLE
    try:
        source_root = get_analysis_workspace_source_root(
            execution.analysis_run_id
        ).resolve(strict=True)
    except OSError:
        return ProcessOwnership.UNVERIFIABLE

    found_member = False
    found_foreign_member = False
    for process_path in Path("/proc").glob("[0-9]*"):
        try:
            process_stat = (process_path / "stat").read_text()
            stat_tail = process_stat.rsplit(")", 1)[1].split()
            if int(stat_tail[2]) != process_group_id:
                continue
            # Zombies cannot execute or fork and should not indefinitely block
            # recovery merely because their eventual parent has not reaped.
            if stat_tail[0] == "Z":
                continue
            if int(stat_tail[3]) != process_session_id:
                found_foreign_member = True
                continue
            if (
                int(process_path.name) == process_group_id
                and int(stat_tail[19]) != process_start_ticks
            ):
                found_foreign_member = True
                continue
        except (IndexError, OSError, ValueError):
            continue
        try:
            member_cwd = (process_path / "cwd").resolve(strict=True)
        except FileNotFoundError:
            continue
        except OSError:
            return ProcessOwnership.UNVERIFIABLE
        try:
            member_cwd.relative_to(source_root)
        except ValueError:
            found_foreign_member = True
            continue
        try:
            environment = (process_path / "environ").read_bytes().split(b"\0")
        except OSError:
            return ProcessOwnership.UNVERIFIABLE
        ownership_marker = (
            f"TOY_SAST_ATTEMPT_TOKEN={attempt.execution_token}".encode("ascii")
        )
        if ownership_marker not in environment:
            found_foreign_member = True
            continue
        found_member = True
    if found_member and not found_foreign_member:
        return ProcessOwnership.OWNED
    if found_foreign_member and not found_member:
        return ProcessOwnership.FOREIGN
    if not _process_group_exists(process_group_id):
        return ProcessOwnership.ABSENT
    return ProcessOwnership.UNVERIFIABLE


def process_group_belongs_to_repository_attempt(attempt, execution):
    return (
        repository_attempt_process_ownership(attempt, execution)
        == ProcessOwnership.OWNED
    )


def _process_group_exists(process_group_id):
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def terminate_process_group(process_group_id, parent_process=None, grace_seconds=5):
    """Terminate the complete session even when its original parent exited.

    `Popen.poll()` only describes the direct child. Grandchildren can keep the
    process group alive after that child exits, so group existence is probed
    independently and TERM always escalates to KILL when necessary.
    """
    process_group_id = int(process_group_id)
    if _process_group_exists(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline and _process_group_exists(process_group_id):
            time.sleep(0.05)
        if _process_group_exists(process_group_id):
            try:
                os.killpg(process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + grace_seconds
            while time.monotonic() < deadline and _process_group_exists(process_group_id):
                time.sleep(0.05)
    if parent_process is not None:
        try:
            parent_process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            try:
                parent_process.kill()
            except ProcessLookupError:
                pass
            parent_process.wait(timeout=grace_seconds)
    return not _process_group_exists(process_group_id)


def _artifact_root(run_id):
    root = get_analysis_workspace_run_root(run_id) / "artifacts"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def _publish_artifact(attempt, temporary_path):
    # The producer normally fsyncs before entering here. Repeating the durable
    # close boundary makes direct callers and future producers equally safe.
    with temporary_path.open("rb") as durable_input:
        os.fsync(durable_input.fileno())
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
    directory_fd = os.open(final_path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    relative_path = final_path.relative_to(get_analysis_workspace_run_root(
        attempt.execution.analysis_run_id
    )).as_posix()

    try:
        with transaction.atomic():
            run = AnalysisRun.objects.select_for_update().get(
                pk=attempt.execution.analysis_run_id
            )
            execution = ScanExecution.objects.select_for_update().get(
                pk=attempt.execution_id
            )
            locked = ScanAttempt.objects.select_for_update().get(pk=attempt.pk)
            if (
                run.status != AnalysisRun.Status.RUNNING
                or execution.status != ScanExecution.Status.RUNNING
                or locked.status != ScanAttempt.Status.RUNNING
                or locked.execution_token != attempt.execution_token
            ):
                raise RepositoryRuntimeError(
                    "engine ownership was lost before artifact publication"
                )
            artifact = ScanArtifact.objects.create(
                execution=execution,
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
            # Keep ready evidence, successful engine completion, and the
            # normalization dispatch in one database commit. A worker loss can
            # therefore never leave a canonical artifact that forces Semgrep
            # to run again.
            from .repository_state import enqueue_normalization

            enqueue_normalization(execution, locked)
    except Exception:
        final_path.unlink(missing_ok=True)
        raise
    return artifact


def execute_repository_scan(attempt):
    execution = attempt.execution
    run_id = execution.analysis_run_id
    source_root = get_analysis_workspace_source_root(run_id).resolve(strict=True)
    manifest = load_repository_manifest(run_id)
    expected_root = get_analysis_workspace_source_root(run_id).resolve(strict=True)
    if source_root != expected_root:
        raise RepositoryRuntimeError("repository scan root is not the immutable workspace")
    verify_repository_snapshot(source_root, manifest)
    from .repository_state import _repository_execution_digests

    _, ruleset_digest, options_digest = _repository_execution_digests(
        execution.analysis_run.analysis_languages
    )
    if (
        execution.snapshot_digest != manifest.get("snapshot_digest")
        or execution.ruleset_digest != ruleset_digest
        or execution.options_digest != options_digest
    ):
        raise RepositoryRuntimeError(
            "repository execution identity no longer matches its planned inputs"
        )

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
    launch_read_fd = None
    launch_write_fd = None
    try:
        launch_read_fd, launch_write_fd = os.pipe()
        launch_program = (
            "import os,sys; "
            "fd=int(sys.argv[1]); "
            "gate=os.read(fd,1); os.close(fd); "
            "sys.exit(125) if gate != b'1' else None; "
            "os.execvp(sys.argv[2],sys.argv[2:])"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", launch_program, str(launch_read_fd), *command],
            cwd=source_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=0,
            pass_fds=(launch_read_fd,),
            env={
                **os.environ,
                "TOY_SAST_ATTEMPT_TOKEN": str(attempt.execution_token),
            },
        )
        os.close(launch_read_fd)
        launch_read_fd = None
        process_session_id, process_start_ticks = _read_process_identity(process.pid)
        updated = ScanAttempt.objects.filter(
            pk=attempt.pk,
            status=ScanAttempt.Status.RUNNING,
            execution_token=attempt.execution_token,
        ).update(
            process_group_id=process.pid,
            process_session_id=process_session_id,
            process_start_ticks=process_start_ticks,
        )
        if updated != 1:
            os.close(launch_write_fd)
            launch_write_fd = None
            terminate_process_group(process.pid, process)
            raise RepositoryRuntimeError("engine ownership was lost before launch")
        os.write(launch_write_fd, b"1")
        os.close(launch_write_fd)
        launch_write_fd = None
        deadline = time.monotonic() + REPOSITORY_SCAN_TIMEOUT_SECONDS
        heartbeat_interval = max(
            1.0,
            min(10.0, REPOSITORY_ATTEMPT_LEASE_SECONDS / 3),
        )
        next_heartbeat = time.monotonic()
        stream_limits = {
            process.stdout: (output_handle, REPOSITORY_MAX_ARTIFACT_BYTES),
            process.stderr: (
                error_handle,
                SEMGREP_DIAGNOSTIC_STDERR_MAX_BYTES,
            ),
        }
        stream_sizes = {stream: 0 for stream in stream_limits}
        selector = selectors.DefaultSelector()
        try:
            for stream in stream_limits:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if now >= deadline:
                    terminate_process_group(process.pid, process)
                    raise RepositoryRuntimeError(
                        "Semgrep repository scan timed out"
                    )
                if now >= next_heartbeat:
                    if not _renew_attempt_lease(attempt):
                        terminate_process_group(process.pid, process)
                        raise RepositoryRuntimeError("engine ownership was lost")
                    next_heartbeat = now + heartbeat_interval
                for key, _ in selector.select(timeout=0.25):
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    destination, limit = stream_limits[stream]
                    next_size = stream_sizes[stream] + len(chunk)
                    if next_size > limit:
                        terminate_process_group(process.pid, process)
                        label = "raw output" if stream is process.stdout else "diagnostic output"
                        raise RepositoryRuntimeError(
                            f"Semgrep {label} exceeded limit"
                        )
                    destination.write(chunk)
                    stream_sizes[stream] = next_size
        finally:
            selector.close()
            for stream in stream_limits:
                stream.close()
        output_handle.flush()
        os.fsync(output_handle.fileno())
        error_handle.flush()
        os.fsync(error_handle.fileno())
        output_handle.close()
        error_handle.close()
        if error_path.stat().st_size > SEMGREP_DIAGNOSTIC_STDERR_MAX_BYTES:
            raise RepositoryRuntimeError("Semgrep diagnostic output exceeded limit")
        if process.returncode not in (0, 1):
            raise RepositoryRuntimeError(
                error_path.read_bytes()[:8192].decode("utf-8", errors="replace")
                or f"Semgrep exited with {process.returncode}"
            )
        return _publish_artifact(attempt, temporary_path)
    finally:
        if launch_read_fd is not None:
            os.close(launch_read_fd)
        if launch_write_fd is not None:
            os.close(launch_write_fd)
        if process is not None:
            terminate_process_group(process.pid, process)
        output_handle.close()
        error_handle.close()
        temporary_path.unlink(missing_ok=True)
        error_path.unlink(missing_ok=True)
