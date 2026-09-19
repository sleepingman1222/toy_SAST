import hashlib
import json
from datetime import timedelta
from pathlib import Path, PurePosixPath

from django.db import transaction
from django.utils import timezone

from ..constants import LANGUAGE_EXTENSIONS, REPOSITORY_ATTEMPT_LEASE_SECONDS
from ..models import (
    AnalysisRun,
    ScanArtifact,
    ScanExecution,
    ScanFinding,
    ScanNormalizationAttempt,
    ScanOccurrence,
    Vulnerability,
)
from .repository_manifest import load_repository_manifest
from .repository_runtime import SEMGREP_PINNED_VERSION
from .source_snapshot import (
    get_analysis_workspace_run_root,
    get_analysis_workspace_source_root,
)
from .vulnerability_writer import build_vulnerability


class RepositoryNormalizationError(RuntimeError):
    pass


def _digest(*parts):
    value = "\x1f".join(str(part) for part in parts)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _relative_engine_path(raw_path, source_root=None):
    value = str(raw_path or "").replace("\\", "/")
    path = PurePosixPath(value)
    if path.is_absolute():
        if source_root is None:
            raise RepositoryNormalizationError("engine result path is not repository-relative")
        try:
            value = Path(value).resolve().relative_to(Path(source_root).resolve(strict=True)).as_posix()
            path = PurePosixPath(value)
        except (OSError, ValueError) as error:
            raise RepositoryNormalizationError(
                "engine result path escapes repository snapshot"
            ) from error
    if ".." in path.parts:
        raise RepositoryNormalizationError("engine result path is not repository-relative")
    parts = list(path.parts)
    if parts and parts[0] == ".":
        parts = parts[1:]
    normalized = PurePosixPath(*parts).as_posix()
    if not normalized or normalized == ".":
        raise RepositoryNormalizationError("engine result path is empty")
    return normalized


def _artifact_payload(artifact):
    if (
        artifact.kind != ScanArtifact.Kind.SEMGREP_JSON
        or artifact.schema_version != 1
        or artifact.content_type != "application/json"
    ):
        raise RepositoryNormalizationError("artifact contract is unsupported")
    if artifact.execution.engine_version != SEMGREP_PINNED_VERSION:
        raise RepositoryNormalizationError("artifact engine version is unsupported")
    run_root = get_analysis_workspace_run_root(artifact.execution.analysis_run_id).resolve(strict=True)
    path = (run_root / PurePosixPath(artifact.relative_path)).resolve(strict=True)
    try:
        path.relative_to(run_root)
    except ValueError as error:
        raise RepositoryNormalizationError("artifact path escapes run root") from error
    data = path.read_bytes()
    if len(data) != artifact.size_bytes:
        raise RepositoryNormalizationError("artifact size mismatch")
    if hashlib.sha256(data).hexdigest() != artifact.sha256:
        raise RepositoryNormalizationError("artifact hash mismatch")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RepositoryNormalizationError("artifact JSON is invalid") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise RepositoryNormalizationError("artifact schema is invalid")
    if any(not isinstance(result, dict) for result in payload["results"]):
        raise RepositoryNormalizationError("Semgrep result is malformed")
    return payload


def _extract_paths(items, source_root=None):
    if not isinstance(items, list):
        raise RepositoryNormalizationError("engine path collection is malformed")
    result = set()
    for item in items:
        if isinstance(item, str):
            raw_path = item
        elif isinstance(item, dict):
            raw_path = item.get("path")
        else:
            raise RepositoryNormalizationError("engine path entry is malformed")
        if not isinstance(raw_path, str) or not raw_path:
            raise RepositoryNormalizationError("engine path entry is malformed")
        result.add(_relative_engine_path(raw_path, source_root=source_root))
    return result


def reconcile_coverage(manifest, payload, source_root=None):
    if not isinstance(manifest, dict) or not isinstance(manifest.get("inventory"), list):
        raise RepositoryNormalizationError("repository manifest inventory is malformed")
    if any(not isinstance(item, dict) for item in manifest["inventory"]):
        raise RepositoryNormalizationError("repository manifest inventory entry is malformed")
    supported = {
        item["path"]: item
        for item in manifest["inventory"]
        if item.get("kind") == "supported_source"
    }
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        raise RepositoryNormalizationError("engine paths coverage is malformed")
    scanned = _extract_paths(paths.get("scanned", []), source_root=source_root)
    skipped = _extract_paths(paths.get("skipped", []), source_root=source_root)
    engine_errors = _extract_paths(payload.get("errors", []), source_root=source_root)
    unknown = (scanned | skipped | engine_errors) - set(supported)
    if unknown:
        raise RepositoryNormalizationError("engine reported paths outside manifest")
    overlaps = (
        (scanned & skipped)
        | (scanned & engine_errors)
        | (skipped & engine_errors)
    )
    if overlaps:
        raise RepositoryNormalizationError(
            "engine reported a path in multiple coverage categories"
        )
    excluded = {
        path
        for path, item in supported.items()
        if item.get("exclusion_reason") in {"ignored_by_policy", "oversized"}
    }
    if excluded & (scanned | skipped | engine_errors):
        raise RepositoryNormalizationError(
            "engine reported a manifest-excluded path"
        )

    categories = {name: [] for name in (
        "scanned", "ignored_by_policy", "ignored_by_semgrep", "oversized",
        "engine_error", "missing_from_engine_report",
    )}
    for path, item in supported.items():
        reason = item.get("exclusion_reason")
        if reason == "ignored_by_policy":
            category = "ignored_by_policy"
        elif reason == "oversized":
            category = "oversized"
        elif path in scanned:
            category = "scanned"
        elif path in engine_errors:
            category = "engine_error"
        elif path in skipped:
            category = "ignored_by_semgrep"
        else:
            category = "missing_from_engine_report"
        categories[category].append(path)

    counts = {name: len(values) for name, values in categories.items()}
    accounted = sum(counts.values())
    unaccounted = len(supported) - accounted
    if unaccounted != 0:
        raise RepositoryNormalizationError("coverage reconciliation is incomplete")
    return {
        "discovered_supported": len(supported),
        **counts,
        "unaccounted": unaccounted,
        "coverage_complete": counts["missing_from_engine_report"] == 0,
        "paths": categories,
    }


def _finding_payload(result, source_root=None):
    path = _relative_engine_path(result.get("path"), source_root=source_root)
    start = result.get("start") or {}
    end = result.get("end") or {}
    extra = result.get("extra") or {}
    rule_id = str(result.get("check_id") or "unknown")
    start_line = max(int(start.get("line") or 1), 1)
    start_column = max(int(start.get("col") or 1), 1)
    end_line = max(int(end.get("line") or start_line), start_line)
    end_column = max(int(end.get("col") or start_column), 1)
    metavars = extra.get("metavars") if isinstance(extra.get("metavars"), dict) else {}
    engine_identity = result.get("match_based_id") or extra.get("fingerprint")
    context = extra.get("lines") or extra.get("message") or json.dumps(metavars, sort_keys=True)
    aggregate = _digest("v2", rule_id, path, start_line, start_column, end_line, end_column, engine_identity or context)
    lineage = _digest("v2", rule_id, path, engine_identity or context)
    return {
        "rule_id": rule_id,
        "language": LANGUAGE_EXTENSIONS.get(Path(path).suffix.lower(), ""),
        "file_path": path,
        "start_line": start_line,
        "start_column": start_column,
        "end_line": end_line,
        "end_column": end_column,
        "severity": str(extra.get("severity") or "warning").lower(),
        "message": str(extra.get("message") or ""),
        "aggregate_fingerprint": aggregate,
        "lineage_signature": lineage,
    }


def normalize_repository_artifact(normalization_attempt):
    heartbeat_at = timezone.now()
    renewed = ScanNormalizationAttempt.objects.filter(
        pk=normalization_attempt.pk,
        status=ScanNormalizationAttempt.Status.RUNNING,
        execution_token=normalization_attempt.execution_token,
    ).update(
        heartbeat_at=heartbeat_at,
        lease_expires_at=heartbeat_at
        + timedelta(seconds=REPOSITORY_ATTEMPT_LEASE_SECONDS),
    )
    if renewed != 1:
        raise RepositoryNormalizationError("normalization ownership was lost")
    artifact = (
        ScanArtifact.objects.select_related("execution", "execution__analysis_run")
        .get(
            execution=normalization_attempt.execution,
            kind=ScanArtifact.Kind.SEMGREP_JSON,
            state=ScanArtifact.State.READY,
            is_canonical=True,
        )
    )
    payload = _artifact_payload(artifact)
    manifest = load_repository_manifest(artifact.execution.analysis_run_id)
    source_root = get_analysis_workspace_source_root(artifact.execution.analysis_run_id)
    coverage = reconcile_coverage(manifest, payload, source_root=source_root)
    results = payload.get("results", [])
    now = timezone.now()

    renewed = ScanNormalizationAttempt.objects.filter(
        pk=normalization_attempt.pk,
        status=ScanNormalizationAttempt.Status.RUNNING,
        execution_token=normalization_attempt.execution_token,
    ).update(
        heartbeat_at=now,
        lease_expires_at=now
        + timedelta(seconds=REPOSITORY_ATTEMPT_LEASE_SECONDS),
    )
    if renewed != 1:
        raise RepositoryNormalizationError("normalization ownership was lost")

    with transaction.atomic():
        run = AnalysisRun.objects.select_for_update().get(pk=artifact.execution.analysis_run_id)
        execution = ScanExecution.objects.select_for_update().get(pk=artifact.execution_id)
        attempt = ScanNormalizationAttempt.objects.select_for_update().get(pk=normalization_attempt.pk)
        locked_artifact = ScanArtifact.objects.select_for_update().get(
            pk=artifact.pk,
            state=ScanArtifact.State.READY,
            is_canonical=True,
        )
        if attempt.status != ScanNormalizationAttempt.Status.RUNNING or attempt.execution_token != normalization_attempt.execution_token:
            raise RepositoryNormalizationError("normalization ownership was lost")
        if execution.status != ScanExecution.Status.NORMALIZING:
            raise RepositoryNormalizationError("execution is not normalizing")
        # Recheck immutable evidence after all lifecycle rows are locked so a
        # concurrent reconciliation cannot invalidate it between validation
        # and derived-row publication.
        _artifact_payload(locked_artifact)

        for index, result in enumerate(results):
            if not isinstance(result, dict):
                raise RepositoryNormalizationError("Semgrep result is malformed")
            values = _finding_payload(result, source_root=source_root)
            canonical_payload = {key: values[key] for key in (
                "rule_id", "language", "file_path", "start_line", "start_column",
                "end_line", "end_column", "severity", "message",
            )}
            finding, created = ScanFinding.objects.get_or_create(
                analysis_run=run,
                fingerprint_version="v2",
                aggregate_fingerprint=values["aggregate_fingerprint"],
                defaults={**canonical_payload, "lineage_signature": values["lineage_signature"], "canonical_payload": canonical_payload},
            )
            if not created and finding.canonical_payload != canonical_payload:
                raise RepositoryNormalizationError("aggregate fingerprint collision")
            occurrence_key = _digest(execution.id, artifact.sha256, index)
            ScanOccurrence.objects.get_or_create(
                artifact=artifact,
                occurrence_key=occurrence_key,
                defaults={"finding": finding, "raw_result_index": index, "raw_payload": result},
            )
            vulnerability = build_vulnerability(
                run,
                result,
                source_root,
                values["language"],
            )
            Vulnerability.objects.get_or_create(
                analysis_run=run,
                fingerprint=values["aggregate_fingerprint"],
                defaults={
                    "security_weakness": vulnerability.security_weakness,
                    "analysis_language": vulnerability.analysis_language,
                    "rule_id": vulnerability.rule_id,
                    "name": vulnerability.name,
                    "severity": vulnerability.severity,
                    "confidence": vulnerability.confidence,
                    "file_path": vulnerability.file_path,
                    "line": vulnerability.line,
                    "message": vulnerability.message,
                    "evidence": vulnerability.evidence,
                    "recommendation": vulnerability.recommendation,
                },
            )

        attempt.status = ScanNormalizationAttempt.Status.COMPLETED
        attempt.completed_at = now
        attempt.save(update_fields=["status", "completed_at", "updated_at"])
        execution.coverage = coverage
        execution.coverage_complete = coverage["coverage_complete"]
        execution.discovered_supported = coverage["discovered_supported"]
        execution.raw_occurrence_count = len(results)
        execution.result_count = execution.analysis_run.scan_findings.count()
        execution.status = ScanExecution.Status.COMPLETED
        execution.completed_at = now
        execution.save(update_fields=[
            "coverage", "coverage_complete", "discovered_supported",
            "raw_occurrence_count", "result_count", "status", "completed_at", "updated_at",
        ])
        run.status = AnalysisRun.Status.COMPLETED
        run.completed_at = now
        run.failure_reason = ""
        run.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
    return {"occurrence_count": len(results), "finding_count": execution.result_count, "coverage": coverage}
