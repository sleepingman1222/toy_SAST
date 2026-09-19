import hashlib
import os
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from projects.models import Project, SourceVersion

from .constants import REPOSITORY_MAX_TARGET_BYTES
from .models import (
    AnalysisRun,
    KisaSecurityWeakness,
    ScanArtifact,
    ScanAttempt,
    ScanDispatchOutbox,
    ScanExecution,
    ScanNormalizationAttempt,
    Vulnerability,
)
from .services.analysis_progress import build_analysis_progress
from .services.repository_normalization import (
    RepositoryNormalizationError,
    _finding_payload,
    _relative_engine_path,
    normalize_repository_artifact,
    reconcile_coverage,
)
from .services.repository_recovery import (
    _process_group_belongs_to_attempt,
    _recover_engine_attempt,
    _recover_normalization_attempt,
    reconcile_scan_artifacts,
)
from .services.repository_runtime import (
    SEMGREP_PINNED_VERSION,
    _read_process_identity,
    build_repository_semgrep_command,
    terminate_process_group,
)
from .services.repository_state import (
    _repository_execution_digests,
    cancel_repository_execution,
    claim_repository_normalization,
    dispatch_repository_outboxes,
    fail_repository_normalization,
)
from .services.source_snapshot import (
    get_analysis_workspace_run_root,
    get_analysis_workspace_source_root,
)
from .signals import _remove_run_files, _remove_run_files_with_audit


def source(path, exclusion_reason=""):
    return {
        "path": path,
        "kind": "supported_source",
        "language": "python",
        "size": 10,
        "content_sha256": "a" * 64,
        "eligibility": not exclusion_reason,
        "exclusion_reason": exclusion_reason,
    }


class RepositoryCoverageTests(SimpleTestCase):
    def test_malformed_coverage_collections_fail_closed(self):
        manifest = {"inventory": [source("source/app.py")]}
        malformed_payloads = (
            {"paths": {"scanned": "source/app.py"}, "errors": []},
            {"paths": {"scanned": [42]}, "errors": []},
            {"paths": {"scanned": []}, "errors": {"path": "source/app.py"}},
        )

        for payload in malformed_payloads:
            with self.subTest(payload=payload), self.assertRaises(
                RepositoryNormalizationError
            ):
                reconcile_coverage(manifest, payload)

    def test_manifest_inventory_must_be_an_explicit_list(self):
        with self.assertRaisesRegex(
            RepositoryNormalizationError,
            "manifest inventory is malformed",
        ):
            reconcile_coverage({}, {"paths": {}, "errors": []})

    def test_relative_source_directory_is_preserved(self):
        self.assertEqual(_relative_engine_path("source/app.py"), "source/app.py")

    def test_duplicate_engine_coverage_categories_fail_closed(self):
        manifest = {"inventory": [source("source/app.py")]}
        payload = {
            "paths": {
                "scanned": ["source/app.py"],
                "skipped": [{"path": "source/app.py"}],
            },
            "errors": [],
        }

        with self.assertRaisesRegex(
            RepositoryNormalizationError,
            "multiple coverage categories",
        ):
            reconcile_coverage(manifest, payload)

    def test_each_manifest_source_has_exactly_one_category(self):
        manifest = {"inventory": [
            source("scanned.py"),
            source("ignored.py", "ignored_by_policy"),
            source("large.py", "oversized"),
            source("semgrep.py"),
            source("error.py"),
            source("missing.py"),
        ]}
        payload = {
            "results": [],
            "paths": {"scanned": ["scanned.py"], "skipped": [{"path": "semgrep.py"}]},
            "errors": [{"path": "error.py"}],
        }
        coverage = reconcile_coverage(manifest, payload)
        self.assertEqual(coverage["unaccounted"], 0)
        self.assertEqual(coverage["discovered_supported"], 6)
        self.assertEqual(coverage["missing_from_engine_report"], 1)
        self.assertFalse(coverage["coverage_complete"])
        all_paths = [path for paths in coverage["paths"].values() for path in paths]
        self.assertEqual(len(all_paths), len(set(all_paths)))

    def test_engine_path_outside_manifest_fails_closed(self):
        with self.assertRaises(RepositoryNormalizationError):
            reconcile_coverage(
                {"inventory": [source("known.py")]},
                {"results": [], "paths": {"scanned": ["unknown.py"]}},
            )


class RepositoryIdentityTests(SimpleTestCase):
    def result(self, line):
        return {
            "check_id": "rule.test",
            "path": "src/example.py",
            "start": {"line": line, "col": 1},
            "end": {"line": line, "col": 4},
            "extra": {"message": "same semantic context", "severity": "WARNING"},
        }

    def test_aggregate_is_range_sensitive_and_lineage_is_line_stable(self):
        first = _finding_payload(self.result(2))
        moved = _finding_payload(self.result(20))
        self.assertNotEqual(first["aggregate_fingerprint"], moved["aggregate_fingerprint"])
        self.assertEqual(first["lineage_signature"], moved["lineage_signature"])


class RepositoryCommandTests(SimpleTestCase):
    def test_command_targets_one_root_with_explicit_resource_limits(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            rules = root / "rules.yml"
            rules.write_text("rules: []", encoding="utf-8")
            with patch(
                "scans.services.repository_runtime.get_semgrep_rule_path",
                return_value=rules,
            ):
                command = build_repository_semgrep_command(root, ["python"])
        self.assertEqual(command.count(str(root.resolve())), 1)
        self.assertIn("--jobs", command)
        self.assertIn("--timeout", command)
        self.assertIn("--max-memory", command)
        index = command.index("--max-target-bytes")
        self.assertEqual(command[index + 1], str(REPOSITORY_MAX_TARGET_BYTES))

    def test_execution_digests_are_deterministic_and_bind_rule_contents(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            python_rules = root / "python"
            javascript_rules = root / "javascript"
            python_rules.mkdir()
            javascript_rules.mkdir()
            python_rule = python_rules / "rule.yml"
            python_rule.write_text("rules: []", encoding="utf-8")
            (javascript_rules / "rule.yml").write_text("rules: []", encoding="utf-8")

            rule_roots = {
                "python": python_rules,
                "javascript": javascript_rules,
            }
            with patch(
                "scans.services.repository_state.get_semgrep_rule_path",
                side_effect=rule_roots.get,
            ):
                first = _repository_execution_digests(["python", "javascript"])
                reordered = _repository_execution_digests(["javascript", "python"])
                python_rule.write_text("rules:\n  - id: changed", encoding="utf-8")
                changed = _repository_execution_digests(["python", "javascript"])

        self.assertEqual(first[1:], reordered[1:])
        self.assertEqual(first[0], ["python", "javascript"])
        self.assertEqual(reordered[0], ["javascript", "python"])
        self.assertEqual(len(first[1]), 64)
        self.assertEqual(len(first[2]), 64)
        self.assertNotEqual(first[1], changed[1])
        self.assertEqual(first[2], changed[2])

    def test_committed_run_cleanup_does_not_mask_rmtree_failure(self):
        with patch("scans.signals.shutil.rmtree", side_effect=OSError("read-only")):
            with self.assertRaisesRegex(OSError, "read-only"):
                _remove_run_files(Path("/tmp/not-removed"))

    def test_committed_run_cleanup_records_failure_before_reraising(self):
        path = Path("/tmp/not-removed")
        with (
            patch("scans.signals._remove_run_files", side_effect=OSError("read-only")),
            self.assertLogs("scans.signals", level="ERROR") as logs,
            self.assertRaisesRegex(OSError, "read-only"),
        ):
            _remove_run_files_with_audit(42, path)

        self.assertIn("repository run filesystem cleanup failed", logs.output[0])


class RepositoryStateTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="repository-test")
        project = Project.objects.create(name="repository-test", created_by=user)
        source_version = SourceVersion.objects.create(
            project=project,
            version=1,
            source_type=SourceVersion.SourceType.INTERNAL,
            internal_path="/tmp",
            created_by=user,
        )
        self.run = AnalysisRun.objects.create(
            project=project,
            source_version=source_version,
            sequence=1,
            executed_by=user,
            pipeline_version=AnalysisRun.PipelineVersion.REPOSITORY_V2,
        )

    def test_pipeline_version_rejects_instance_and_bulk_mutation(self):
        self.run.pipeline_version = AnalysisRun.PipelineVersion.CHUNK_V1
        with self.assertRaises(ValueError):
            self.run.save()
        with self.assertRaises(ValueError):
            AnalysisRun.objects.filter(pk=self.run.pk).update(pipeline_version="chunk_v1")

    def test_normalization_retry_only_enqueues_normalization(self):
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.NORMALIZING,
            capabilities={},
        )
        attempt = ScanNormalizationAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            lease_expires_at=timezone.now() + timedelta(minutes=5),
        )
        fail_repository_normalization(execution.id, attempt.id, "retry", retryable=True)
        execution.refresh_from_db()
        self.assertEqual(execution.status, ScanExecution.Status.NORMALIZATION_PENDING)
        self.assertEqual(
            list(execution.dispatch_outboxes.values_list("kind", flat=True)),
            [ScanDispatchOutbox.Kind.NORMALIZATION],
        )

    def test_expired_engine_and_normalization_leases_retry_their_own_stage(self):
        now = timezone.now()
        engine_execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.RUNNING,
            capabilities={},
        )
        engine_attempt = ScanAttempt.objects.create(
            execution=engine_execution,
            attempt_no=1,
            lease_expires_at=now - timedelta(seconds=1),
        )

        self.assertTrue(_recover_engine_attempt(engine_attempt.id, now))
        engine_attempt.refresh_from_db()
        engine_execution.refresh_from_db()
        self.assertEqual(engine_attempt.status, ScanAttempt.Status.WORKER_LOST)
        self.assertEqual(engine_execution.status, ScanExecution.Status.RETRY_PENDING)
        self.assertEqual(
            list(engine_execution.dispatch_outboxes.values_list("kind", flat=True)),
            [ScanDispatchOutbox.Kind.ENGINE],
        )

        second_run = AnalysisRun.objects.create(
            project=self.run.project,
            source_version=self.run.source_version,
            sequence=2,
            executed_by=self.run.executed_by,
            pipeline_version=AnalysisRun.PipelineVersion.REPOSITORY_V2,
        )
        normalization_execution = ScanExecution.objects.create(
            analysis_run=second_run,
            status=ScanExecution.Status.NORMALIZING,
            capabilities={},
        )
        normalization_attempt = ScanNormalizationAttempt.objects.create(
            execution=normalization_execution,
            attempt_no=1,
            lease_expires_at=now - timedelta(seconds=1),
        )

        self.assertTrue(_recover_normalization_attempt(normalization_attempt.id, now))
        normalization_attempt.refresh_from_db()
        normalization_execution.refresh_from_db()
        self.assertEqual(
            normalization_attempt.status,
            ScanNormalizationAttempt.Status.WORKER_LOST,
        )
        self.assertEqual(
            normalization_attempt.failure_reason,
            "NORMALIZATION_LEASE_EXPIRED",
        )
        self.assertEqual(
            normalization_execution.status,
            ScanExecution.Status.NORMALIZATION_PENDING,
        )
        self.assertEqual(
            list(normalization_execution.dispatch_outboxes.values_list("kind", flat=True)),
            [ScanDispatchOutbox.Kind.NORMALIZATION],
        )

    @patch(
        "scans.services.repository_recovery._process_group_belongs_to_attempt",
        return_value=True,
    )
    @patch("scans.services.repository_recovery.terminate_process_group")
    def test_expired_engine_lease_exhaustion_fails_run_and_stops_owned_group(
        self, terminate, belongs_to_attempt
    ):
        now = timezone.now()
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.RUNNING,
            retry_count=0,
            max_retries=0,
            capabilities={},
        )
        attempt = ScanAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            process_group_id=4321,
            lease_expires_at=now - timedelta(seconds=1),
        )

        self.assertTrue(_recover_engine_attempt(attempt.id, now))
        self.assertFalse(_recover_engine_attempt(attempt.id, now))

        attempt.refresh_from_db()
        execution.refresh_from_db()
        self.run.refresh_from_db()
        self.assertEqual(attempt.status, ScanAttempt.Status.WORKER_LOST)
        self.assertEqual(execution.status, ScanExecution.Status.FAILED)
        self.assertEqual(execution.status_reason, "LEASE_EXPIRED")
        self.assertEqual(self.run.status, AnalysisRun.Status.FAILED)
        self.assertEqual(self.run.failure_reason, "LEASE_EXPIRED")
        self.assertEqual(self.run.completed_at, now)
        terminate.assert_called_once_with(4321)
        belongs_to_attempt.assert_called_once()
        self.assertFalse(execution.dispatch_outboxes.exists())

    def test_expired_normalization_lease_exhaustion_fails_run(self):
        now = timezone.now()
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.NORMALIZING,
            normalization_retry_count=0,
            max_normalization_retries=0,
            capabilities={},
        )
        attempt = ScanNormalizationAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            lease_expires_at=now - timedelta(seconds=1),
        )

        self.assertTrue(_recover_normalization_attempt(attempt.id, now))

        attempt.refresh_from_db()
        execution.refresh_from_db()
        self.run.refresh_from_db()
        self.assertEqual(attempt.status, ScanNormalizationAttempt.Status.WORKER_LOST)
        self.assertEqual(execution.status, ScanExecution.Status.FAILED)
        self.assertEqual(execution.status_reason, "NORMALIZATION_LEASE_EXPIRED")
        self.assertEqual(self.run.status, AnalysisRun.Status.FAILED)
        self.assertEqual(self.run.failure_reason, "NORMALIZATION_LEASE_EXPIRED")
        self.assertEqual(self.run.completed_at, now)
        self.assertFalse(execution.dispatch_outboxes.exists())

    @patch("scans.services.repository_recovery.terminate_process_group")
    def test_engine_recovery_does_not_signal_group_without_expired_ownership(
        self, terminate
    ):
        now = timezone.now()
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.RUNNING,
            capabilities={},
        )
        attempt = ScanAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            process_group_id=4321,
            lease_expires_at=now + timedelta(seconds=1),
        )

        self.assertFalse(_recover_engine_attempt(attempt.id, now))

        terminate.assert_not_called()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, ScanAttempt.Status.RUNNING)

    @patch(
        "scans.services.repository_recovery._process_group_belongs_to_attempt",
        return_value=False,
    )
    @patch("scans.services.repository_recovery.terminate_process_group")
    def test_engine_recovery_does_not_signal_reused_process_group(
        self, terminate, belongs_to_attempt
    ):
        now = timezone.now()
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.RUNNING,
            capabilities={},
        )
        attempt = ScanAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            process_group_id=4321,
            lease_expires_at=now - timedelta(seconds=1),
        )

        self.assertTrue(_recover_engine_attempt(attempt.id, now))

        belongs_to_attempt.assert_called_once()
        terminate.assert_not_called()
        execution.refresh_from_db()
        self.assertEqual(execution.status, ScanExecution.Status.RETRY_PENDING)

    @patch(
        "scans.services.repository_state.process_group_belongs_to_repository_attempt",
        return_value=True,
    )
    @patch("scans.services.repository_state.terminate_process_group")
    def test_cancellation_invalidates_attempts_and_outboxes(
        self, terminate, belongs_to_attempt
    ):
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.RUNNING,
            capabilities={},
        )
        engine_attempt = ScanAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            process_group_id=4321,
            lease_expires_at=timezone.now() + timedelta(minutes=5),
        )
        normalization_attempt = ScanNormalizationAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            lease_expires_at=timezone.now() + timedelta(minutes=5),
        )
        for dispatch_no, kind in enumerate(
            (ScanDispatchOutbox.Kind.ENGINE, ScanDispatchOutbox.Kind.NORMALIZATION),
            start=1,
        ):
            ScanDispatchOutbox.objects.create(
                execution=execution,
                kind=kind,
                dispatch_no=dispatch_no,
                task_name=f"test.{kind}",
            )

        self.assertTrue(cancel_repository_execution(execution.id))

        execution.refresh_from_db()
        engine_attempt.refresh_from_db()
        normalization_attempt.refresh_from_db()
        self.run.refresh_from_db()
        self.assertEqual(execution.status, ScanExecution.Status.CANCELLED)
        self.assertEqual(engine_attempt.status, ScanAttempt.Status.CANCELLED)
        self.assertEqual(
            normalization_attempt.status,
            ScanNormalizationAttempt.Status.CANCELLED,
        )
        self.assertEqual(self.run.status, AnalysisRun.Status.CANCELLED)
        self.assertFalse(
            execution.dispatch_outboxes.exclude(
                status=ScanDispatchOutbox.Status.CANCELLED
            ).exists()
        )
        terminate.assert_called_once_with(4321)
        belongs_to_attempt.assert_called_once()

    def create_engine_outbox(self, **overrides):
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.QUEUED,
            capabilities={},
        )
        values = {
            "execution": execution,
            "kind": ScanDispatchOutbox.Kind.ENGINE,
            "dispatch_no": 1,
            "task_name": "scans.tasks.run_repository_scan",
            "payload": {"execution_id": execution.id},
        }
        values.update(overrides)
        return execution, ScanDispatchOutbox.objects.create(**values)

    @patch("scans.services.repository_state.current_app.send_task")
    def test_published_unclaimed_replays_same_logical_event(self, send_task):
        execution, outbox = self.create_engine_outbox(
            status=ScanDispatchOutbox.Status.PUBLISHED,
            publish_attempts=1,
            published_at=timezone.now() - timedelta(minutes=2),
            claim_deadline_at=timezone.now() - timedelta(seconds=1),
        )
        original_event = outbox.event_key
        original_task = outbox.deterministic_task_id
        result = dispatch_repository_outboxes()
        outbox.refresh_from_db()
        self.assertEqual(result["published_count"], 1)
        self.assertEqual(outbox.event_key, original_event)
        self.assertEqual(outbox.deterministic_task_id, original_task)
        send_task.assert_called_once_with(
            outbox.task_name,
            kwargs=outbox.payload,
            task_id=str(original_task),
        )

    @patch("scans.services.repository_state.current_app.send_task")
    def test_normalization_published_unclaimed_replays_same_event(self, send_task):
        execution, outbox = self.create_engine_outbox(
            kind=ScanDispatchOutbox.Kind.NORMALIZATION,
            task_name="scans.tasks.normalize_repository_scan",
            status=ScanDispatchOutbox.Status.PUBLISHED,
            publish_attempts=1,
            published_at=timezone.now() - timedelta(minutes=2),
            claim_deadline_at=timezone.now() - timedelta(seconds=1),
        )
        execution.status = ScanExecution.Status.NORMALIZATION_PENDING
        execution.save(update_fields=["status", "updated_at"])
        self.run.status = AnalysisRun.Status.RUNNING
        self.run.save(update_fields=["status", "updated_at"])
        engine_attempt = ScanAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            status=ScanAttempt.Status.COMPLETED,
            lease_expires_at=timezone.now(),
            completed_at=timezone.now(),
        )
        ScanArtifact.objects.create(
            execution=execution,
            attempt=engine_attempt,
            state=ScanArtifact.State.READY,
            is_canonical=True,
            relative_path="artifacts/semgrep-attempt-1.json",
            sha256="a" * 64,
            size_bytes=1,
            published_at=timezone.now(),
        )
        event_key = outbox.event_key
        task_id = outbox.deterministic_task_id
        self.assertEqual(dispatch_repository_outboxes()["published_count"], 1)
        outbox.refresh_from_db()
        self.assertEqual(outbox.event_key, event_key)
        self.assertEqual(outbox.deterministic_task_id, task_id)
        send_task.assert_called_once_with(
            outbox.task_name, kwargs=outbox.payload, task_id=str(task_id)
        )
        normalization_attempt = claim_repository_normalization(
            execution.id,
            str(event_key),
        )
        self.assertIsNotNone(normalization_attempt)
        outbox.refresh_from_db()
        self.assertEqual(
            outbox.claimed_normalization_attempt_id,
            normalization_attempt.id,
        )
        self.assertIsNone(outbox.claimed_attempt_id)

    @patch("scans.services.repository_state.current_app.send_task")
    def test_published_event_before_deadline_is_not_replayed(self, send_task):
        self.create_engine_outbox(
            status=ScanDispatchOutbox.Status.PUBLISHED,
            publish_attempts=1,
            published_at=timezone.now(),
            claim_deadline_at=timezone.now() + timedelta(minutes=1),
        )
        self.assertEqual(dispatch_repository_outboxes()["published_count"], 0)
        send_task.assert_not_called()

    @patch(
        "scans.services.repository_state.current_app.send_task",
        side_effect=RuntimeError("broker unavailable"),
    )
    def test_publish_failure_is_bounded_and_observable(self, send_task):
        _, outbox = self.create_engine_outbox()
        self.assertEqual(dispatch_repository_outboxes()["published_count"], 0)
        outbox.refresh_from_db()
        self.assertEqual(outbox.status, ScanDispatchOutbox.Status.PENDING)
        self.assertEqual(outbox.publish_attempts, 1)
        self.assertIn("broker unavailable", outbox.last_error)
        self.assertGreater(outbox.available_at, timezone.now())

    def test_unclaimed_publish_budget_exhaustion_fails_run(self):
        execution, _ = self.create_engine_outbox(
            status=ScanDispatchOutbox.Status.PUBLISHED,
            publish_attempts=5,
            max_publish_attempts=5,
            published_at=timezone.now() - timedelta(minutes=2),
            claim_deadline_at=timezone.now() - timedelta(seconds=1),
        )
        dispatch_repository_outboxes()
        execution.refresh_from_db()
        self.run.refresh_from_db()
        self.assertEqual(execution.status_reason, "DISPATCH_UNCLAIMED")
        self.assertEqual(self.run.status, AnalysisRun.Status.FAILED)

    def test_pending_publish_budget_exhaustion_fails_run(self):
        execution, _ = self.create_engine_outbox(
            status=ScanDispatchOutbox.Status.PENDING,
            publish_attempts=5,
            max_publish_attempts=5,
            available_at=timezone.now() - timedelta(seconds=1),
        )

        dispatch_repository_outboxes()

        execution.refresh_from_db()
        self.run.refresh_from_db()
        self.assertEqual(execution.status, ScanExecution.Status.FAILED)
        self.assertEqual(execution.status_reason, "DISPATCH_UNCLAIMED")
        self.assertEqual(self.run.status, AnalysisRun.Status.FAILED)

    @patch(
        "scans.services.repository_state.process_group_belongs_to_repository_attempt",
        return_value=True,
    )
    @patch("scans.services.repository_state.terminate_process_group")
    def test_cancellation_escalates_each_owned_process_group(
        self, terminate, belongs_to_attempt
    ):
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.RUNNING,
            capabilities={},
        )
        ScanAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            process_group_id=4242,
            lease_expires_at=timezone.now() + timedelta(minutes=5),
        )
        self.assertTrue(cancel_repository_execution(execution.id))
        terminate.assert_called_once_with(4242)
        belongs_to_attempt.assert_called_once()
        execution.refresh_from_db()
        self.assertEqual(execution.status, ScanExecution.Status.CANCELLED)

    @patch(
        "scans.services.repository_state.process_group_belongs_to_repository_attempt",
        return_value=False,
    )
    @patch("scans.services.repository_state.terminate_process_group")
    def test_cancellation_does_not_signal_reused_process_group(
        self, terminate, belongs_to_attempt
    ):
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.RUNNING,
            capabilities={},
        )
        ScanAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            process_group_id=4242,
            lease_expires_at=timezone.now() + timedelta(minutes=5),
        )

        self.assertTrue(cancel_repository_execution(execution.id))

        belongs_to_attempt.assert_called_once()
        terminate.assert_not_called()

    def test_v2_progress_and_v1_empty_progress_remain_compatible(self):
        v1 = AnalysisRun.objects.create(
            project=self.run.project,
            source_version=self.run.source_version,
            sequence=2,
            executed_by=self.run.executed_by,
            pipeline_version=AnalysisRun.PipelineVersion.CHUNK_V1,
        )
        self.assertEqual(build_analysis_progress(v1)["total_chunks"], 0)
        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.NORMALIZING,
            capabilities={},
        )
        progress = build_analysis_progress(self.run)
        self.assertEqual(progress["pipeline_version"], "repository_v2")
        self.assertEqual(progress["progress_percent"], 75)
        self.assertEqual(progress["chunks"][0]["language"], "mixed")
        self.assertEqual(progress["chunks"][0]["status"], "running")
        self.assertEqual(progress["running_chunks"], 1)
        self.assertFalse(progress["coverage_complete"])

    def test_v2_progress_before_planning_and_split_retry_counts(self):
        unplanned = build_analysis_progress(self.run)
        self.assertEqual(unplanned["total_executions"], 0)
        self.assertEqual(unplanned["progress_percent"], 0)
        self.assertEqual(unplanned["retry_count"], 0)

        execution = ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.RETRY_PENDING,
            retry_count=2,
            normalization_retry_count=1,
            capabilities={},
        )
        progress = build_analysis_progress(self.run)
        self.assertEqual(progress["engine_retry_count"], 2)
        self.assertEqual(progress["normalization_retry_count"], 1)
        self.assertEqual(progress["retry_count"], 3)
        self.assertEqual(progress["executions"][0]["engine_retry_count"], 2)
        self.assertEqual(progress["executions"][0]["normalization_retry_count"], 1)
        execution.delete()
        self.run.refresh_from_db()

        self.run.status = AnalysisRun.Status.FAILED
        self.run.completed_at = timezone.now()
        self.run.save(update_fields=["status", "completed_at", "updated_at"])
        failed_before_planning = build_analysis_progress(self.run)
        self.assertEqual(failed_before_planning["progress_percent"], 100)
        self.assertEqual(failed_before_planning["total_executions"], 0)

    @patch(
        "scans.services.analysis_progress._repository_manifest_details",
    )
    def test_v2_progress_reports_manifest_and_coverage_counts_by_language(
        self,
        manifest_details,
    ):
        self.run.analysis_languages = ["javascript", "python"]
        self.run.save(update_fields=["analysis_languages", "updated_at"])
        manifest_details.return_value = (
            [
                {"kind": "supported_source", "path": "web/a.js", "language": "javascript"},
                {"kind": "supported_source", "path": "src/a.py", "language": "python"},
                {"kind": "supported_source", "path": "src/b.py", "language": "python"},
            ],
            "verified",
            "",
        )
        ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.COMPLETED,
            completed_at=timezone.now(),
            discovered_supported=3,
            coverage_complete=False,
            coverage={
                "scanned": 2,
                "missing_from_engine_report": 1,
                "unaccounted": 0,
                "coverage_complete": False,
                "paths": {
                    "scanned": ["web/a.js", "src/a.py"],
                    "missing_from_engine_report": ["src/b.py"],
                },
            },
        )

        progress = build_analysis_progress(self.run)

        self.assertEqual(
            progress["languages"],
            [
                {
                    "language": "javascript",
                    "file_count": 1,
                    "coverage": {
                        "discovered_supported": 1,
                        "scanned": 1,
                        "ignored_by_policy": 0,
                        "ignored_by_semgrep": 0,
                        "oversized": 0,
                        "engine_error": 0,
                        "missing_from_engine_report": 0,
                        "unaccounted": 0,
                        "coverage_complete": True,
                    },
                },
                {
                    "language": "python",
                    "file_count": 2,
                    "coverage": {
                        "discovered_supported": 2,
                        "scanned": 1,
                        "ignored_by_policy": 0,
                        "ignored_by_semgrep": 0,
                        "oversized": 0,
                        "engine_error": 0,
                        "missing_from_engine_report": 1,
                        "unaccounted": 0,
                        "coverage_complete": False,
                    },
                },
            ],
        )

    @patch(
        "scans.services.analysis_progress._repository_manifest_details",
    )
    def test_v2_progress_tolerates_malformed_coverage_path_categories(
        self,
        manifest_details,
    ):
        self.run.analysis_languages = ["python"]
        self.run.save(update_fields=["analysis_languages", "updated_at"])
        manifest_details.return_value = (
            [
                {"kind": "supported_source", "path": "src/a.py", "language": "python"},
            ],
            "verified",
            "",
        )
        ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.RUNNING,
            discovered_supported=1,
            capabilities={},
            coverage={"paths": {"scanned": None}},
        )

        progress = build_analysis_progress(self.run)

        self.assertEqual(progress["languages"][0]["file_count"], 1)
        self.assertEqual(progress["languages"][0]["coverage"]["scanned"], 0)
        self.assertEqual(progress["languages"][0]["coverage"]["unaccounted"], 1)
        self.assertFalse(
            progress["languages"][0]["coverage"]["coverage_complete"]
        )

    def test_v2_progress_exposes_missing_or_corrupt_manifest_as_incomplete(self):
        self.run.analysis_languages = ["python"]
        self.run.save(update_fields=["analysis_languages", "updated_at"])
        ScanExecution.objects.create(
            analysis_run=self.run,
            status=ScanExecution.Status.COMPLETED,
            completed_at=timezone.now(),
            discovered_supported=1,
            coverage_complete=True,
            coverage={
                "scanned": 1,
                "coverage_complete": True,
                "paths": {"scanned": ["src/a.py"]},
            },
        )

        failures = (
            (FileNotFoundError(), "missing"),
            (ValueError("corrupt json"), "invalid"),
        )
        for error, expected_status in failures:
            with self.subTest(expected_status=expected_status), patch(
                "scans.services.repository_manifest.load_repository_manifest",
                side_effect=error,
            ):
                progress = build_analysis_progress(self.run)

            self.assertEqual(progress["manifest_integrity"], expected_status)
            self.assertTrue(progress["manifest_integrity_error"])
            self.assertFalse(progress["coverage_complete"])
            self.assertFalse(progress["executions"][0]["coverage_complete"])
            self.assertFalse(
                progress["languages"][0]["coverage"]["coverage_complete"]
            )

    def test_run_cleanup_waits_for_commit_and_orphans_are_bounded(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            run_path = get_analysis_workspace_run_root(self.run.id)
            run_path.mkdir(parents=True)
            marker = run_path / "marker"
            marker.write_text("retained", encoding="utf-8")
            artifact_root = run_path / "artifacts"
            artifact_root.mkdir()
            artifact_path = artifact_root / "semgrep-attempt-1.json"
            artifact_bytes = b'{"results": []}'
            artifact_path.write_bytes(artifact_bytes)
            execution = ScanExecution.objects.create(
                analysis_run=self.run,
                status=ScanExecution.Status.RUNNING,
                capabilities={},
            )
            attempt = ScanAttempt.objects.create(
                execution=execution,
                attempt_no=1,
                lease_expires_at=timezone.now() + timedelta(minutes=5),
            )
            ScanArtifact.objects.create(
                execution=execution,
                attempt=attempt,
                state=ScanArtifact.State.READY,
                is_canonical=True,
                relative_path="artifacts/semgrep-attempt-1.json",
                sha256=hashlib.sha256(artifact_bytes).hexdigest(),
                size_bytes=len(artifact_bytes),
                published_at=timezone.now(),
            )
            claimed_at = timezone.now()
            ScanDispatchOutbox.objects.create(
                execution=execution,
                kind=ScanDispatchOutbox.Kind.ENGINE,
                dispatch_no=1,
                task_name="test.claimed-engine",
                status=ScanDispatchOutbox.Status.PUBLISHED,
                published_at=claimed_at,
                claim_deadline_at=claimed_at + timedelta(minutes=1),
                claimed_at=claimed_at,
                claimed_attempt=attempt,
            )
            try:
                with transaction.atomic():
                    AnalysisRun.objects.get(pk=self.run.pk).delete()
                    raise RuntimeError("rollback")
            except RuntimeError:
                pass
            self.assertTrue(marker.exists())
            self.assertTrue(AnalysisRun.objects.filter(pk=self.run.pk).exists())

            stale_time = time.time() - 1000
            for index in range(3):
                temporary = artifact_root / f".semgrep-{index}"
                temporary.write_text("temporary", encoding="utf-8")
                os.utime(temporary, (stale_time, stale_time))
            bounded = reconcile_scan_artifacts()
            self.assertEqual(bounded["removed_stale_files"], 3)
            self.assertEqual(list(artifact_root.glob(".semgrep-*")), [])

            orphan = Path(directory) / "analysis_workspaces" / "run_999999"
            orphan.mkdir(parents=True)
            (orphan / "orphan").write_text("x", encoding="utf-8")
            result = reconcile_scan_artifacts()
            self.assertEqual(result["removed_orphans"], 1)
            self.assertFalse(orphan.exists())

            with self.captureOnCommitCallbacks(execute=True):
                AnalysisRun.objects.get(pk=self.run.pk).delete()
                self.assertTrue(marker.exists())
            self.assertFalse(run_path.exists())

    def test_v2_vulnerability_projection_uses_legacy_writer_semantics(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            weakness, _ = KisaSecurityWeakness.objects.update_or_create(
                identifier="KISA-SW-01",
                defaults={
                    "category": "input validation",
                    "item_number": 1,
                    "name": "SQL injection",
                    "description": "test master row",
                    "implementation_status": (
                        KisaSecurityWeakness.ImplementationStatus.IMPLEMENTED
                    ),
                },
            )
            source_root = get_analysis_workspace_source_root(self.run.id)
            source_root.mkdir(parents=True)
            (source_root / "app.py").write_text(
                "safe = True\ndangerous_query(user_input)\n",
                encoding="utf-8",
            )
            result = {
                "check_id": "kisa.sw01.python.test",
                "path": "app.py",
                "start": {"line": 2, "col": 1},
                "end": {"line": 2, "col": 28},
                "extra": {
                    "severity": "ERROR",
                    "message": "unsafe query",
                    "metadata": {
                        "kisa_identifier": weakness.identifier,
                        "kisa_name": "KISA SQL injection",
                        "confidence": "HIGH",
                        "recommendation": "Use parameterized queries.",
                    },
                },
            }
            payload = {
                "results": [result, result],
                "paths": {"scanned": ["app.py"]},
                "errors": [],
            }
            artifact_bytes = __import__("json").dumps(payload).encode("utf-8")
            run_root = get_analysis_workspace_run_root(self.run.id)
            artifact_path = run_root / "artifacts" / "semgrep-attempt-1.json"
            artifact_path.parent.mkdir()
            artifact_path.write_bytes(artifact_bytes)
            execution = ScanExecution.objects.create(
                analysis_run=self.run,
                status=ScanExecution.Status.NORMALIZING,
                capabilities={},
                engine_version=SEMGREP_PINNED_VERSION,
            )
            engine_attempt = ScanAttempt.objects.create(
                execution=execution,
                attempt_no=1,
                status=ScanAttempt.Status.COMPLETED,
                lease_expires_at=timezone.now(),
                completed_at=timezone.now(),
            )
            artifact = ScanArtifact.objects.create(
                execution=execution,
                attempt=engine_attempt,
                state=ScanArtifact.State.READY,
                is_canonical=True,
                relative_path=artifact_path.relative_to(run_root).as_posix(),
                sha256=hashlib.sha256(artifact_bytes).hexdigest(),
                size_bytes=len(artifact_bytes),
                published_at=timezone.now(),
            )
            normalization_attempt = ScanNormalizationAttempt.objects.create(
                execution=execution,
                attempt_no=1,
                lease_expires_at=timezone.now() + timedelta(minutes=1),
            )
            manifest = {"inventory": [source("app.py")]}

            with patch(
                "scans.services.repository_normalization.load_repository_manifest",
                return_value=manifest,
            ):
                normalize_repository_artifact(normalization_attempt)

            vulnerability = Vulnerability.objects.get(analysis_run=self.run)
            finding = self.run.scan_findings.get()
            self.assertEqual(vulnerability.fingerprint, finding.aggregate_fingerprint)
            self.assertEqual(vulnerability.security_weakness, weakness)
            self.assertEqual(vulnerability.name, "KISA SQL injection")
            self.assertEqual(vulnerability.severity, Vulnerability.Severity.HIGH)
            self.assertEqual(vulnerability.confidence, Vulnerability.Confidence.HIGH)
            self.assertEqual(vulnerability.evidence, "dangerous_query(user_input)")
            self.assertEqual(vulnerability.recommendation, "Use parameterized queries.")
            self.assertEqual(artifact.occurrences.count(), 2)
            self.assertEqual(Vulnerability.objects.filter(analysis_run=self.run).count(), 1)

    def test_completed_history_is_not_rewritten_when_evidence_is_invalidated(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            completed_at = timezone.now() - timedelta(minutes=1)
            self.run.status = AnalysisRun.Status.COMPLETED
            self.run.completed_at = completed_at
            self.run.failure_reason = ""
            self.run.save()
            execution = ScanExecution.objects.create(
                analysis_run=self.run,
                status=ScanExecution.Status.COMPLETED,
                completed_at=completed_at,
                status_reason="",
                capabilities={},
            )
            attempt = ScanAttempt.objects.create(
                execution=execution,
                attempt_no=1,
                status=ScanAttempt.Status.COMPLETED,
                completed_at=completed_at,
                lease_expires_at=completed_at,
            )
            run_root = get_analysis_workspace_run_root(self.run.id)
            path = run_root / "artifacts" / "semgrep-attempt-1.json"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"corrupt")
            artifact = ScanArtifact.objects.create(
                execution=execution,
                attempt=attempt,
                state=ScanArtifact.State.READY,
                is_canonical=True,
                relative_path=path.relative_to(run_root).as_posix(),
                sha256=hashlib.sha256(b"expected").hexdigest(),
                size_bytes=path.stat().st_size,
                published_at=completed_at,
            )

            self.assertEqual(reconcile_scan_artifacts()["invalidated_artifacts"], 1)

            artifact.refresh_from_db()
            execution.refresh_from_db()
            self.run.refresh_from_db()
            self.assertEqual(artifact.state, ScanArtifact.State.INVALID)
            self.assertEqual(execution.status, ScanExecution.Status.COMPLETED)
            self.assertEqual(execution.completed_at, completed_at)
            self.assertEqual(execution.status_reason, "")
            self.assertEqual(self.run.status, AnalysisRun.Status.COMPLETED)
            self.assertEqual(self.run.completed_at, completed_at)
            self.assertEqual(self.run.failure_reason, "")

    def test_deleted_artifact_file_is_reclaimed_without_age_delay(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            execution = ScanExecution.objects.create(
                analysis_run=self.run,
                status=ScanExecution.Status.RUNNING,
                capabilities={},
            )
            attempt = ScanAttempt.objects.create(
                execution=execution,
                attempt_no=1,
                lease_expires_at=timezone.now() + timedelta(minutes=1),
            )
            run_root = get_analysis_workspace_run_root(self.run.id)
            path = run_root / "artifacts" / "semgrep-attempt-1.json"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"deleted")
            ScanArtifact.objects.create(
                execution=execution,
                attempt=attempt,
                state=ScanArtifact.State.DELETED,
                relative_path=path.relative_to(run_root).as_posix(),
                sha256=hashlib.sha256(b"deleted").hexdigest(),
                size_bytes=7,
            )

            result = reconcile_scan_artifacts()

            self.assertEqual(result["removed_stale_files"], 1)
            self.assertFalse(path.exists())

    def test_cleanup_propagates_deletion_failures_without_false_success(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            orphan = Path(directory) / "analysis_workspaces" / "run_999999"
            orphan.mkdir(parents=True)
            with patch(
                "scans.services.repository_recovery.shutil.rmtree",
                side_effect=OSError("permission denied"),
            ):
                with self.assertRaisesRegex(OSError, "permission denied"):
                    reconcile_scan_artifacts()
            self.assertTrue(orphan.exists())

    def test_artifact_cleanup_propagates_unlink_failure(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            execution = ScanExecution.objects.create(
                analysis_run=self.run,
                status=ScanExecution.Status.RUNNING,
                capabilities={},
            )
            attempt = ScanAttempt.objects.create(
                execution=execution,
                attempt_no=1,
                lease_expires_at=timezone.now() + timedelta(minutes=1),
            )
            run_root = get_analysis_workspace_run_root(self.run.id)
            path = run_root / "artifacts" / "semgrep-attempt-1.json"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"deleted")
            ScanArtifact.objects.create(
                execution=execution,
                attempt=attempt,
                state=ScanArtifact.State.DELETED,
                relative_path=path.relative_to(run_root).as_posix(),
                sha256=hashlib.sha256(b"deleted").hexdigest(),
                size_bytes=7,
            )

            with patch.object(Path, "unlink", side_effect=OSError("read-only")):
                with self.assertRaisesRegex(OSError, "read-only"):
                    reconcile_scan_artifacts()

            self.assertTrue(path.exists())


class ProcessGroupTerminationTests(SimpleTestCase):
    def test_recovery_only_recognizes_group_in_its_immutable_snapshot(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            source_root = get_analysis_workspace_run_root(123) / "source"
            process_root = source_root / "nested"
            process_root.mkdir(parents=True)
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                cwd=process_root,
                start_new_session=True,
                env={
                    **os.environ,
                    "TOY_SAST_ATTEMPT_TOKEN": "owned-token",
                },
            )
            session_id, start_ticks = _read_process_identity(process.pid)
            attempt = SimpleNamespace(
                process_group_id=process.pid,
                process_session_id=session_id,
                process_start_ticks=start_ticks,
                execution_token="owned-token",
            )
            execution = SimpleNamespace(analysis_run_id=123)
            try:
                self.assertTrue(
                    _process_group_belongs_to_attempt(attempt, execution)
                )
                with self.settings(MEDIA_ROOT=str(Path(directory) / "other")):
                    other_source = get_analysis_workspace_run_root(123) / "source"
                    other_source.mkdir(parents=True)
                    self.assertFalse(
                        _process_group_belongs_to_attempt(attempt, execution)
                    )
                attempt.execution_token = "different-token"
                self.assertFalse(
                    _process_group_belongs_to_attempt(attempt, execution)
                )
            finally:
                terminate_process_group(process.pid, process, grace_seconds=0.2)

    def test_descendant_is_killed_after_direct_parent_already_exited(self):
        child_program = (
            "import signal,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "time.sleep(60)"
        )
        parent_program = (
            "import subprocess,sys; "
            "child=subprocess.Popen([sys.executable,'-c',%r], "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
            "print(child.pid, flush=True)"
        ) % child_program
        parent = subprocess.Popen(
            [sys.executable, "-c", parent_program],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        child_pid = int(parent.stdout.readline().strip())
        parent.wait(timeout=5)
        self.assertIsNotNone(parent.poll())
        try:
            terminate_process_group(parent.pid, parent, grace_seconds=0.2)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                stat = Path(f"/proc/{child_pid}/stat")
                if not stat.exists() or stat.read_text().split()[2] == "Z":
                    break
                time.sleep(0.05)
            stat = Path(f"/proc/{child_pid}/stat")
            self.assertTrue(not stat.exists() or stat.read_text().split()[2] == "Z")
        finally:
            try:
                os.kill(child_pid, 9)
            except ProcessLookupError:
                pass
