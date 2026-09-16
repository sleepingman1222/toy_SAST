from pathlib import Path
from datetime import timedelta
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from projects.models import Project, SourceVersion
from .models import (
    AnalysisRun,
    ScanAttempt,
    ScanDispatchOutbox,
    ScanExecution,
    ScanNormalizationAttempt,
)
from .services.repository_recovery import (
    _recover_engine_attempt,
    _recover_normalization_attempt,
)
from .services.repository_state import (
    cancel_repository_execution,
    fail_repository_normalization,
)

from .constants import REPOSITORY_MAX_TARGET_BYTES
from .services.repository_normalization import (
    RepositoryNormalizationError,
    _finding_payload,
    reconcile_coverage,
)
from .services.repository_runtime import build_repository_semgrep_command


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
            normalization_execution.status,
            ScanExecution.Status.NORMALIZATION_PENDING,
        )
        self.assertEqual(
            list(normalization_execution.dispatch_outboxes.values_list("kind", flat=True)),
            [ScanDispatchOutbox.Kind.NORMALIZATION],
        )

    @patch("scans.services.repository_state.os.killpg")
    def test_cancellation_invalidates_attempts_outboxes_and_process_group(self, killpg):
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
        killpg.assert_called_once_with(4321, 15)
