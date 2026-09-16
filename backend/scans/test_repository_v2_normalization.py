from pathlib import Path
from datetime import timedelta
import os
import subprocess
import sys
import time
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from projects.models import Project, SourceVersion
from .models import AnalysisRun, ScanDispatchOutbox, ScanExecution, ScanNormalizationAttempt
from .models import ScanAttempt
from .services.analysis_progress import build_analysis_progress
from .services.repository_recovery import reconcile_scan_artifacts
from .services.repository_runtime import terminate_process_group
from .services.repository_state import (
    cancel_repository_execution,
    dispatch_repository_outboxes,
    fail_repository_normalization,
)
from .services.source_snapshot import get_analysis_workspace_run_root

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

    @patch("scans.services.repository_state.terminate_process_group")
    def test_cancellation_escalates_each_owned_process_group(self, terminate):
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
        execution.refresh_from_db()
        self.assertEqual(execution.status, ScanExecution.Status.CANCELLED)

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

    def test_run_cleanup_waits_for_commit_and_orphans_are_bounded(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            run_path = get_analysis_workspace_run_root(self.run.id)
            run_path.mkdir(parents=True)
            marker = run_path / "marker"
            marker.write_text("retained", encoding="utf-8")
            try:
                with transaction.atomic():
                    AnalysisRun.objects.get(pk=self.run.pk).delete()
                    raise RuntimeError("rollback")
            except RuntimeError:
                pass
            self.assertTrue(marker.exists())
            self.assertTrue(AnalysisRun.objects.filter(pk=self.run.pk).exists())

            artifact_root = run_path / "artifacts"
            artifact_root.mkdir()
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


class ProcessGroupTerminationTests(SimpleTestCase):
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
