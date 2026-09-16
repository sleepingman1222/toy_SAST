import json
import threading
import uuid
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError, close_old_connections, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from projects.models import Project, SourceVersion

from .models import (
    AnalysisRun,
    ScanArtifact,
    ScanAttempt,
    ScanDispatchOutbox,
    ScanExecution,
    ScanFinding,
    ScanOccurrence,
)
from .services.repository_runtime import RepositoryRuntimeError, _publish_artifact
from .services.repository_state import RepositoryStateError, plan_repository_execution


class RepositoryV2AcceptanceTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="acceptance-test")
        self.project = Project.objects.create(name="acceptance-test", created_by=self.user)
        self.source_version = SourceVersion.objects.create(
            project=self.project,
            version=1,
            source_type=SourceVersion.SourceType.INTERNAL,
            internal_path="/tmp",
            created_by=self.user,
        )

    def create_run(self, sequence=1, pipeline="repository_v2", status="planning"):
        return AnalysisRun.objects.create(
            project=self.project,
            source_version=self.source_version,
            sequence=sequence,
            executed_by=self.user,
            pipeline_version=pipeline,
            status=status,
        )

    def create_attempt(self, run):
        execution = ScanExecution.objects.create(
            analysis_run=run,
            status=ScanExecution.Status.RUNNING,
            capabilities={},
        )
        attempt = ScanAttempt.objects.create(
            execution=execution,
            attempt_no=1,
            lease_expires_at=timezone.now() + timedelta(minutes=5),
        )
        return execution, attempt

    def test_route_freezes_and_large_mixed_manifest_plans_one_execution(self):
        run = self.create_run()
        inventory = [
            {
                "path": f"src/file-{index}.py",
                "kind": "supported_source",
                "language": "python" if index % 2 else "javascript",
                "size": 200_000,
                "content_sha256": f"{index:064x}",
                "eligibility": True,
                "exclusion_reason": "",
            }
            for index in range(31)
        ]
        self.assertGreater(sum(item["size"] for item in inventory), 5 * 1024 * 1024)
        manifest = {"snapshot_digest": "a" * 64, "inventory": inventory}

        with self.settings(REPOSITORY_SAST_V2_ENABLED=False):
            first = plan_repository_execution(run.id, manifest, ["python", "javascript"])
            second = plan_repository_execution(run.id, manifest, ["python", "javascript"])

        run.refresh_from_db()
        self.assertEqual(run.pipeline_version, AnalysisRun.PipelineVersion.REPOSITORY_V2)
        self.assertEqual(first.id, second.id)
        self.assertEqual(ScanExecution.objects.filter(analysis_run=run).count(), 1)
        self.assertEqual(first.scope_root, ".")
        self.assertEqual(first.discovered_supported, 31)
        self.assertEqual(first.dispatch_outboxes.count(), 1)

        legacy = self.create_run(sequence=2, pipeline="chunk_v1")
        with self.assertRaises(RepositoryStateError):
            plan_repository_execution(legacy.id, manifest, ["python"])

    def test_artifact_overflow_and_stale_token_publish_nothing(self):
        run = self.create_run(status=AnalysisRun.Status.RUNNING)
        execution, attempt = self.create_attempt(run)
        with TemporaryDirectory() as directory:
            run_root = Path(directory)
            overflow = run_root / ".overflow"
            overflow.write_text(json.dumps({"results": []}), encoding="utf-8")
            with (
                patch("scans.services.repository_runtime.REPOSITORY_MAX_ARTIFACT_BYTES", 5),
                patch(
                    "scans.services.repository_runtime.get_analysis_workspace_run_root",
                    return_value=run_root,
                ),
            ):
                with self.assertRaises(RepositoryRuntimeError):
                    _publish_artifact(attempt, overflow)
            self.assertFalse(ScanArtifact.objects.filter(execution=execution).exists())

            stale = run_root / ".stale"
            stale.write_text(json.dumps({"results": []}), encoding="utf-8")
            attempt.execution_token = uuid.uuid4()
            with patch(
                "scans.services.repository_runtime.get_analysis_workspace_run_root",
                return_value=run_root,
            ):
                with self.assertRaises(RepositoryRuntimeError):
                    _publish_artifact(attempt, stale)
            self.assertFalse(ScanArtifact.objects.filter(execution=execution).exists())
            self.assertFalse((run_root / "semgrep-attempt-1.json").exists())

    def test_invalid_lifecycle_rows_and_identity_collisions_fail_closed(self):
        run = self.create_run(status=AnalysisRun.Status.RUNNING)
        execution, attempt = self.create_attempt(run)

        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanAttempt.objects.filter(pk=attempt.pk).update(
                status=ScanAttempt.Status.FAILED,
                completed_at=None,
            )
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanExecution.objects.filter(pk=execution.pk).update(
                status=ScanExecution.Status.COMPLETED,
                completed_at=None,
            )
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanArtifact.objects.create(
                execution=execution,
                attempt=attempt,
                state=ScanArtifact.State.READY,
                is_canonical=True,
            )

        artifact = ScanArtifact.objects.create(
            execution=execution,
            attempt=attempt,
            state=ScanArtifact.State.READY,
            is_canonical=True,
            relative_path="artifacts/result.json",
            sha256="b" * 64,
            size_bytes=2,
            published_at=timezone.now(),
        )
        finding = ScanFinding.objects.create(
            analysis_run=run,
            aggregate_fingerprint="c" * 64,
            lineage_signature="d" * 64,
            rule_id="rule.one",
            file_path="src/a.py",
        )
        ScanOccurrence.objects.create(
            artifact=artifact,
            finding=finding,
            occurrence_key="e" * 64,
            raw_result_index=0,
        )
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanOccurrence.objects.create(
                artifact=artifact,
                finding=finding,
                occurrence_key="e" * 64,
                raw_result_index=1,
            )
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanFinding.objects.create(
                analysis_run=run,
                aggregate_fingerprint="c" * 64,
                lineage_signature="f" * 64,
                rule_id="rule.collision",
                file_path="src/other.py",
            )

    def test_engine_and_normalization_pending_outboxes_are_independently_unique(self):
        run = self.create_run(status=AnalysisRun.Status.RUNNING)
        execution, _attempt = self.create_attempt(run)
        for kind in (ScanDispatchOutbox.Kind.ENGINE, ScanDispatchOutbox.Kind.NORMALIZATION):
            ScanDispatchOutbox.objects.create(
                execution=execution,
                kind=kind,
                dispatch_no=1,
                task_name=f"test.{kind}",
            )
        self.assertEqual(execution.dispatch_outboxes.count(), 2)
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanDispatchOutbox.objects.create(
                execution=execution,
                kind=ScanDispatchOutbox.Kind.ENGINE,
                dispatch_no=2,
                task_name="test.engine.duplicate",
            )


class RepositoryRoutingRaceTests(TransactionTestCase):
    reset_sequences = True

    def test_concurrent_planners_keep_one_stored_v2_route_and_one_outbox(self):
        user = get_user_model().objects.create_user(username="routing-race")
        project = Project.objects.create(name="routing-race", created_by=user)
        source_version = SourceVersion.objects.create(
            project=project,
            version=1,
            source_type=SourceVersion.SourceType.INTERNAL,
            internal_path="/tmp",
            created_by=user,
        )
        run = AnalysisRun.objects.create(
            project=project,
            source_version=source_version,
            sequence=1,
            executed_by=user,
            pipeline_version=AnalysisRun.PipelineVersion.REPOSITORY_V2,
            status=AnalysisRun.Status.PLANNING,
        )
        manifest = {
            "snapshot_digest": "a" * 64,
            "inventory": [
                {
                    "path": "src/app.py",
                    "kind": "supported_source",
                    "language": "python",
                }
            ],
        }
        barrier = threading.Barrier(2)
        execution_ids = []
        failures = []

        def plan():
            close_old_connections()
            try:
                barrier.wait(timeout=5)
                with self.settings(REPOSITORY_SAST_V2_ENABLED=False):
                    execution_ids.append(
                        plan_repository_execution(run.id, manifest, ["python"]).id
                    )
            except Exception as error:  # collected for assertion in the test thread
                failures.append(error)
            finally:
                close_old_connections()

        threads = [threading.Thread(target=plan) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(failures, [])
        self.assertEqual(len(set(execution_ids)), 1)
        run.refresh_from_db()
        self.assertEqual(run.pipeline_version, AnalysisRun.PipelineVersion.REPOSITORY_V2)
        self.assertEqual(ScanExecution.objects.filter(analysis_run=run).count(), 1)
        self.assertEqual(
            ScanDispatchOutbox.objects.filter(
                execution__analysis_run=run,
                kind=ScanDispatchOutbox.Kind.ENGINE,
            ).count(),
            1,
        )
