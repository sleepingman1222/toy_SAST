import hashlib
import shutil
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from projects.models import Project, SourceVersion

from .kisa_master_data import KISA_SECURITY_WEAKNESSES
from .models import (
    AnalysisRun,
    KisaSecurityWeakness,
    ScanArtifact,
    ScanAttempt,
    ScanDispatchOutbox,
    ScanExecution,
)
from .services.repository_manifest import build_repository_manifest
from .services.repository_normalization import normalize_repository_artifact
from .services.repository_recovery import reconcile_scan_artifacts
from .services.repository_runtime import RepositoryRuntimeError, execute_repository_scan
from .services.repository_state import (
    claim_repository_engine,
    claim_repository_normalization,
    plan_repository_execution,
)
from .services.source_snapshot import (
    get_analysis_workspace_run_root,
    materialize_analysis_workspace,
)


class RepositoryV2RealEngineTests(TestCase):
    def setUp(self):
        KisaSecurityWeakness.objects.bulk_create(
            KisaSecurityWeakness(
                **item,
                implementation_status=(
                    KisaSecurityWeakness.ImplementationStatus.IMPLEMENTED
                ),
            )
            for item in KISA_SECURITY_WEAKNESSES
        )
        user = get_user_model().objects.create_user(username="repository-e2e")
        project = Project.objects.create(name="repository-e2e", created_by=user)
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
            status=AnalysisRun.Status.PLANNING,
        )

    def _publish_outbox(self, execution, kind):
        outbox = execution.dispatch_outboxes.get(kind=kind)
        now = timezone.now()
        outbox.status = ScanDispatchOutbox.Status.PUBLISHED
        outbox.publish_attempts = 1
        outbox.published_at = now
        outbox.claim_deadline_at = now + timedelta(minutes=1)
        outbox.save(update_fields=[
            "status",
            "publish_attempts",
            "published_at",
            "claim_deadline_at",
            "updated_at",
        ])
        return outbox

    def _make_mixed_repository(self, root):
        fixtures = Path(settings.BASE_DIR) / "semgrep_rules" / "tests"
        samples = {
            "python": ("py", "#", fixtures / "python" / "kisa_sw_01_sql_injection.py"),
            "javascript": ("js", "//", fixtures / "javascript" / "kisa_sw_01_sql_injection.js"),
            "java": ("java", "//", fixtures / "java" / "kisa_sw_01_sql_injection.java"),
        }
        count = 0
        for language, (suffix, marker, fixture) in samples.items():
            language_root = root / language
            language_root.mkdir(parents=True)
            shutil.copyfile(fixture, language_root / f"finding.{suffix}")
            count += 1
            for index in range(10 if language != "java" else 8):
                # Parseable comments keep the fixture real while crossing the
                # historical 5 MiB chunk boundary without huge ASTs.
                content = (f"{marker} repository context padding {index}\n" * 6000)
                (language_root / f"padding-{index}.{suffix}").write_text(
                    content, encoding="utf-8"
                )
                count += 1
        self.assertGreater(count, 30)
        self.assertGreater(
            sum(path.stat().st_size for path in root.rglob("*") if path.is_file()),
            5 * 1024 * 1024,
        )

    def test_large_mixed_snapshot_runs_one_real_semgrep_process_end_to_end(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            original = Path(directory) / "original"
            original.mkdir()
            self._make_mixed_repository(original)
            snapshot = materialize_analysis_workspace(self.run.id, original)
            manifest = build_repository_manifest(self.run.id, original, snapshot)
            execution = plan_repository_execution(
                self.run.id, manifest, ["java", "javascript", "python"]
            )
            engine_outbox = self._publish_outbox(
                execution, ScanDispatchOutbox.Kind.ENGINE
            )
            attempt = claim_repository_engine(
                execution.id,
                str(engine_outbox.event_key),
                celery_task_id="real-e2e",
            )
            engine_outbox.refresh_from_db()
            self.assertEqual(engine_outbox.claimed_attempt_id, attempt.id)
            self.assertIsNone(engine_outbox.claimed_normalization_attempt_id)
            attempt = ScanAttempt.objects.select_related(
                "execution", "execution__analysis_run"
            ).get(pk=attempt.pk)

            with (
                patch("scans.services.repository_runtime._verify_semgrep_pin"),
                patch(
                    "scans.services.repository_runtime.subprocess.Popen",
                    wraps=__import__("subprocess").Popen,
                ) as popen,
            ):
                artifact = execute_repository_scan(attempt)
            self.assertEqual(popen.call_count, 1)
            self.assertEqual(artifact.state, ScanArtifact.State.READY)
            attempt.refresh_from_db()
            execution.refresh_from_db()
            self.assertEqual(attempt.status, ScanAttempt.Status.COMPLETED)
            self.assertEqual(execution.status, ScanExecution.Status.NORMALIZATION_PENDING)
            self.assertTrue(
                execution.dispatch_outboxes.filter(
                    kind=ScanDispatchOutbox.Kind.NORMALIZATION,
                    status=ScanDispatchOutbox.Status.PENDING,
                ).exists()
            )

            normalization_outbox = self._publish_outbox(
                execution, ScanDispatchOutbox.Kind.NORMALIZATION
            )
            normalization_attempt = claim_repository_normalization(
                execution.id, str(normalization_outbox.event_key)
            )
            normalization_outbox.refresh_from_db()
            self.assertEqual(
                normalization_outbox.claimed_normalization_attempt_id,
                normalization_attempt.id,
            )
            self.assertIsNone(normalization_outbox.claimed_attempt_id)
            result = normalize_repository_artifact(normalization_attempt)
            execution.refresh_from_db()
            self.run.refresh_from_db()
            self.assertEqual(execution.status, ScanExecution.Status.COMPLETED)
            self.assertEqual(self.run.status, AnalysisRun.Status.COMPLETED)
            self.assertEqual(execution.scope_root, ".")
            self.assertEqual(execution.attempts.count(), 1)
            self.assertGreater(result["finding_count"], 0)
            self.assertEqual(result["coverage"]["unaccounted"], 0)
            self.assertTrue(result["coverage"]["coverage_complete"])

    def test_disk_shortage_starts_no_child_and_corruption_is_invalidated(self):
        with TemporaryDirectory() as directory, self.settings(MEDIA_ROOT=directory):
            original = Path(directory) / "original"
            original.mkdir()
            (original / "app.py").write_text("print('ok')\n", encoding="utf-8")
            snapshot = materialize_analysis_workspace(self.run.id, original)
            manifest = build_repository_manifest(self.run.id, original, snapshot)
            execution = plan_repository_execution(self.run.id, manifest, ["python"])
            engine_outbox = self._publish_outbox(
                execution, ScanDispatchOutbox.Kind.ENGINE
            )
            attempt = claim_repository_engine(
                execution.id, str(engine_outbox.event_key)
            )
            attempt = ScanAttempt.objects.select_related(
                "execution", "execution__analysis_run"
            ).get(pk=attempt.pk)

            with (
                patch(
                    "scans.services.repository_runtime.shutil.disk_usage",
                    return_value=SimpleNamespace(total=1, used=1, free=0),
                ),
                patch("scans.services.repository_runtime.subprocess.Popen") as popen,
            ):
                with self.assertRaisesRegex(RepositoryRuntimeError, "insufficient disk"):
                    execute_repository_scan(attempt)
            popen.assert_not_called()
            self.assertFalse(ScanArtifact.objects.filter(execution=execution).exists())

            run_root = get_analysis_workspace_run_root(self.run.id)
            artifact_path = run_root / "artifacts" / "corrupt.json"
            artifact_path.parent.mkdir(exist_ok=True)
            artifact_path.write_text('{"results": []}', encoding="utf-8")
            artifact = ScanArtifact.objects.create(
                execution=execution,
                attempt=attempt,
                state=ScanArtifact.State.READY,
                is_canonical=True,
                relative_path=artifact_path.relative_to(run_root).as_posix(),
                sha256=hashlib.sha256(b"different").hexdigest(),
                size_bytes=artifact_path.stat().st_size,
                published_at=__import__("django.utils.timezone", fromlist=["now"]).now(),
            )
            self.assertEqual(reconcile_scan_artifacts()["invalidated_artifacts"], 1)
            artifact.refresh_from_db()
            self.assertEqual(artifact.state, ScanArtifact.State.INVALID)
            self.assertFalse(artifact.is_canonical)
