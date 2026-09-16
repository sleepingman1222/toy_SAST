from pathlib import Path
from datetime import timedelta
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from projects.models import Project, SourceVersion
from .models import AnalysisRun, ScanDispatchOutbox, ScanExecution, ScanNormalizationAttempt
from .services.repository_state import fail_repository_normalization

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
