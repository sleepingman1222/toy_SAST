from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from scans.constants import (
    MAX_ANALYZABLE_FILE_BYTES,
    REPOSITORY_MAX_TARGET_BYTES,
)
from scans.models import (
    AnalysisRun,
    ScanArtifact,
    ScanAttempt,
    ScanDispatchOutbox,
    ScanExecution,
    ScanFinding,
    ScanNormalizationAttempt,
    ScanOccurrence,
)
from scans.services.repository_manifest import build_repository_manifest
from scans.services.repository_runtime import build_repository_semgrep_command
from scans.services.repository_state import CE_CAPABILITIES


class RepositoryV2ModelContractTests(SimpleTestCase):
    def test_pipeline_version_defaults_to_legacy_and_exposes_v2(self):
        field = AnalysisRun._meta.get_field("pipeline_version")

        self.assertEqual(field.default, AnalysisRun.PipelineVersion.CHUNK_V1)
        self.assertEqual(
            {value for value, _label in field.choices},
            {"chunk_v1", "repository_v2"},
        )

    def test_repository_execution_is_fixed_to_one_root_scope(self):
        constraints = {constraint.name for constraint in ScanExecution._meta.constraints}

        self.assertTrue(
            {
                "scan_execution_sequence_one",
                "scan_execution_repository_scope",
                "scan_execution_root_dot",
                "scan_execution_retry_bounds",
                "scan_normalization_retry_bounds",
            }.issubset(constraints)
        )
        self.assertEqual(ScanExecution._meta.get_field("sequence").default, 1)
        self.assertEqual(ScanExecution._meta.get_field("scope_kind").default, "repository")
        self.assertEqual(ScanExecution._meta.get_field("scope_root").default, ".")

    def test_attempt_artifact_outbox_and_identity_constraints_are_declared(self):
        expected = {
            ScanAttempt: {
                "unique_scan_attempt_number",
                "unique_running_scan_attempt",
            },
            ScanArtifact: {"unique_canonical_scan_artifact"},
            ScanDispatchOutbox: {
                "unique_scan_dispatch_number",
                "unique_pending_scan_dispatch",
                "scan_dispatch_publish_bounds",
            },
            ScanNormalizationAttempt: {
                "unique_normalization_attempt_number",
                "unique_running_normalization_attempt",
            },
            ScanFinding: {"unique_scan_aggregate_fingerprint"},
            ScanOccurrence: {
                "unique_scan_occurrence_key",
                "unique_scan_raw_result_index",
            },
        }

        for model, required_names in expected.items():
            with self.subTest(model=model.__name__):
                actual_names = {constraint.name for constraint in model._meta.constraints}
                self.assertTrue(required_names.issubset(actual_names))


class RepositoryV2RuntimeContractTests(SimpleTestCase):
    def test_ce_capabilities_do_not_claim_pro_or_interfile_analysis(self):
        self.assertEqual(
            CE_CAPABILITIES,
            {
                "engine_mode": "ce",
                "repository_context_present": True,
                "cross_file_parsing": False,
                "cross_function_dataflow": False,
                "interfile_dataflow": False,
                "interfile_taint": False,
                "pro_engine": False,
            },
        )

    def test_semgrep_command_has_one_root_and_explicit_resource_limits(self):
        self.assertEqual(MAX_ANALYZABLE_FILE_BYTES, 10 * 1024 * 1024)
        self.assertEqual(REPOSITORY_MAX_TARGET_BYTES, MAX_ANALYZABLE_FILE_BYTES)

        with self.subTest("command"):
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as directory:
                root = Path(directory)
                rule = root / "rules.yml"
                rule.write_text("rules: []\n", encoding="utf-8")
                with mock.patch(
                    "scans.services.repository_runtime.get_semgrep_rule_path",
                    return_value=rule,
                ):
                    command = build_repository_semgrep_command(root, ["python", "javascript"])

        self.assertEqual(command[0:3], ["semgrep", "--json", "--metrics=off"])
        self.assertEqual(command.count("--config"), 2)
        self.assertEqual(command.count(str(root.resolve())), 1)
        self.assertEqual(command[-1], str(root.resolve()))
        for flag in ("--jobs", "--timeout", "--max-memory", "--max-target-bytes"):
            self.assertIn(flag, command)
        target_index = command.index("--max-target-bytes")
        self.assertEqual(command[target_index + 1], str(10 * 1024 * 1024))


class RepositoryV2ManifestContractTests(SimpleTestCase):
    def test_digest_is_stable_across_run_identity_and_covers_evidence(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            base = Path(directory)
            original = base / "original"
            original.mkdir()
            source = original / "app.py"
            source.write_text("print('ok')\n", encoding="utf-8")
            (original / ".semgrepignore").write_text("vendor/\n", encoding="utf-8")
            (original / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

            snapshot = SimpleNamespace(
                relative_path="app.py",
                language="python",
                size_bytes=source.stat().st_size,
                file_class="normal",
                content_sha256="0" * 64,
            )

            manifests = []
            for run_id in (101, 202):
                run_root = base / f"run-{run_id}"
                source_root = run_root / "source"
                source_root.mkdir(parents=True)
                (source_root / "app.py").write_bytes(source.read_bytes())
                with (
                    mock.patch(
                        "scans.services.repository_manifest.get_analysis_workspace_run_root",
                        return_value=run_root,
                    ),
                    mock.patch(
                        "scans.services.repository_manifest.get_analysis_workspace_source_root",
                        return_value=source_root,
                    ),
                ):
                    manifests.append(build_repository_manifest(run_id, original, [snapshot]))

        self.assertEqual(manifests[0]["snapshot_digest"], manifests[1]["snapshot_digest"])
        self.assertNotEqual(manifests[0]["analysis_run_id"], manifests[1]["analysis_run_id"])
        inventory_kinds = {item["kind"] for item in manifests[0]["inventory"]}
        self.assertEqual(
            inventory_kinds,
            {"supported_source", "semgrep_ignore", "project_marker"},
        )
