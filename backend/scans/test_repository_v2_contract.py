import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from scans.constants import (
    MAX_ANALYZABLE_FILE_BYTES,
    REPOSITORY_ARTIFACT_SAFETY_MARGIN_BYTES,
    REPOSITORY_ATTEMPT_LEASE_SECONDS,
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
from scans.services.repository_manifest import (
    RepositoryManifestError,
    _stable_sha256_file,
    build_repository_manifest,
)
from scans.services.repository_runtime import (
    SEMGREP_DIAGNOSTIC_STDERR_MAX_BYTES,
    RepositoryRuntimeError,
    _renew_attempt_lease,
    _verify_semgrep_pin,
    build_repository_semgrep_command,
    verify_repository_snapshot,
)
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
                "scan_dispatch_pending_metadata",
                "scan_dispatch_published_time",
                "scan_dispatch_claim_metadata",
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
    @mock.patch("scans.services.repository_runtime.subprocess.run")
    def test_semgrep_version_pin_requires_exact_equality(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout="Semgrep 1.175.0\n",
        )
        with self.assertRaisesRegex(RepositoryRuntimeError, "pin mismatch"):
            _verify_semgrep_pin()

        run.return_value.stdout = "1.175.0\n"
        _verify_semgrep_pin()

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

    def test_watchdog_heartbeat_renews_owned_attempt_lease(self):
        attempt = SimpleNamespace(pk=7, execution_token="owned-token")
        queryset = mock.Mock()
        queryset.update.return_value = 1

        with mock.patch.object(ScanAttempt.objects, "filter", return_value=queryset) as filter_mock:
            self.assertTrue(_renew_attempt_lease(attempt))

        filter_mock.assert_called_once_with(
            pk=7,
            status=ScanAttempt.Status.RUNNING,
            execution_token="owned-token",
        )
        update = queryset.update.call_args.kwargs
        self.assertEqual(
            (update["lease_expires_at"] - update["heartbeat_at"]).total_seconds(),
            REPOSITORY_ATTEMPT_LEASE_SECONDS,
        )

        queryset.update.return_value = 0
        with mock.patch.object(ScanAttempt.objects, "filter", return_value=queryset):
            self.assertFalse(_renew_attempt_lease(attempt))

    def test_diagnostic_stderr_has_a_bounded_runtime_cap(self):
        self.assertGreater(SEMGREP_DIAGNOSTIC_STDERR_MAX_BYTES, 0)
        self.assertLessEqual(
            SEMGREP_DIAGNOSTIC_STDERR_MAX_BYTES,
            REPOSITORY_ARTIFACT_SAFETY_MARGIN_BYTES,
        )


class RepositoryV2ManifestContractTests(SimpleTestCase):
    def test_source_hashing_stops_at_the_planning_byte_bound(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            source = Path(directory) / "growing.py"
            source.write_bytes(b"12345")

            with self.assertRaisesRegex(
                RepositoryManifestError,
                "exceeds planning byte budget while hashing",
            ):
                _stable_sha256_file(
                    source,
                    expected_size=4,
                    max_bytes=4,
                )

    def test_manifest_enrichment_fails_at_the_inventory_limit(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            base = Path(directory)
            original = base / "original"
            ignored = original / "node_modules"
            ignored.mkdir(parents=True)
            (ignored / "one.py").write_text("one", encoding="utf-8")
            (ignored / "two.py").write_text("two", encoding="utf-8")
            run_root = base / "run"
            source_root = run_root / "source"
            source_root.mkdir(parents=True)

            with (
                mock.patch(
                    "scans.services.repository_manifest.get_analysis_workspace_run_root",
                    return_value=run_root,
                ),
                mock.patch(
                    "scans.services.repository_manifest.get_analysis_workspace_source_root",
                    return_value=source_root,
                ),
                mock.patch(
                    "scans.services.repository_manifest.MAX_PLANNABLE_SOURCE_FILES",
                    1,
                ),
            ):
                with self.assertRaisesRegex(
                    RepositoryManifestError,
                    "inventory exceeds source file limit",
                ):
                    build_repository_manifest(101, original, [])

    def test_oversized_marker_and_ignore_evidence_fail_before_copy(self):
        from tempfile import TemporaryDirectory

        for evidence_name in ("pyproject.toml", ".semgrepignore"):
            with self.subTest(evidence_name=evidence_name), TemporaryDirectory() as directory:
                base = Path(directory)
                original = base / "original"
                original.mkdir()
                (original / evidence_name).write_bytes(b"12345")
                run_root = base / "run"
                source_root = run_root / "source"
                source_root.mkdir(parents=True)

                with (
                    mock.patch(
                        "scans.services.repository_manifest.get_analysis_workspace_run_root",
                        return_value=run_root,
                    ),
                    mock.patch(
                        "scans.services.repository_manifest.get_analysis_workspace_source_root",
                        return_value=source_root,
                    ),
                    mock.patch(
                        "scans.services.repository_manifest.MAX_ANALYZABLE_FILE_BYTES",
                        4,
                    ),
                ):
                    with self.assertRaisesRegex(
                        RepositoryManifestError,
                        "evidence exceeds per-file byte limit",
                    ):
                        build_repository_manifest(101, original, [])

                self.assertFalse((source_root / evidence_name).exists())

    def test_manifest_evidence_respects_total_workspace_budget(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            base = Path(directory)
            original = base / "original"
            original.mkdir()
            source = original / "app.py"
            source.write_bytes(b"1234")
            (original / "pyproject.toml").write_bytes(b"12")
            run_root = base / "run"
            source_root = run_root / "source"
            source_root.mkdir(parents=True)
            (source_root / "app.py").write_bytes(b"1234")
            snapshot = SimpleNamespace(
                relative_path="app.py",
                language="python",
                size_bytes=4,
                file_class="normal",
                content_sha256=hashlib.sha256(b"1234").hexdigest(),
            )

            with (
                mock.patch(
                    "scans.services.repository_manifest.get_analysis_workspace_run_root",
                    return_value=run_root,
                ),
                mock.patch(
                    "scans.services.repository_manifest.get_analysis_workspace_source_root",
                    return_value=source_root,
                ),
                mock.patch(
                    "scans.services.repository_manifest.MAX_PLANNABLE_ANALYZABLE_BYTES",
                    5,
                ),
            ):
                with self.assertRaisesRegex(
                    RepositoryManifestError,
                    "evidence exceeds workspace byte budget",
                ):
                    build_repository_manifest(101, original, [snapshot])

            self.assertFalse((source_root / "pyproject.toml").exists())

    def test_oversized_snapshot_row_remains_excluded_without_workspace_copy(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            base = Path(directory)
            original = base / "original"
            original.mkdir()
            oversized = original / "oversized.py"
            with oversized.open("wb") as stream:
                stream.truncate(MAX_ANALYZABLE_FILE_BYTES + 1)
            run_root = base / "run"
            source_root = run_root / "source"
            source_root.mkdir(parents=True)
            snapshot = SimpleNamespace(
                relative_path="oversized.py",
                language="python",
                size_bytes=MAX_ANALYZABLE_FILE_BYTES + 1,
                file_class="oversized",
                content_sha256="",
            )

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
                manifest = build_repository_manifest(101, original, [snapshot])

            source_item = manifest["inventory"][0]
            self.assertEqual(source_item["path"], "oversized.py")
            self.assertFalse(source_item["eligibility"])
            self.assertEqual(source_item["exclusion_reason"], "oversized")
            self.assertEqual(
                source_item["content_sha256"],
                hashlib.sha256(oversized.read_bytes()).hexdigest(),
            )
            self.assertFalse((source_root / "oversized.py").exists())
            verify_repository_snapshot(source_root, manifest)

    def test_excluded_source_content_changes_snapshot_digest(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            base = Path(directory)
            original = base / "original"
            ignored = original / "node_modules"
            ignored.mkdir(parents=True)
            excluded = ignored / "ignored.py"
            excluded.write_bytes(b"first")

            digests = []
            for run_name, content in (("run-one", b"first"), ("run-two", b"other")):
                excluded.write_bytes(content)
                run_root = base / run_name
                source_root = run_root / "source"
                source_root.mkdir(parents=True)
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
                    manifest = build_repository_manifest(101, original, [])
                digests.append(manifest["snapshot_digest"])

            self.assertNotEqual(*digests)

    def test_manifest_and_runtime_verify_immutable_workspace_bytes(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            base = Path(directory)
            original = base / "original"
            original.mkdir()
            original_source = original / "app.py"
            original_source.write_text("print('original')\n", encoding="utf-8")
            (original / ".semgrepignore").write_text("vendor/\n", encoding="utf-8")
            run_root = base / "run"
            source_root = run_root / "source"
            source_root.mkdir(parents=True)
            workspace_bytes = b"print('immutable')\n"
            (source_root / "app.py").write_bytes(workspace_bytes)
            snapshot = SimpleNamespace(
                relative_path="app.py",
                language="python",
                size_bytes=len(workspace_bytes),
                file_class="normal",
                content_sha256=hashlib.sha256(workspace_bytes).hexdigest(),
            )

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
                manifest = build_repository_manifest(101, original, [snapshot])

            source_item = next(
                item for item in manifest["inventory"]
                if item["kind"] == "supported_source"
            )
            self.assertEqual(source_item["size"], len(workspace_bytes))
            self.assertEqual(
                source_item["content_sha256"],
                hashlib.sha256(workspace_bytes).hexdigest(),
            )
            verify_repository_snapshot(source_root, manifest)

            (source_root / "app.py").write_text("print('changed')\n", encoding="utf-8")
            with self.assertRaisesRegex(RepositoryRuntimeError, "does not match manifest"):
                verify_repository_snapshot(source_root, manifest)

            (source_root / "app.py").write_bytes(workspace_bytes)
            (source_root / ".semgrepignore").write_text("changed/\n", encoding="utf-8")
            with self.assertRaisesRegex(RepositoryRuntimeError, "does not match manifest"):
                verify_repository_snapshot(source_root, manifest)

            (source_root / ".semgrepignore").write_text("vendor/\n", encoding="utf-8")
            (source_root / "injected.py").write_text("print('new')\n", encoding="utf-8")
            with self.assertRaisesRegex(RepositoryRuntimeError, "unexpected scan input"):
                verify_repository_snapshot(source_root, manifest)

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
