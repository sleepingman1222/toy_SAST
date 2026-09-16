from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from scans.constants import MAX_ANALYZABLE_FILE_BYTES, REPOSITORY_MAX_TARGET_BYTES
from scans.models import ScanArtifact, ScanExecution
from scans.services.repository_runtime import SEMGREP_PINNED_VERSION, _verify_semgrep_pin
from scans.services.repository_state import CE_CAPABILITIES


class Command(BaseCommand):
    help = "Verify repository-v2 schema, limits, CE capabilities, migrations, and Semgrep pin."

    def handle(self, *args, **options):
        failures = []
        if MAX_ANALYZABLE_FILE_BYTES != REPOSITORY_MAX_TARGET_BYTES:
            failures.append("snapshot and Semgrep max-target bytes differ")
        if ScanExecution._meta.get_field("scope_root").default != ".":
            failures.append("repository execution root is not fixed to '.'")
        if not ScanArtifact._meta.get_field("sha256"):
            failures.append("artifact integrity metadata is unavailable")
        expected = {
            "engine_mode": "ce",
            "repository_context_present": True,
            "cross_file_parsing": False,
            "cross_function_dataflow": False,
            "interfile_dataflow": False,
            "interfile_taint": False,
            "pro_engine": False,
        }
        if CE_CAPABILITIES != expected:
            failures.append("CE capability contract changed")
        try:
            _verify_semgrep_pin()
        except Exception as error:
            failures.append(str(error))
        call_command("makemigrations", check=True, dry_run=True, verbosity=0)
        if failures:
            raise CommandError("repository scan pipeline invalid: " + "; ".join(failures))
        self.stdout.write(
            self.style.SUCCESS(
                "repository scan pipeline OK: root=., max-target=10485760, "
                f"semgrep={SEMGREP_PINNED_VERSION}, CE capabilities verified"
            )
        )
