import shutil

from django.db import transaction
from django.db.models.signals import pre_delete
from django.dispatch import receiver

from .models import AnalysisRun
from .services.source_snapshot import get_analysis_workspace_run_root


def _remove_run_files(path):
    shutil.rmtree(path, ignore_errors=True)


@receiver(pre_delete, sender=AnalysisRun)
def cleanup_repository_files_after_run_delete(sender, instance, using, **kwargs):
    # Register from pre_delete so QuerySet/cascade deletes are covered. The
    # callback only runs after a successful commit; rollback retains evidence.
    path = get_analysis_workspace_run_root(instance.pk)
    transaction.on_commit(lambda: _remove_run_files(path), using=using)
