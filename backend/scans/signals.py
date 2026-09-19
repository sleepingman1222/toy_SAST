import logging
import shutil

from django.db import transaction
from django.db.models.signals import pre_delete
from django.dispatch import receiver

from .models import AnalysisRun
from .services.source_snapshot import get_analysis_workspace_run_root


logger = logging.getLogger(__name__)


def _remove_run_files(path):
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return False
    return True


def _remove_run_files_with_audit(run_id, path):
    try:
        return _remove_run_files(path)
    except OSError:
        logger.exception(
            "repository run filesystem cleanup failed",
            extra={
                "analysis_run_id": run_id,
                "workspace_path": str(path),
            },
        )
        raise


@receiver(pre_delete, sender=AnalysisRun)
def cleanup_repository_files_after_run_delete(sender, instance, using, **kwargs):
    # Register from pre_delete so QuerySet/cascade deletes are covered. The
    # callback only runs after a successful commit; rollback retains evidence.
    path = get_analysis_workspace_run_root(instance.pk)
    transaction.on_commit(
        lambda: _remove_run_files_with_audit(instance.pk, path),
        using=using,
    )
