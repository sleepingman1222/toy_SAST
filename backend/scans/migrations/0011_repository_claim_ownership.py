import django.db.models.deletion
from django.db import migrations, models


def backfill_claim_ownership(apps, schema_editor):
    Outbox = apps.get_model("scans", "ScanDispatchOutbox")
    NormalizationAttempt = apps.get_model("scans", "ScanNormalizationAttempt")
    for outbox in Outbox.objects.filter(claimed_at__isnull=False).iterator():
        if outbox.kind == "normalization":
            attempt = NormalizationAttempt.objects.filter(
                execution_id=outbox.execution_id,
                attempt_no=outbox.dispatch_no,
            ).first()
            if attempt is None:
                attempt = NormalizationAttempt.objects.filter(
                    execution_id=outbox.execution_id,
                    started_at__gte=outbox.claimed_at,
                ).order_by("started_at", "pk").first()
            if attempt is None:
                outbox.claimed_at = None
                outbox.save(update_fields=["claimed_at"])
            else:
                outbox.claimed_normalization_attempt_id = attempt.pk
                outbox.save(update_fields=["claimed_normalization_attempt"])
        elif outbox.claimed_attempt_id is None:
            outbox.claimed_at = None
            outbox.save(update_fields=["claimed_at"])


class Migration(migrations.Migration):
    dependencies = [
        ("scans", "0010_repository_outbox_state_constraints"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanattempt",
            name="process_session_id",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="scanattempt",
            name="process_start_ticks",
            field=models.PositiveBigIntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="scandispatchoutbox",
            name="claimed_attempt",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="claimed_outboxes",
                to="scans.scanattempt",
            ),
        ),
        migrations.AddField(
            model_name="scandispatchoutbox",
            name="claimed_normalization_attempt",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="claimed_outboxes",
                to="scans.scannormalizationattempt",
            ),
        ),
        migrations.RunPython(
            backfill_claim_ownership,
            migrations.RunPython.noop,
        ),
        migrations.RemoveConstraint(
            model_name="scandispatchoutbox",
            name="scan_dispatch_pending_metadata",
        ),
        migrations.RemoveConstraint(
            model_name="scandispatchoutbox",
            name="scan_dispatch_claim_metadata",
        ),
        migrations.AddConstraint(
            model_name="scandispatchoutbox",
            constraint=models.CheckConstraint(
                condition=(
                    ~models.Q(status="pending")
                    | models.Q(
                        published_at__isnull=True,
                        claim_deadline_at__isnull=True,
                        claimed_at__isnull=True,
                        claimed_attempt__isnull=True,
                        claimed_normalization_attempt__isnull=True,
                    )
                ),
                name="scan_dispatch_pending_metadata",
            ),
        ),
        migrations.AddConstraint(
            model_name="scandispatchoutbox",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(
                        claimed_at__isnull=True,
                        claimed_attempt__isnull=True,
                        claimed_normalization_attempt__isnull=True,
                    )
                    | models.Q(
                        kind="engine",
                        claimed_at__isnull=False,
                        claimed_attempt__isnull=False,
                        claimed_normalization_attempt__isnull=True,
                    )
                    | models.Q(
                        kind="normalization",
                        claimed_at__isnull=False,
                        claimed_attempt__isnull=True,
                        claimed_normalization_attempt__isnull=False,
                    )
                ),
                name="scan_dispatch_claim_metadata",
            ),
        ),
    ]
