from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scans", "0009_alter_scanartifact_attempt"),
    ]

    operations = [
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
                    )
                ),
                name="scan_dispatch_pending_metadata",
            ),
        ),
        migrations.AddConstraint(
            model_name="scandispatchoutbox",
            constraint=models.CheckConstraint(
                condition=(
                    ~models.Q(status="published")
                    | models.Q(
                        published_at__isnull=False,
                        claim_deadline_at__isnull=False,
                    )
                ),
                name="scan_dispatch_published_time",
            ),
        ),
        migrations.AddConstraint(
            model_name="scandispatchoutbox",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(claimed_attempt__isnull=True)
                    | models.Q(claimed_at__isnull=False)
                ),
                name="scan_dispatch_claim_metadata",
            ),
        ),
    ]
