from datetime import timedelta

from django.core.management.base import (
    BaseCommand,
    CommandError,
)
from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from scans.models import (
    AnalysisChunk,
    AnalysisChunkAttempt,
    AnalysisDispatchOutbox,
    AnalysisRun,
)
from scans.services.chunk_executor import (
    claim_chunk,
)
from scans.services.chunk_recovery import (
    recover_pending_analysis_runs,
    recover_pending_outboxes,
    recover_stale_attempt,
)


class Command(BaseCommand):

    help = (
        "Pending AnalysisRun / "
        "Stale Chunk Attempt / "
        "Pending Outbox Recovery를 검증합니다."
    )

    # ====================================
    # PASS
    # ====================================

    def pass_test(
        self,
        number,
        message,
    ):

        self.stdout.write(
            self.style.SUCCESS(
                f"[PASS {number}] "
                f"{message}"
            )
        )

    # ====================================
    # Assert True
    # ====================================

    def assert_true(
        self,
        number,
        condition,
        message,
    ):

        if not condition:

            raise CommandError(
                f"\n[FAIL {number}] "
                f"{message}"
            )

        self.pass_test(
            number,
            message,
        )

    # ====================================
    # Assert Equal
    # ====================================

    def assert_equal(
        self,
        number,
        actual,
        expected,
        message,
    ):

        if actual != expected:

            raise CommandError(
                f"\n[FAIL {number}] "
                f"{message}\n"
                f"expected={expected}\n"
                f"actual={actual}"
            )

        self.pass_test(
            number,
            message,
        )

    # ====================================
    # AnalysisRun Helper
    # ====================================

    def create_run(
        self,
        base_run,
        sequence,
        status,
    ):

        started_at = None

        if (
            status
            ==
            AnalysisRun.Status.RUNNING
        ):

            started_at = (
                timezone.now()
            )

        return (
            AnalysisRun.objects.create(
                project=
                    base_run.project,
                source_version=
                    base_run.source_version,
                sequence=
                    sequence,
                status=
                    status,
                engine=
                    "Semgrep",
                analysis_language=
                    "python",
                analysis_languages=[
                    "python"
                ],
                executed_by=
                    base_run.executed_by,
                started_at=
                    started_at,
            )
        )

    # ====================================
    # Chunk Helper
    # ====================================

    def create_chunk(
        self,
        analysis_run,
        sequence,
        retry_count=0,
        max_retries=3,
        status=None,
    ):

        if status is None:

            status = (
                AnalysisChunk.Status.QUEUED
            )

        return (
            AnalysisChunk.objects.create(
                analysis_run=
                    analysis_run,
                language=
                    "python",
                sequence=
                    sequence,
                status=
                    status,
                file_count=
                    1,
                total_bytes=
                    100,
                retry_count=
                    retry_count,
                max_retries=
                    max_retries,
            )
        )

    # ====================================
    # Attempt Lease 강제 만료
    # ====================================

    def expire_attempt(
        self,
        attempt_id,
    ):

        expired_at = (
            timezone.now()
            -
            timedelta(
                seconds=10
            )
        )

        AnalysisChunkAttempt.objects.filter(
            pk=attempt_id
        ).update(
            lease_expires_at=
                expired_at
        )

    # ====================================
    # Main
    # ====================================

    def handle(
        self,
        *args,
        **options,
    ):

        self.stdout.write(
            self.style.MIGRATE_HEADING(
                "\n"
                "========================================\n"
                "Chunk Recovery Test\n"
                "========================================"
            )
        )

        base_run = (
            AnalysisRun.objects
            .select_related(
                "project",
                "source_version",
                "executed_by",
            )
            .order_by(
                "id"
            )
            .first()
        )

        if base_run is None:

            raise CommandError(
                "기존 AnalysisRun이 필요합니다."
            )

        with transaction.atomic():

            max_sequence = (
                AnalysisRun.objects
                .filter(
                    project=
                        base_run.project
                )
                .aggregate(
                    value=
                        Max(
                            "sequence"
                        )
                )
                ["value"]
                or 0
            )

            base_sequence = (
                max_sequence
                + 8000
            )

            # =================================
            # GROUP A
            #
            # Stale Worker
            # Retry 가능
            # =================================

            retry_run = (
                self.create_run(
                    base_run,
                    base_sequence,
                    AnalysisRun.Status.RUNNING,
                )
            )

            retry_chunk = (
                self.create_chunk(
                    retry_run,
                    1,
                )
            )

            # Planner가 만들었다고 가정한
            # 최초 Outbox #1
            AnalysisDispatchOutbox.objects.create(
                chunk=
                    retry_chunk,
                dispatch_no=
                    1,
                status=
                    AnalysisDispatchOutbox.Status.PUBLISHED,
                publish_attempts=
                    1,
                celery_task_id=
                    "initial-task",
                published_at=
                    timezone.now(),
            )

            retry_claim = (
                claim_chunk(
                    retry_chunk.id,
                    celery_task_id=
                        "lost-worker-task",
                )
            )

            self.assert_true(
                1,
                retry_claim["claimed"],
                "Stale Recovery 테스트 Chunk Claim 성공",
            )

            self.expire_attempt(
                retry_claim["attempt_id"]
            )

            recovery_result = (
                recover_stale_attempt(
                    retry_claim["attempt_id"]
                )
            )

            retry_attempt = (
                AnalysisChunkAttempt.objects
                .get(
                    pk=
                        retry_claim["attempt_id"]
                )
            )

            retry_chunk.refresh_from_db()
            retry_run.refresh_from_db()

            self.assert_true(
                2,
                recovery_result["recovered"],
                "Lease 만료 Attempt Recovery 성공",
            )

            self.assert_equal(
                3,
                retry_attempt.status,
                AnalysisChunkAttempt.Status.WORKER_LOST,
                "Stale Attempt → worker_lost",
            )

            self.assert_equal(
                4,
                retry_chunk.status,
                AnalysisChunk.Status.RETRY_PENDING,
                "Worker Lost 후 Chunk retry_pending",
            )

            self.assert_equal(
                5,
                retry_chunk.retry_count,
                0,
                (
                    "Recovery 예약 단계에서는 "
                    "retry_count 증가 안 함"
                ),
            )

            retry_outboxes = (
                AnalysisDispatchOutbox.objects
                .filter(
                    chunk=
                        retry_chunk
                )
                .order_by(
                    "dispatch_no"
                )
            )

            self.assert_equal(
                6,
                retry_outboxes.count(),
                2,
                "Worker Lost Retry Outbox 생성",
            )

            retry_outbox = (
                retry_outboxes.last()
            )

            self.assert_equal(
                7,
                retry_outbox.dispatch_no,
                2,
                "Recovery Retry Outbox dispatch_no = 2",
            )

            self.assert_equal(
                8,
                retry_outbox.status,
                AnalysisDispatchOutbox.Status.PENDING,
                "Recovery Retry Outbox pending",
            )

            self.assert_equal(
                9,
                retry_run.status,
                AnalysisRun.Status.RUNNING,
                "retry_pending 존재 시 Run running 유지",
            )

            # =================================
            # 동일 Attempt Recovery 반복
            # =================================

            duplicate_recovery = (
                recover_stale_attempt(
                    retry_claim["attempt_id"]
                )
            )

            self.assert_true(
                10,
                not duplicate_recovery["recovered"],
                "동일 Stale Attempt 중복 Recovery 차단",
            )

            self.assert_equal(
                11,
                AnalysisDispatchOutbox.objects
                .filter(
                    chunk=
                        retry_chunk
                )
                .count(),
                2,
                "중복 Recovery가 Outbox를 추가 생성하지 않음",
            )

            # =================================
            # GROUP B
            #
            # Retry Budget 소진
            # =================================

            exhausted_run = (
                self.create_run(
                    base_run,
                    base_sequence + 1,
                    AnalysisRun.Status.RUNNING,
                )
            )

            exhausted_chunk = (
                self.create_chunk(
                    exhausted_run,
                    1,
                    retry_count=
                        3,
                    max_retries=
                        3,
                )
            )

            exhausted_claim = (
                claim_chunk(
                    exhausted_chunk.id,
                    celery_task_id=
                        "exhausted-worker",
                )
            )

            self.assert_true(
                12,
                exhausted_claim["claimed"],
                "Retry 소진 테스트 현재 Attempt Claim 성공",
            )

            self.expire_attempt(
                exhausted_claim["attempt_id"]
            )

            recover_stale_attempt(
                exhausted_claim["attempt_id"]
            )

            exhausted_attempt = (
                AnalysisChunkAttempt.objects
                .get(
                    pk=
                        exhausted_claim["attempt_id"]
                )
            )

            exhausted_chunk.refresh_from_db()
            exhausted_run.refresh_from_db()

            self.assert_equal(
                13,
                exhausted_attempt.status,
                AnalysisChunkAttempt.Status.WORKER_LOST,
                "Retry 소진 Stale Attempt worker_lost",
            )

            self.assert_equal(
                14,
                exhausted_chunk.status,
                AnalysisChunk.Status.FAILED,
                "Retry 소진 Worker Lost → Chunk failed",
            )

            self.assert_equal(
                15,
                exhausted_chunk.status_reason,
                "WORKER_LOST_MAX_RETRIES_EXCEEDED",
                "Retry 소진 Worker Lost 사유 저장",
            )

            self.assert_equal(
                16,
                AnalysisDispatchOutbox.objects
                .filter(
                    chunk=
                        exhausted_chunk
                )
                .count(),
                0,
                "Retry 소진 시 새 Outbox 생성 안 함",
            )

            self.assert_equal(
                17,
                exhausted_run.status,
                AnalysisRun.Status.FAILED,
                "최종 Worker Lost 실패 후 Run failed",
            )

            # =================================
            # GROUP C
            #
            # Lease 아직 살아 있음
            # =================================

            alive_run = (
                self.create_run(
                    base_run,
                    base_sequence + 2,
                    AnalysisRun.Status.RUNNING,
                )
            )

            alive_chunk = (
                self.create_chunk(
                    alive_run,
                    1,
                )
            )

            alive_claim = (
                claim_chunk(
                    alive_chunk.id,
                    celery_task_id=
                        "alive-worker",
                )
            )

            alive_recovery = (
                recover_stale_attempt(
                    alive_claim["attempt_id"]
                )
            )

            self.assert_true(
                18,
                not alive_recovery["recovered"],
                "Lease가 살아 있는 Attempt는 Recovery 안 함",
            )

            self.assert_equal(
                19,
                alive_recovery["reason"],
                "lease_not_expired",
                "정상 Worker Lease 판정",
            )

            # =================================
            # GROUP D
            #
            # 오래된 Pending AnalysisRun
            # Bootstrap Recovery
            # =================================

            old_pending_run = (
                self.create_run(
                    base_run,
                    base_sequence + 3,
                    AnalysisRun.Status.PENDING,
                )
            )

            self.create_run(
                base_run,
                base_sequence + 4,
                AnalysisRun.Status.PENDING,
            )

            old_time = (
                timezone.now()
                -
                timedelta(
                    seconds=120
                )
            )

            AnalysisRun.objects.filter(
                pk=
                    old_pending_run.id
            ).update(
                updated_at=
                    old_time
            )

            published_run_ids = []

            def fake_bootstrap_publisher(
                analysis_run_id,
            ):

                published_run_ids.append(
                    analysis_run_id
                )

                return (
                    f"fake-bootstrap-"
                    f"{analysis_run_id}"
                )

            pending_recovery = (
                recover_pending_analysis_runs(
                    publish_func=
                        fake_bootstrap_publisher,
                    batch_size=
                        10,
                    grace_seconds=
                        30,
                )
            )

            self.assert_equal(
                20,
                pending_recovery["published_count"],
                1,
                "오래된 Pending AnalysisRun 재전송",
            )

            self.assert_equal(
                21,
                published_run_ids,
                [
                    old_pending_run.id
                ],
                "Fresh Pending Run은 Recovery 대상에서 제외",
            )

            second_pending_recovery = (
                recover_pending_analysis_runs(
                    publish_func=
                        fake_bootstrap_publisher,
                    batch_size=
                        10,
                    grace_seconds=
                        30,
                )
            )

            self.assert_equal(
                22,
                second_pending_recovery["published_count"],
                0,
                (
                    "성공한 Pending Recovery는 "
                    "즉시 다시 publish하지 않음"
                ),
            )

            # =================================
            # GROUP E
            #
            # Bootstrap Broker Failure
            # =================================

            failed_pending_run = (
                self.create_run(
                    base_run,
                    base_sequence + 5,
                    AnalysisRun.Status.PENDING,
                )
            )

            AnalysisRun.objects.filter(
                pk=
                    failed_pending_run.id
            ).update(
                updated_at=
                    old_time
            )

            def failing_bootstrap_publisher(
                analysis_run_id,
            ):

                raise RuntimeError(
                    "TEST_REDIS_DOWN"
                )

            failed_bootstrap_result = (
                recover_pending_analysis_runs(
                    publish_func=
                        failing_bootstrap_publisher,
                    batch_size=
                        10,
                    grace_seconds=
                        30,
                )
            )

            failed_pending_run.refresh_from_db()

            self.assert_equal(
                23,
                failed_bootstrap_result["failed_count"],
                1,
                "Bootstrap Redis 실패 집계",
            )

            self.assert_equal(
                24,
                failed_pending_run.status,
                AnalysisRun.Status.PENDING,
                "Bootstrap publish 실패 시 Run pending 유지",
            )

            # =================================
            # GROUP F
            #
            # Pending Outbox Recovery
            # =================================

            outbox_run = (
                self.create_run(
                    base_run,
                    base_sequence + 6,
                    AnalysisRun.Status.RUNNING,
                )
            )

            outbox_chunk = (
                self.create_chunk(
                    outbox_run,
                    1,
                )
            )

            pending_outbox = (
                AnalysisDispatchOutbox.objects.create(
                    chunk=
                        outbox_chunk,
                    dispatch_no=
                        1,
                    status=
                        AnalysisDispatchOutbox.Status.PENDING,
                )
            )

            # =================================
            # 중요: 테스트 격리
            #
            # 앞선 Group A에서도 Worker Lost
            # Recovery가 Retry Outbox를 하나
            # PENDING으로 생성한다.
            #
            # recover_pending_outboxes()는
            # 특정 테스트 Chunk가 아니라
            # "현재 publish 가능한 모든 Pending
            # Outbox"를 처리하는 Production 함수다.
            #
            # 따라서 Group F에서 대상 Outbox만
            # 검증하려면, 이 테스트 대상 외의
            # Pending Outbox는 available_at을
            # 잠시 미래로 미뤄야 한다.
            #
            # 전체 command가 transaction rollback
            # 되므로 실제 DB에는 영향이 남지 않는다.
            # =================================

            isolation_future_time = (
                timezone.now()
                +
                timedelta(
                    hours=1
                )
            )

            (
                AnalysisDispatchOutbox.objects
                .filter(
                    status=
                        AnalysisDispatchOutbox.Status.PENDING
                )
                .exclude(
                    pk=
                        pending_outbox.pk
                )
                .update(
                    available_at=
                        isolation_future_time
                )
            )

            published_chunk_ids = []

            def fake_outbox_publisher(
                chunk_id,
            ):

                published_chunk_ids.append(
                    chunk_id
                )

                return (
                    f"fake-chunk-"
                    f"{chunk_id}"
                )

            outbox_recovery = (
                recover_pending_outboxes(
                    publish_func=
                        fake_outbox_publisher,
                    batch_size=
                        10,
                )
            )

            pending_outbox.refresh_from_db()

            self.assert_equal(
                25,
                published_chunk_ids,
                [
                    outbox_chunk.id
                ],
                "Pending Outbox Recovery가 chunk_id publish",
            )

            self.assert_equal(
                26,
                pending_outbox.status,
                AnalysisDispatchOutbox.Status.PUBLISHED,
                "Recovery 후 Pending Outbox published",
            )

            self.assert_equal(
                27,
                outbox_recovery["published_count"],
                1,
                "Pending Outbox Recovery publish 집계",
            )

            # =================================
            # Rollback
            # =================================

            transaction.set_rollback(
                True
            )

        self.stdout.write(
            self.style.SUCCESS(
                "\n"
                "========================================\n"
                "Chunk Recovery Test Finished\n"
                "모든 테스트 데이터는 Rollback 되었습니다.\n"
                "========================================"
            )
        )
