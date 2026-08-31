from unittest.mock import patch

from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from scans.tasks import (
    run_analysis_recovery,
)


class Command(BaseCommand):

    help = (
        "Analysis Recovery Celery Task 등록과 "
        "Recovery Cycle 연결을 검증합니다."
    )

    def pass_test(
        self,
        number,
        message,
    ):

        self.stdout.write(
            self.style.SUCCESS(
                f"[PASS {number}] {message}"
            )
        )

    def assert_true(
        self,
        number,
        condition,
        message,
    ):

        if not condition:
            raise CommandError(
                f"\n[FAIL {number}] {message}"
            )

        self.pass_test(
            number,
            message,
        )

    def assert_equal(
        self,
        number,
        actual,
        expected,
        message,
    ):

        if actual != expected:
            raise CommandError(
                f"\n[FAIL {number}] {message}\n"
                f"expected={expected}\n"
                f"actual={actual}"
            )

        self.pass_test(
            number,
            message,
        )

    def handle(
        self,
        *args,
        **options,
    ):

        self.stdout.write(
            self.style.MIGRATE_HEADING(
                "\n"
                "========================================\n"
                "Analysis Recovery Task Test\n"
                "========================================"
            )
        )

        # ====================================
        # TEST 1
        # Celery Task 이름
        # ====================================

        self.assert_equal(
            1,
            run_analysis_recovery.name,
            "scans.tasks.run_analysis_recovery",
            "Recovery Celery Task 이름 정상",
        )

        # ====================================
        # TEST 2
        # acks_late
        # ====================================

        self.assert_true(
            2,
            bool(
                run_analysis_recovery.acks_late
            ),
            "Recovery Task acks_late 활성화",
        )

        # ====================================
        # TEST 3
        # reject_on_worker_lost
        # ====================================

        self.assert_true(
            3,
            bool(
                run_analysis_recovery.reject_on_worker_lost
            ),
            "Recovery Task reject_on_worker_lost 활성화",
        )

        fake_result = {
            "pending_runs": {
                "candidate_count": 1,
                "published_count": 1,
            },
            "stale_attempts": {
                "candidate_count": 2,
                "recovered_count": 2,
            },
            "outboxes": {
                "claimed_count": 3,
                "published_count": 3,
            },
        }

        # ====================================
        # 실제 Broker / DB Recovery는 호출하지 않고
        # Task가 Service 진입점을 정확히 한 번
        # 호출하는지만 검증한다.
        # ====================================

        with patch(
            "scans.tasks.run_recovery_cycle",
            return_value=fake_result,
        ) as recovery_mock:

            result = (
                run_analysis_recovery.run()
            )

        # ====================================
        # TEST 4
        # ====================================

        self.assert_equal(
            4,
            recovery_mock.call_count,
            1,
            "Recovery Task가 run_recovery_cycle을 1회 호출",
        )

        # ====================================
        # TEST 5
        # ====================================

        self.assert_equal(
            5,
            result,
            fake_result,
            "Recovery Cycle 결과를 Celery Task가 그대로 반환",
        )

        # ====================================
        # TEST 6
        # 핵심 세 Recovery 결과 유지
        # ====================================

        self.assert_true(
            6,
            (
                "pending_runs" in result
                and
                "stale_attempts" in result
                and
                "outboxes" in result
            ),
            "Pending Run / Stale Attempt / Outbox 결과 포함",
        )

        self.stdout.write(
            self.style.SUCCESS(
                "\n"
                "========================================\n"
                "Analysis Recovery Task Test Finished\n"
                "========================================"
            )
        )
