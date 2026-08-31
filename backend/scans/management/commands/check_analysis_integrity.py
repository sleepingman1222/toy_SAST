from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import IntegrityError, transaction
from django.db.models import Max
from django.utils import timezone

from scans.models import (
    AnalysisChunk,
    AnalysisChunkAttempt,
    AnalysisChunkFile,
    AnalysisDispatchOutbox,
    AnalysisRun,
    Vulnerability,
)


class Command(BaseCommand):

    help = (
        "AnalysisChunk 관련 DB 무결성 제약조건을 "
        "실제 PostgreSQL에서 검증합니다."
    )


    def handle(self, *args, **options):

        analysis_run = (
            AnalysisRun.objects
            .order_by("id")
            .first()
        )

        if analysis_run is None:

            self.stdout.write(
                self.style.ERROR(
                    "AnalysisRun 데이터가 없습니다.\n"
                    "기존 분석을 최소 1회 생성한 뒤 "
                    "다시 실행해주세요."
                )
            )

            return


        self.stdout.write(
            self.style.MIGRATE_HEADING(
                "\n========================================\n"
                "Analysis DB Integrity Test\n"
                "========================================"
            )
        )

        self.stdout.write(
            f"\n테스트 대상 AnalysisRun: "
            f"#{analysis_run.id}"
        )


        # ========================================
        # 전체 테스트 Transaction
        #
        # 테스트가 끝나면 강제로 Rollback하여
        # 실제 DB 데이터는 남기지 않는다.
        # ========================================

        with transaction.atomic():

            current_max_sequence = (
                AnalysisChunk.objects
                .filter(
                    analysis_run=analysis_run
                )
                .aggregate(
                    max_sequence=Max("sequence")
                )
                ["max_sequence"]
                or 0
            )

            base_sequence = (
                current_max_sequence + 1000
            )


            # ========================================
            # TEST 1
            #
            # 같은 언어의 Chunk 여러 개 생성 가능
            # ========================================

            chunk_1 = (
                AnalysisChunk.objects.create(
                    analysis_run=analysis_run,
                    language="python",
                    sequence=base_sequence,
                    status=(
                        AnalysisChunk
                        .Status
                        .PENDING
                    ),
                )
            )

            chunk_2 = (
                AnalysisChunk.objects.create(
                    analysis_run=analysis_run,
                    language="python",
                    sequence=base_sequence + 1,
                    status=(
                        AnalysisChunk
                        .Status
                        .PENDING
                    ),
                )
            )

            self.stdout.write(
                self.style.SUCCESS(
                    "\n[PASS 1] "
                    "동일 언어의 여러 Chunk 생성 가능"
                )
            )


            # ========================================
            # TEST 2
            #
            # AnalysisRun 내부 sequence 중복 방지
            # ========================================

            try:

                with transaction.atomic():

                    AnalysisChunk.objects.create(
                        analysis_run=analysis_run,
                        language="javascript",
                        sequence=base_sequence,
                    )

            except IntegrityError:

                self.stdout.write(
                    self.style.SUCCESS(
                        "[PASS 2] "
                        "동일 AnalysisRun의 "
                        "Chunk sequence 중복 차단"
                    )
                )

            else:

                self.stdout.write(
                    self.style.ERROR(
                        "[FAIL 2] "
                        "Chunk sequence 중복이 "
                        "허용되었습니다."
                    )
                )


            # ========================================
            # TEST 3
            #
            # 같은 Chunk에 동일 파일 경로
            # 중복 등록 방지
            # ========================================

            AnalysisChunkFile.objects.create(
                chunk=chunk_1,
                relative_path=(
                    "integrity_test/example.py"
                ),
                size_bytes=1024,
                file_class=(
                    AnalysisChunkFile
                    .FileClass
                    .NORMAL
                ),
            )

            try:

                with transaction.atomic():

                    AnalysisChunkFile.objects.create(
                        chunk=chunk_1,
                        relative_path=(
                            "integrity_test/example.py"
                        ),
                        size_bytes=1024,
                        file_class=(
                            AnalysisChunkFile
                            .FileClass
                            .NORMAL
                        ),
                    )

            except IntegrityError:

                self.stdout.write(
                    self.style.SUCCESS(
                        "[PASS 3] "
                        "동일 Chunk의 파일 경로 "
                        "중복 등록 차단"
                    )
                )

            else:

                self.stdout.write(
                    self.style.ERROR(
                        "[FAIL 3] "
                        "동일 파일 경로가 "
                        "중복 등록되었습니다."
                    )
                )


            # ========================================
            # TEST 4
            #
            # Running Attempt 최대 1개
            # ========================================

            lease_expires_at = (
                timezone.now()
                +
                timedelta(
                    minutes=5
                )
            )

            running_attempt = (
                AnalysisChunkAttempt.objects.create(
                    chunk=chunk_1,
                    attempt_no=1,
                    status=(
                        AnalysisChunkAttempt
                        .Status
                        .RUNNING
                    ),
                    lease_expires_at=
                        lease_expires_at,
                )
            )

            try:

                with transaction.atomic():

                    AnalysisChunkAttempt.objects.create(
                        chunk=chunk_1,
                        attempt_no=2,
                        status=(
                            AnalysisChunkAttempt
                            .Status
                            .RUNNING
                        ),
                        lease_expires_at=
                            lease_expires_at,
                    )

            except IntegrityError:

                self.stdout.write(
                    self.style.SUCCESS(
                        "[PASS 4] "
                        "동일 Chunk의 Running Attempt "
                        "중복 차단"
                    )
                )

            else:

                self.stdout.write(
                    self.style.ERROR(
                        "[FAIL 4] "
                        "Running Attempt가 "
                        "2개 생성되었습니다."
                    )
                )


            # ========================================
            # TEST 5
            #
            # Completed Attempt 최대 1개
            #
            # 별도 Chunk 사용
            # ========================================

            completed_chunk = (
                AnalysisChunk.objects.create(
                    analysis_run=analysis_run,
                    language="java",
                    sequence=base_sequence + 2,
                    status=(
                        AnalysisChunk
                        .Status
                        .COMPLETED
                    ),
                )
            )

            completed_attempt = (
                AnalysisChunkAttempt.objects.create(
                    chunk=completed_chunk,
                    attempt_no=1,
                    status=(
                        AnalysisChunkAttempt
                        .Status
                        .COMPLETED
                    ),
                    lease_expires_at=
                        lease_expires_at,
                    completed_at=
                        timezone.now(),
                )
            )

            try:

                with transaction.atomic():

                    AnalysisChunkAttempt.objects.create(
                        chunk=completed_chunk,
                        attempt_no=2,
                        status=(
                            AnalysisChunkAttempt
                            .Status
                            .COMPLETED
                        ),
                        lease_expires_at=
                            lease_expires_at,
                        completed_at=
                            timezone.now(),
                    )

            except IntegrityError:

                self.stdout.write(
                    self.style.SUCCESS(
                        "[PASS 5] "
                        "동일 Chunk의 Completed Attempt "
                        "중복 차단"
                    )
                )

            else:

                self.stdout.write(
                    self.style.ERROR(
                        "[FAIL 5] "
                        "Completed Attempt가 "
                        "2개 생성되었습니다."
                    )
                )


            # ========================================
            # TEST 6
            #
            # Attempt 번호 중복 방지
            # ========================================

            try:

                with transaction.atomic():

                    AnalysisChunkAttempt.objects.create(
                        chunk=chunk_1,
                        attempt_no=1,
                        status=(
                            AnalysisChunkAttempt
                            .Status
                            .FAILED
                        ),
                        lease_expires_at=
                            lease_expires_at,
                    )

            except IntegrityError:

                self.stdout.write(
                    self.style.SUCCESS(
                        "[PASS 6] "
                        "Chunk 내부 Attempt 번호 "
                        "중복 차단"
                    )
                )

            else:

                self.stdout.write(
                    self.style.ERROR(
                        "[FAIL 6] "
                        "Attempt 번호 중복이 "
                        "허용되었습니다."
                    )
                )


            # ========================================
            # TEST 7
            #
            # Vulnerability Fingerprint
            # 중복 방지
            # ========================================

            fingerprint = (
                "a" * 64
            )

            Vulnerability.objects.create(
                analysis_run=analysis_run,

                analysis_attempt=
                    completed_attempt,

                fingerprint=
                    fingerprint,

                analysis_language=
                    "java",

                rule_id=
                    "integrity-test-rule",

                name=
                    "Integrity Test Vulnerability",

                severity=
                    Vulnerability
                    .Severity
                    .HIGH,

                confidence=
                    Vulnerability
                    .Confidence
                    .HIGH,

                file_path=
                    "integrity_test/Test.java",

                line=10,

                message=
                    "DB integrity test",

                evidence=
                    "test",

                recommendation=
                    "test",
            )

            try:

                with transaction.atomic():

                    Vulnerability.objects.create(
                        analysis_run=
                            analysis_run,

                        analysis_attempt=
                            completed_attempt,

                        fingerprint=
                            fingerprint,

                        analysis_language=
                            "java",

                        rule_id=
                            "integrity-test-rule",

                        name=
                            "Integrity Test Vulnerability",

                        severity=
                            Vulnerability
                            .Severity
                            .HIGH,

                        confidence=
                            Vulnerability
                            .Confidence
                            .HIGH,

                        file_path=
                            "integrity_test/Test.java",

                        line=10,

                        message=
                            "duplicate",

                        evidence=
                            "duplicate",

                        recommendation=
                            "duplicate",
                    )

            except IntegrityError:

                self.stdout.write(
                    self.style.SUCCESS(
                        "[PASS 7] "
                        "동일 Attempt의 Vulnerability "
                        "fingerprint 중복 차단"
                    )
                )

            else:

                self.stdout.write(
                    self.style.ERROR(
                        "[FAIL 7] "
                        "동일 fingerprint가 "
                        "중복 저장되었습니다."
                    )
                )


            # ========================================
            # TEST 8
            #
            # Outbox dispatch_no 중복 방지
            # ========================================

            AnalysisDispatchOutbox.objects.create(
                chunk=chunk_2,
                dispatch_no=1,
            )

            try:

                with transaction.atomic():

                    AnalysisDispatchOutbox.objects.create(
                        chunk=chunk_2,
                        dispatch_no=1,
                    )

            except IntegrityError:

                self.stdout.write(
                    self.style.SUCCESS(
                        "[PASS 8] "
                        "Chunk 내부 Outbox dispatch 번호 "
                        "중복 차단"
                    )
                )

            else:

                self.stdout.write(
                    self.style.ERROR(
                        "[FAIL 8] "
                        "Outbox dispatch 번호 중복이 "
                        "허용되었습니다."
                    )
                )


            # ========================================
            # TEST 9
            #
            # 다른 Attempt에서는 동일 fingerprint
            # 사용 가능
            #
            # fingerprint uniqueness는
            # AnalysisRun 전체가 아니라
            # Attempt 내부에서만 적용되어야 한다.
            # ========================================

            second_completed_chunk = (
                AnalysisChunk.objects.create(
                    analysis_run=analysis_run,
                    language="javascript",
                    sequence=base_sequence + 3,
                    status=(
                        AnalysisChunk
                        .Status
                        .COMPLETED
                    ),
                )
            )

            second_completed_attempt = (
                AnalysisChunkAttempt.objects.create(
                    chunk=
                        second_completed_chunk,

                    attempt_no=1,

                    status=(
                        AnalysisChunkAttempt
                        .Status
                        .COMPLETED
                    ),

                    lease_expires_at=
                        lease_expires_at,

                    completed_at=
                        timezone.now(),
                )
            )

            try:

                Vulnerability.objects.create(
                    analysis_run=
                        analysis_run,

                    analysis_attempt=
                        second_completed_attempt,

                    fingerprint=
                        fingerprint,

                    analysis_language=
                        "javascript",

                    rule_id=
                        "integrity-test-rule",

                    name=
                        "Integrity Test Vulnerability",

                    severity=
                        Vulnerability
                        .Severity
                        .HIGH,

                    confidence=
                        Vulnerability
                        .Confidence
                        .HIGH,

                    file_path=
                        "integrity_test/example.js",

                    line=10,

                    message=
                        "Different attempt",

                    evidence=
                        "test",

                    recommendation=
                        "test",
                )

            except IntegrityError:

                self.stdout.write(
                    self.style.ERROR(
                        "[FAIL 9] "
                        "다른 Attempt에서도 동일 "
                        "fingerprint가 차단되었습니다."
                    )
                )

            else:

                self.stdout.write(
                    self.style.SUCCESS(
                        "[PASS 9] "
                        "다른 Attempt에서는 동일 "
                        "fingerprint 사용 가능"
                    )
                )


            # ========================================
            # 테스트 데이터 Rollback
            # ========================================

            transaction.set_rollback(
                True
            )


        self.stdout.write(
            self.style.SUCCESS(
                "\n========================================\n"
                "Integrity Test Finished\n"
                "모든 테스트 데이터는 Rollback 되었습니다.\n"
                "========================================"
            )
        )