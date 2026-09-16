from django.core.management.base import (
    BaseCommand,
    CommandError,
)
from django.db import transaction

from scans.kisa_catalog_codes import (
    KISA_CATEGORY_BY_ITEM_NUMBER,
    KISA_IDENTIFIER_BY_ITEM_NUMBER,
)
from scans.kisa_master_data import (
    KISA_SECURITY_WEAKNESSES,
)
from scans.models import (
    KisaSecurityWeakness,
)


class Command(BaseCommand):
    help = (
        "KISA 구현단계 보안약점 49개 Master Data를 "
        "생성 또는 동기화합니다."
    )

    def add_arguments(
        self,
        parser,
    ):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=(
                "DB 변경 없이 동기화 예정 결과만 확인합니다."
            ),
        )

    def handle(
        self,
        *args,
        **options,
    ):
        dry_run = options["dry_run"]

        if len(KISA_SECURITY_WEAKNESSES) != 49:
            raise CommandError(
                "KISA Master 정의가 49개가 아닙니다."
            )

        item_numbers = {
            item["item_number"]
            for item in KISA_SECURITY_WEAKNESSES
        }

        if item_numbers != set(range(1, 50)):
            raise CommandError(
                "item_number는 1~49가 정확히 한 번씩 존재해야 합니다."
            )

        identifiers = {
            item["identifier"]
            for item in KISA_SECURITY_WEAKNESSES
        }

        expected_identifiers = set(
            KISA_IDENTIFIER_BY_ITEM_NUMBER.values()
        )

        if identifiers != expected_identifiers:
            raise CommandError(
                "identifier가 카테고리 기반 KISA 카탈로그 코드와 "
                "일치하지 않습니다."
            )

        for item in KISA_SECURITY_WEAKNESSES:

            item_number = item["item_number"]

            expected_identifier = (
                KISA_IDENTIFIER_BY_ITEM_NUMBER[
                    item_number
                ]
            )

            expected_category = (
                KISA_CATEGORY_BY_ITEM_NUMBER[
                    item_number
                ]
            )

            if (
                item["identifier"]
                !=
                expected_identifier
            ):

                raise CommandError(
                    "KISA identifier 매핑 오류: "
                    f"item_number={item_number}, "
                    f"expected={expected_identifier}, "
                    f"actual={item['identifier']}"
                )

            if (
                item["category"]
                !=
                expected_category
            ):

                raise CommandError(
                    "KISA category 매핑 오류: "
                    f"item_number={item_number}, "
                    f"expected={expected_category}, "
                    f"actual={item['category']}"
                )

        created_count = 0
        updated_count = 0
        unchanged_count = 0

        with transaction.atomic():
            for item in KISA_SECURITY_WEAKNESSES:
                item_number = item["item_number"]
                identifier = item["identifier"]

                weakness = (
                    KisaSecurityWeakness.objects
                    .filter(
                        item_number=item_number
                    )
                    .first()
                )

                if weakness is None:

                    legacy_identifiers = [
                        f"KISA-SW-{item_number:02d}",
                        f"KISA-SW-{item_number:03d}",
                        f"SW-{item_number:02d}",
                    ]

                    weakness = (
                        KisaSecurityWeakness.objects
                        .filter(
                            identifier__in=[
                                identifier,
                                *legacy_identifiers,
                            ]
                        )
                        .first()
                    )

                created = weakness is None

                if created:
                    weakness = KisaSecurityWeakness(
                        item_number=item_number
                    )

                conflicting = (
                    KisaSecurityWeakness.objects
                    .filter(
                        identifier=identifier
                    )
                    .exclude(
                        pk=weakness.pk
                    )
                    .first()
                )

                if conflicting is not None:
                    raise CommandError(
                        "KISA identifier 충돌: "
                        f"identifier={identifier}, "
                        f"item_number={item_number}, "
                        f"conflicting_pk={conflicting.pk}"
                    )

                old_values = (
                    weakness.identifier,
                    weakness.category,
                    weakness.item_number,
                    weakness.name,
                    weakness.description,
                    weakness.implementation_status,
                )

                weakness.identifier = identifier
                weakness.category = item["category"]
                weakness.item_number = item_number
                weakness.name = item["name"]
                weakness.description = item["description"]

                if created:
                    weakness.implementation_status = (
                        KisaSecurityWeakness
                        .ImplementationStatus
                        .NOT_IMPLEMENTED
                    )

                new_values = (
                    weakness.identifier,
                    weakness.category,
                    weakness.item_number,
                    weakness.name,
                    weakness.description,
                    weakness.implementation_status,
                )

                if created:
                    action = "CREATE"
                    created_count += 1

                elif old_values != new_values:
                    action = "UPDATE"
                    updated_count += 1

                else:
                    action = "KEEP"
                    unchanged_count += 1

                self.stdout.write(
                    f"[{action}] {identifier} {item['name']}"
                )

                if not dry_run:
                    weakness.save()

            if dry_run:
                transaction.set_rollback(True)

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    "\nDRY-RUN: DB 변경사항을 롤백했습니다."
                )
            )

        else:
            actual_count = (
                KisaSecurityWeakness.objects
                .count()
            )

            if actual_count != 49:
                raise CommandError(
                    "동기화 후 KISA Master가 49개가 아닙니다. "
                    f"actual={actual_count}"
                )

        self.stdout.write(
            self.style.SUCCESS(
                "\nKISA Master 동기화 완료 "
                f"(created={created_count}, "
                f"updated={updated_count}, "
                f"unchanged={unchanged_count})"
            )
        )
