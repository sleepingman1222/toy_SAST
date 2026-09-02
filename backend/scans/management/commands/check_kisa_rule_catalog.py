import json

from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from scans.services.kisa_rule_catalog import (
    build_catalog_report,
    validate_kisa_rule_catalog,
)


class Command(BaseCommand):

    help = (
        "KISA Semgrep Custom Rule Catalog의 "
        "YAML 구조와 DB Master Data 정합성을 검사합니다."
    )


    def add_arguments(
        self,
        parser,
    ):

        parser.add_argument(
            "--full-coverage",
            action="store_true",
            help=(
                "49개 KISA 항목 모두에 "
                "최소 1개 이상의 자동 Rule이 "
                "존재하는지까지 검사합니다."
            ),
        )

        parser.add_argument(
            "--json",
            action="store_true",
            help=(
                "검사 결과를 JSON으로 출력합니다."
            ),
        )


    def handle(
        self,
        *args,
        **options,
    ):

        result = (
            validate_kisa_rule_catalog(
                require_full_master=
                    True,

                require_full_coverage=
                    options[
                        "full_coverage"
                    ],
            )
        )

        report = (
            build_catalog_report(
                result
            )
        )

        if options[
            "json"
        ]:

            self.stdout.write(
                json.dumps(
                    report,
                    ensure_ascii=False,
                    indent=2,
                )
            )

        else:

            self.stdout.write(
                self.style.MIGRATE_HEADING(
                    "\n"
                    "========================================\n"
                    "KISA Semgrep Rule Catalog Check\n"
                    "========================================"
                )
            )

            self.stdout.write(
                f"KISA Master       : "
                f"{result.master_count}/49"
            )

            self.stdout.write(
                f"Rule Files        : "
                f"{result.rule_file_count}"
            )

            self.stdout.write(
                f"Rules             : "
                f"{result.rule_count}"
            )

            self.stdout.write(
                f"KISA Covered      : "
                f"{result.covered_kisa_count}/49"
            )

            self.stdout.write(
                "\n[Language Rule Count]"
            )

            for (
                language,
                count,
            ) in (
                result
                .coverage_by_language
                .items()
            ):

                self.stdout.write(
                    f"- {language}: {count}"
                )

            if result.warnings:

                self.stdout.write(
                    "\n[Warnings]"
                )

                for warning in (
                    result.warnings
                ):

                    location = " / ".join(
                        item
                        for item
                        in (
                            warning.file_path,
                            warning.rule_id,
                        )
                        if item
                    )

                    self.stdout.write(
                        self.style.WARNING(
                            (
                                f"- [{warning.code}] "
                                f"{warning.message}"
                                +
                                (
                                    f" ({location})"
                                    if location
                                    else ""
                                )
                            )
                        )
                    )

            if result.errors:

                self.stdout.write(
                    "\n[Errors]"
                )

                for error in (
                    result.errors
                ):

                    location = " / ".join(
                        item
                        for item
                        in (
                            error.file_path,
                            error.rule_id,
                        )
                        if item
                    )

                    self.stdout.write(
                        self.style.ERROR(
                            (
                                f"- [{error.code}] "
                                f"{error.message}"
                                +
                                (
                                    f" ({location})"
                                    if location
                                    else ""
                                )
                            )
                        )
                    )

            self.stdout.write(
                "\n[Coverage]"
            )

            for (
                identifier,
                coverage,
            ) in (
                result
                .coverage_by_kisa
                .items()
            ):

                if (
                    coverage[
                        "rule_count"
                    ]
                    ==
                    0
                ):
                    continue

                language_text = ", ".join(
                    (
                        f"{language}="
                        f"{count}"
                    )
                    for (
                        language,
                        count,
                    )
                    in coverage[
                        "languages"
                    ].items()
                    if count > 0
                )

                self.stdout.write(
                    (
                        f"- {identifier} "
                        f"{coverage['name']}: "
                        f"{coverage['rule_count']} rules "
                        f"({language_text})"
                    )
                )

        if not result.is_valid:

            raise CommandError(
                (
                    "KISA Rule Catalog 검사에 "
                    f"실패했습니다. "
                    f"errors={len(result.errors)}"
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                "\nKISA Rule Catalog 검사를 통과했습니다."
            )
        )
