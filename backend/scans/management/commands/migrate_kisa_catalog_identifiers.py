import re
from pathlib import Path

from django.conf import settings
from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from scans.kisa_catalog_codes import (
    KISA_IDENTIFIER_BY_ITEM_NUMBER,
)


RULE_ROOT = (
    Path(settings.BASE_DIR)
    / "semgrep_rules"
    / "kisa"
)


RULE_ID_PATTERN = re.compile(
    r"^\s*-\s*id:\s*"
    r"kisa\.sw(?P<number>\d{2})\."
    r"(?:java|javascript|python)\.",
    re.MULTILINE,
)


IDENTIFIER_LINE_PATTERN = re.compile(
    r"^(?P<indent>\s*)"
    r"kisa_identifier\s*:\s*"
    r"(?P<quote>[\"']?)"
    r"(?P<identifier>"
    r"KISA-SW-\d{2,3}"
    r"|SW-\d{2}"
    r"|KISA-(?:INP|SEC|TIM|ERR|COD|ENC|API)-\d{2}"
    r")"
    r"(?P=quote)"
    r"\s*$",
    re.MULTILINE,
)


class Command(BaseCommand):

    help = (
        "KISA Semgrep Rule metadata의 kisa_identifier를 "
        "카테고리 기반 코드(KISA-INP-01 등)로 마이그레이션합니다."
    )


    def add_arguments(
        self,
        parser,
    ):

        parser.add_argument(
            "--apply",
            action="store_true",
            help=(
                "실제 YAML 파일을 수정합니다. "
                "옵션이 없으면 dry-run입니다."
            ),
        )


    def handle(
        self,
        *args,
        **options,
    ):

        apply_changes = options[
            "apply"
        ]


        if not RULE_ROOT.exists():

            raise CommandError(
                "KISA Rule 디렉터리를 찾을 수 없습니다. "
                f"path={RULE_ROOT}"
            )


        rule_files = sorted(
            [
                *RULE_ROOT.rglob("*.yml"),
                *RULE_ROOT.rglob("*.yaml"),
            ]
        )


        if not rule_files:

            raise CommandError(
                "KISA Rule YAML 파일이 없습니다."
            )


        changed_files = 0
        unchanged_files = 0
        invalid_files = []


        for rule_file in rule_files:

            original = rule_file.read_text(
                encoding="utf-8"
            )


            rule_matches = list(
                RULE_ID_PATTERN.finditer(
                    original
                )
            )

            identifier_matches = list(
                IDENTIFIER_LINE_PATTERN.finditer(
                    original
                )
            )


            if (
                len(rule_matches) != 1
                or
                len(identifier_matches) != 1
            ):

                invalid_files.append(
                    (
                        str(
                            rule_file.relative_to(
                                settings.BASE_DIR
                            )
                        ),
                        len(rule_matches),
                        len(identifier_matches),
                    )
                )

                continue


            item_number = int(
                rule_matches[0].group(
                    "number"
                )
            )


            expected_identifier = (
                KISA_IDENTIFIER_BY_ITEM_NUMBER.get(
                    item_number
                )
            )


            if expected_identifier is None:

                invalid_files.append(
                    (
                        str(
                            rule_file.relative_to(
                                settings.BASE_DIR
                            )
                        ),
                        "invalid_item_number",
                        item_number,
                    )
                )

                continue


            identifier_match = (
                identifier_matches[0]
            )

            current_identifier = (
                identifier_match.group(
                    "identifier"
                )
            )


            if (
                current_identifier
                ==
                expected_identifier
            ):

                unchanged_files += 1

                self.stdout.write(
                    "[KEEP] "
                    f"{rule_file.relative_to(settings.BASE_DIR)} "
                    f"{expected_identifier}"
                )

                continue


            replacement = (
                f"{identifier_match.group('indent')}"
                f"kisa_identifier: "
                f"{identifier_match.group('quote')}"
                f"{expected_identifier}"
                f"{identifier_match.group('quote')}"
            )


            migrated = (
                original[
                    :identifier_match.start()
                ]
                +
                replacement
                +
                original[
                    identifier_match.end():
                ]
            )


            changed_files += 1

            self.stdout.write(
                "[CHANGE] "
                f"{rule_file.relative_to(settings.BASE_DIR)} "
                f"{current_identifier} -> "
                f"{expected_identifier}"
            )


            if apply_changes:

                rule_file.write_text(
                    migrated,
                    encoding="utf-8",
                )


        if invalid_files:

            self.stdout.write(
                self.style.ERROR(
                    "\n마이그레이션할 수 없는 Rule 파일:"
                )
            )

            for item in invalid_files:

                self.stdout.write(
                    f"  - {item}"
                )


            raise CommandError(
                "일부 KISA Rule의 id 또는 "
                "kisa_identifier 구조를 확인할 수 없습니다."
            )


        mode = (
            "APPLY"
            if apply_changes
            else "DRY-RUN"
        )


        self.stdout.write(
            self.style.SUCCESS(
                "\nKISA 카탈로그 코드 Rule migration "
                f"{mode} 완료\n"
                f"rule_files={len(rule_files)}\n"
                f"changed_files={changed_files}\n"
                f"unchanged_files={unchanged_files}"
            )
        )
