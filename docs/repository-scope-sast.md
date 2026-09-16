# Repository-scope SAST 운영 가이드

이 문서는 `repository_v2` 분석 파이프라인의 release-1 운영 계약을 설명합니다. 기준 설계와 검증 항목은 `.omx/plans/prd-repository-scope-sast-migration.md` 및 `.omx/plans/test-spec-repository-scope-sast-migration.md`에 있습니다.

## 범위

- 새 `repository_v2` 분석은 불변 source snapshot 전체를 대상으로 Semgrep CE를 한 번 실행합니다.
- release 1은 repository당 `ScanExecution` 하나만 생성합니다. monorepo/logical-project 분할, resource 기반 fallback, diff scan, SARIF, Semgrep Pro는 포함하지 않습니다.
- CE에서 repository context를 전달한다는 사실은 interfile 또는 cross-function 분석 지원을 의미하지 않습니다. API의 capability 값이 실제 엔진 기능의 기준입니다.
- 기존 `chunk_v1` 데이터, 작업, 복구 흐름, API 응답은 호환 기간 동안 유지합니다.

## 실행 및 증거 흐름

1. 분석 생성 transaction에서 `pipeline_version`을 저장합니다. 이후 설정 변경은 생성된 분석의 route를 바꾸지 않습니다.
2. source snapshot과 manifest v2를 만든 뒤 snapshot digest, ruleset digest, options digest를 고정합니다.
3. repository root 하나를 대상으로 Semgrep을 실행합니다. 실행 옵션의 `--max-target-bytes`는 snapshot의 10 MiB 단일 파일 제한과 같아야 합니다.
4. raw JSON을 크기 제한 안에서 임시 파일로 기록하고, fsync/close, SHA-256 및 크기 계산, atomic rename, ownership 재검사를 거쳐 `ready` artifact로 게시합니다.
5. normalization은 별도 outbox/lease/retry 흐름에서 ready artifact만 읽습니다. normalization 재시도는 Semgrep을 다시 실행하지 않습니다.
6. coverage category를 상호 배타적으로 계산하고 `unaccounted=0`인 경우에만 완료합니다. `missing_from_engine_report`는 accounted 상태지만 `coverage_complete=false`입니다.

## 호환 응답

`repository_v2` 진행률 응답은 실제 execution과 기존 UI용 synthetic chunk를 함께 제공합니다.

- `total_executions=1`, `total_chunks=1`
- synthetic chunk의 `language`는 `mixed`
- normalization 상태는 기존 호환 필드에서 `running`으로 표시
- `result_count`는 deduplicated finding 수이며 raw occurrence 수와 구분
- 일반 API는 raw artifact 본문이나 storage path를 노출하지 않음

## 활성화와 롤백

`repository_v2`를 기본값으로 활성화하기 전에 migration, repository scan, artifact, normalization, coverage, recovery, API/frontend 호환 검증이 모두 통과해야 합니다. critical test가 실패하거나 skip된 상태에서는 활성화하지 않습니다.

운영 롤백은 **새 분석의 기본 pipeline만 `chunk_v1`으로 변경**합니다. 이미 생성된 `repository_v2` 분석과 기존 `chunk_v1` 분석은 저장된 `pipeline_version`으로 계속 처리합니다. v2 데이터가 존재한 뒤 schema를 되돌리거나 실행 중인 분석의 version을 수정하지 않습니다.

## Artifact 보존과 정리

- canonical ready artifact는 해당 `AnalysisRun`이 존재하는 동안 보존합니다.
- run 삭제 transaction은 정리할 contained path를 수집하고 commit 이후 idempotent filesystem cleanup을 예약합니다.
- transaction rollback은 파일을 삭제하지 않습니다.
- cleanup 실패는 orphan reconciliation이 run 부재를 확인한 뒤 재처리합니다.
- artifact/diagnostic/temp 파일에는 per-run 크기 및 개수 제한을 적용하고, 실행 전 reserved free-space를 확인합니다. 보존된 모든 run을 합친 전역 고정 용량 한도를 보장한다고 표현하지 않습니다.

## 검증

통합 후 최소 검증 명령은 다음과 같습니다. 명령이 존재한다는 사실만으로 acceptance criteria가 통과한 것은 아니며, 실제 출력과 fault/race 증거를 함께 보관해야 합니다.

```bash
docker compose build backend celery
docker compose run --rm backend semgrep --version
docker compose run --rm backend python manage.py migrate --plan
docker compose run --rm backend python manage.py makemigrations --check --dry-run
docker compose run --rm backend python manage.py check
docker compose run --rm backend python manage.py test scans.tests
docker compose run --rm backend python manage.py check_repository_scan_pipeline
docker compose run --rm frontend npm run lint
docker compose run --rm frontend npm run build
python3 scripts/check_frontend_api_boundaries.py
docker compose config
```

추가로 다음 통합 증거가 필요합니다.

- 30개 초과 파일, 5 MiB 초과, Java/JavaScript/Python fixture가 repository execution/process 하나만 생성
- creation flag 변경과 dispatch의 동시성 경쟁에서도 저장된 version과 typed task/outbox가 일치
- engine 및 normalization worker loss가 중복 process/finding 없이 복구
- timeout, cancel, ownership loss, shutdown, artifact overflow에서 child/grandchild process가 모두 종료 및 reap
- engine/normalization outbox의 published-but-unclaimed crash window가 같은 logical event identity로 수렴
- run 삭제 rollback/commit/cleanup failure가 artifact 보존 및 orphan recovery 계약을 준수

## 중단 조건

다음 중 하나라도 발생하면 v2 활성화 또는 완료 판정을 중단합니다.

- Semgrep exact version 또는 실제 image 실행을 검증할 수 없음
- coverage path가 여러 category에 속하거나 `unaccounted!=0`
- normalization retry가 Semgrep을 재실행
- timeout/cancel 이후 descendant process가 남음
- artifact 또는 temporary file이 제한 없이 증가
- 분석 생성 뒤 pipeline route가 바뀜
- ready artifact/normalization/coverage 조건 없이 run이 완료됨
