#!/usr/bin/env bash


# ========================================
# 관리자 로그인 / Access Token 발급
#
# 사용법:
#
# source ./scripts/admin_login.sh
#
# 성공 시 현재 Shell에:
#
# BASE_URL
# ACCESS_TOKEN
#
# 환경변수가 유지된다.
# ========================================


# ========================================
# source 실행 여부 확인
# ========================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then

    echo "이 스크립트는 source로 실행해야 합니다."
    echo
    echo "사용법:"
    echo "source ./scripts/admin_login.sh"

    exit 1
fi


# ========================================
# 필요한 명령 확인
# ========================================

if ! command -v curl > /dev/null 2>&1; then

    echo "오류: curl이 설치되어 있지 않습니다."

    return 1
fi


if ! command -v jq > /dev/null 2>&1; then

    echo "오류: jq가 설치되어 있지 않습니다."
    echo
    echo "설치:"
    echo "sudo apt install jq"

    return 1
fi


# ========================================
# Backend API 주소
# ========================================

export BASE_URL="${BASE_URL:-http://localhost:8000/api}"


echo "========================================"
echo " 관리자 로그인"
echo "========================================"
echo
echo "API: $BASE_URL"
echo


# ========================================
# 관리자 아이디 입력
#
# 그냥 Enter를 누르면 admin
# ========================================

read -r -p "관리자 아이디 [admin]: " INPUT_USERNAME

ADMIN_USERNAME="${INPUT_USERNAME:-admin}"


# ========================================
# 관리자 비밀번호 입력
#
# 화면에 표시되지 않음
# ========================================

read -r -s -p "관리자 비밀번호: " ADMIN_PASSWORD

echo
echo


# ========================================
# 로그인 JSON 생성
#
# jq를 사용하여
# 특수문자가 포함된 비밀번호도
# 안전하게 JSON으로 변환
# ========================================

LOGIN_PAYLOAD=$(
    jq -n \
        --arg username "$ADMIN_USERNAME" \
        --arg password "$ADMIN_PASSWORD" \
        '{
            username: $username,
            password: $password
        }'
)


# ========================================
# 임시 응답 파일
# ========================================

LOGIN_RESPONSE_FILE=$(
    mktemp
)


# ========================================
# 로그인
#
# POST /api/login/
# ========================================

HTTP_STATUS=$(
    curl \
        -sS \
        -o "$LOGIN_RESPONSE_FILE" \
        -w "%{http_code}" \
        -X POST \
        "$BASE_URL/login/" \
        -H "Content-Type: application/json" \
        -d "$LOGIN_PAYLOAD"
)


# ========================================
# 비밀번호 관련 변수 즉시 제거
# ========================================

unset ADMIN_PASSWORD

unset LOGIN_PAYLOAD


# ========================================
# 로그인 실패
# ========================================

if [[ "$HTTP_STATUS" != "200" ]]; then

    echo "로그인 실패"
    echo
    echo "HTTP Status: $HTTP_STATUS"
    echo

    jq . "$LOGIN_RESPONSE_FILE" 2>/dev/null \
        || cat "$LOGIN_RESPONSE_FILE"

    rm -f "$LOGIN_RESPONSE_FILE"

    unset ACCESS_TOKEN

    return 1
fi


# ========================================
# Access Token 추출
# ========================================

ACCESS_TOKEN=$(
    jq -r \
        '.access // empty' \
        "$LOGIN_RESPONSE_FILE"
)


rm -f "$LOGIN_RESPONSE_FILE"


# ========================================
# Token 존재 확인
# ========================================

if [[ -z "$ACCESS_TOKEN" ]]; then

    echo "로그인은 성공했지만 Access Token을 찾을 수 없습니다."

    unset ACCESS_TOKEN

    return 1
fi


export ACCESS_TOKEN


# ========================================
# Access Token 실제 검증
#
# GET /api/me/
# ========================================

ME_RESPONSE_FILE=$(
    mktemp
)


ME_STATUS=$(
    curl \
        -sS \
        -o "$ME_RESPONSE_FILE" \
        -w "%{http_code}" \
        "$BASE_URL/me/" \
        -H "Authorization: Bearer $ACCESS_TOKEN"
)


# ========================================
# 인증 실패
# ========================================

if [[ "$ME_STATUS" != "200" ]]; then

    echo "Access Token 검증 실패"
    echo
    echo "HTTP Status: $ME_STATUS"
    echo

    jq . "$ME_RESPONSE_FILE" 2>/dev/null \
        || cat "$ME_RESPONSE_FILE"

    rm -f "$ME_RESPONSE_FILE"

    unset ACCESS_TOKEN

    return 1
fi


# ========================================
# 로그인 사용자 정보
# ========================================

LOGIN_USER=$(
    jq -r \
        '.username // "-"' \
        "$ME_RESPONSE_FILE"
)


LOGIN_ROLE=$(
    jq -r \
        '.role // "-"' \
        "$ME_RESPONSE_FILE"
)


rm -f "$ME_RESPONSE_FILE"


# ========================================
# 완료
# ========================================

echo "관리자 로그인 성공"
echo
echo "사용자 : $LOGIN_USER"
echo "권한   : $LOGIN_ROLE"
echo "인증   : HTTP 200"
echo
echo "BASE_URL과 ACCESS_TOKEN이"
echo "현재 터미널에 저장되었습니다."
echo

echo "ACCESS_TOKEN=${ACCESS_TOKEN:0:25}..."
echo

echo "이제 바로 API 테스트를 실행할 수 있습니다."