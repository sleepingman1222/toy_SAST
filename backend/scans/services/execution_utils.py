# backend/scans/services/execution_utils.py

MAX_LOG_LENGTH = 20000


def truncate_log(
    value,
    max_length=MAX_LOG_LENGTH
):

    if not value:
        return ""

    if len(value) <= max_length:
        return value

    return (
        value[:max_length]
        + "\n\n[로그가 너무 길어 일부만 저장되었습니다.]"
    )
