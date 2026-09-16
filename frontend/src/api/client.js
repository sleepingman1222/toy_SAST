/*
 * frontend/src/api/client.js
 *
 * 공통 HTTP transport / 인증 갱신 / API error 처리.
 *
 * Domain API에서는 fetch를 직접 중복 구현하지 않고
 * 이 모듈의 authFetch()를 사용한다.
 */

let refreshPromise = null;


export function getCookie(name) {
  const cookies =
    document.cookie.split(";");

  for (const cookie of cookies) {
    const [key, value] =
      cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(
        value
      );
    }
  }

  return null;
}

async function refreshAccessToken() {

  if (refreshPromise) {
    return refreshPromise;
  }


  refreshPromise = (
    async () => {

      try {
        const csrfToken =
          getCookie(
            "csrftoken"
          );


        const response =
          await fetch(
            "/api/token/refresh/",
            {
              method: "POST",

              credentials:
                "include",

              headers: {
                "X-CSRFToken":
                  csrfToken,
              },
            }
          );


        if (!response.ok) {

          const text =
            await response.text();


          console.error(
            "Refresh 실패 응답:",
            text
          );


          return null;
        }


        const data =
          await response.json();


        return (
          data.access ||
          null
        );

      } catch (error) {

        console.error(
          "Access Token 재발급 실패:",
          error
        );


        return null;
      }

    }
  )();


  try {

    return await refreshPromise;

  } finally {

    refreshPromise = null;
  }
}

export async function authFetch(
  url,
  accessToken,
  setAccessToken,
  options = {}
) {
  let token =
    accessToken;


  // ----------------------------------------
  // Access Token이 메모리에 없는 경우
  // ----------------------------------------

  if (!token) {

    token =
      await refreshAccessToken();


    if (!token) {

      return new Response(
        null,
        {
          status: 401,
        }
      );
    }


    setAccessToken(
      token
    );
  }


  // ----------------------------------------
  // 첫 번째 요청
  // ----------------------------------------

  let response =
    await fetch(
      url,
      {
        ...options,

        credentials:
          "include",

        headers: {
          ...options.headers,

          Authorization:
            `Bearer ${token}`,
        },
      }
    );


  // ----------------------------------------
  // Access Token 정상
  // ----------------------------------------

  if (
    response.status !==
    401
  ) {

    return response;
  }


  // ----------------------------------------
  // Access Token 만료
  // ----------------------------------------

  const newAccessToken =
    await refreshAccessToken();


  if (!newAccessToken) {

    setAccessToken(
      null
    );


    return response;
  }


  setAccessToken(
    newAccessToken
  );


  // ----------------------------------------
  // 원래 요청 재시도
  // ----------------------------------------

  response =
    await fetch(
      url,
      {
        ...options,

        credentials:
          "include",

        headers: {
          ...options.headers,

          Authorization:
            `Bearer ${newAccessToken}`,
        },
      }
    );


  return response;
}

export async function getApiErrorMessage(
  response,
  fallbackMessage
) {

  try {

    const data =
      await response.json();


    if (
      typeof data?.detail ===
      "string"
    ) {

      return data.detail;
    }


    const fields = [
      "username",
      "password",
      "role",
      "isActive",
      "user_id",
      "non_field_errors",
      "name",
      "description",
      "language",
      "source_type",
      "source_file",
      "repository_url",
      "internal_path",
      "source_version_id",
      "current_password",
      "new_password",
      "new_password_confirm",
    ];


    for (
      const field
      of fields
    ) {

      const value =
        data?.[field];


      if (
        Array.isArray(
          value
        ) &&
        value.length > 0
      ) {

        return value[0];
      }


      if (
        typeof value ===
        "string"
      ) {

        return value;
      }
    }

  } catch (error) {

    console.error(
      "API 오류 응답 파싱 실패:",
      error
    );
  }


  return fallbackMessage;
}
