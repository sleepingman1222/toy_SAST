function getCookie(name) {
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


// -------------------------
// CSRF Cookie 생성
// -------------------------

export async function initializeCsrf() {
  const response = await fetch(
    "/api/csrf/",
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      "CSRF Token 초기화 실패"
    );
  }
}


// -------------------------
// Access Token 재발급
// -------------------------

export async function refreshAccessToken() {
  try {
    const csrfToken =
      getCookie("csrftoken");

    const response = await fetch(
      "/api/token/refresh/",
      {
        method: "POST",

        credentials: "include",

        headers: {
          "X-CSRFToken": csrfToken,
        },
      }
    );

    if (!response.ok) {
      const text = await response.text();

      console.error(
        "Refresh 실패 응답:",
        text
      );

      return null;
    }

    const data =
      await response.json();

    return data.access;

  } catch (error) {
    console.error(
      "Access Token 재발급 실패:",
      error
    );

    return null;
  }
}


// -------------------------
// 인증된 API 호출
// -------------------------

export async function authFetch(
  url,
  accessToken,
  setAccessToken,
  options = {}
) {

  let token = accessToken;

  // 새로고침 직후처럼
  // accessToken이 메모리에 없는 경우
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

    setAccessToken(token);
  }


  // 첫 API 요청
  let response = await fetch(
    url,
    {
      ...options,

      credentials: "include",

      headers: {
        ...options.headers,

        Authorization:
          `Bearer ${token}`,
      },
    }
  );


  // Access Token 정상
  if (response.status !== 401) {
    return response;
  }


  // Access Token 만료
  const newAccessToken =
    await refreshAccessToken();


  if (!newAccessToken) {
    setAccessToken(null);

    return response;
  }


  // React 메모리 갱신
  setAccessToken(
    newAccessToken
  );


  // 원래 요청 재시도
  response = await fetch(
    url,
    {
      ...options,

      credentials: "include",

      headers: {
        ...options.headers,

        Authorization:
          `Bearer ${newAccessToken}`,
      },
    }
  );


  return response;
}


// -------------------------
// 로그아웃 요청
// -------------------------

export async function logoutRequest() {

  const csrfToken =
    getCookie("csrftoken");

  const response = await fetch(
    "/api/logout/",
    {
      method: "POST",

      credentials: "include",

      headers: {
        "X-CSRFToken":
          csrfToken,
      },
    }
  );

  return response;
}