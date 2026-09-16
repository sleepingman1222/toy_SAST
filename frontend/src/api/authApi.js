/*
 * frontend/src/api/authApi.js
 *
 * 인증/세션/비밀번호 관련 API.
 */

import {
  authFetch,
  getApiErrorMessage,
  getCookie,
} from "./client";


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

export async function logoutRequest() {

  const csrfToken =
    getCookie(
      "csrftoken"
    );


  const response =
    await fetch(
      "/api/logout/",
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


  return response;
}

export async function changeMyPassword(
  passwordData,
  accessToken,
  setAccessToken
) {

  const csrfToken =
    getCookie(
      "csrftoken"
    );


  const response =
    await authFetch(
      "/api/users/change-password/",
      accessToken,
      setAccessToken,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          ...(csrfToken
            ? {
                "X-CSRFToken":
                  csrfToken,
              }
            : {}),
        },

        body:
          JSON.stringify({
            current_password:
              passwordData.currentPassword,

            new_password:
              passwordData.newPassword,

            new_password_confirm:
              passwordData.newPasswordConfirm,
          }),
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "비밀번호 변경에 실패했습니다."
      );


    throw new Error(
      message
    );
  }


  return await response.json();
}
