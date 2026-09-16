/*
 * frontend/src/api/userApi.js
 *
 * 관리자 사용자 계정 관리 API.
 */

import {
  authFetch,
  getApiErrorMessage,
} from "./client";

import {
  normalizeUser,
} from "./normalizers";


export async function getUsers(
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      "/api/users/",
      accessToken,
      setAccessToken,
      {
        method: "GET",
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "사용자 목록을 불러오지 못했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  const userList =
    Array.isArray(data)
      ? data
      : (
          data.results ||
          []
        );


  return userList.map(
    normalizeUser
  );
}

export async function createUser(
  userData,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      "/api/users/",
      accessToken,
      setAccessToken,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body:
          JSON.stringify({
            username:
              userData.username,

            password:
              userData.password,

            role:
              userData.role,
          }),
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "사용자 등록에 실패했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  return normalizeUser(
    data
  );
}

export async function updateUserStatus(
  userId,
  isActive,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/users/${userId}/`,
      accessToken,
      setAccessToken,
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body:
          JSON.stringify({
            isActive,
          }),
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "사용자 상태 변경에 실패했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  return normalizeUser(
    data
  );
}

export async function deleteUser(
  userId,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/users/${userId}/`,
      accessToken,
      setAccessToken,
      {
        method: "DELETE",
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "사용자 삭제에 실패했습니다."
      );


    throw new Error(
      message
    );
  }
}
