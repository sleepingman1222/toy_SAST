/*
 * frontend/src/api/adminApi.js
 *
 * 관리자 Dashboard 전용 API.
 */

import {
  authFetch,
  getApiErrorMessage,
} from "./client";

import {
  normalizeAdminSummary,
} from "./normalizers";


export async function getAdminSummary(
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      "/api/admin/summary/",
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
        "관리자 요약 정보를 불러오지 못했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  return normalizeAdminSummary(
    data
  );
}
