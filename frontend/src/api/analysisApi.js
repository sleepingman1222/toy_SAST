/*
 * frontend/src/api/analysisApi.js
 *
 * AnalysisRun / Chunk Progress API.
 *
 * getProjectAnalysisRun()은 현재 frontend 전체에서
 * 사용되지 않으므로 Phase 2E에서 제거했다.
 */

import {
  authFetch,
  getApiErrorMessage,
} from "./client";

import {
  normalizeAnalysisProgress,
  normalizeAnalysisRun,
} from "./normalizers";


export async function getProjectAnalysisRuns(
  projectId,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/projects/${projectId}/analyses/`,
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
        "분석 이력을 불러오지 못했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  const analysisList =
    Array.isArray(data)
      ? data
      : (
          data.results ||
          []
        );


  return analysisList.map(
    normalizeAnalysisRun
  );
}

export async function createAnalysisRun(
  projectId,
  sourceVersionId,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/projects/${projectId}/analyses/`,
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
            source_version_id:
              sourceVersionId,
          }),
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "분석 실행에 실패했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  return normalizeAnalysisRun(
    data
  );
}

export async function getAdminProjectAnalysisProgress(
  projectId,
  analysisId,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/projects/${projectId}/analyses/${analysisId}/progress/`,
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
        "분석 Chunk 진행 정보를 불러오지 못했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  return normalizeAnalysisProgress(
    data
  );
}
