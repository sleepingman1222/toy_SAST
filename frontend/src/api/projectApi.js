/*
 * frontend/src/api/projectApi.js
 *
 * Project / SourceVersion / ProjectAccess API.
 */

import {
  authFetch,
  getApiErrorMessage,
} from "./client";

import {
  normalizeProject,
  normalizeSourceVersion,
} from "./normalizers";


export async function getProjects(
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      "/api/projects/",
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
        "프로젝트 목록을 불러오지 못했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  const projectList =
    Array.isArray(data)
      ? data
      : (
          data.results ||
          []
        );


  return projectList.map(
    normalizeProject
  );
}

export async function createProject(
  projectData,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      "/api/projects/",
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
            name:
              projectData.name,

            description:
              projectData.description,
          }),
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "프로젝트 등록에 실패했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  return normalizeProject(
    data
  );
}

export async function updateProject(
  projectId,
  projectData,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/projects/${projectId}/`,
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
            name:
              projectData.name,

            description:
              projectData.description,
          }),
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "프로젝트 수정에 실패했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  return normalizeProject(
    data
  );
}

export async function createSourceVersion(
  projectId,
  sourceData,
  accessToken,
  setAccessToken
) {

  const formData =
    new FormData();


  formData.append(
    "source_type",
    sourceData.sourceType
  );


  if (
    sourceData.sourceType ===
    "upload" &&
    sourceData.sourceFile
  ) {

    formData.append(
      "source_file",
      sourceData.sourceFile
    );
  }


  if (
    sourceData.sourceType ===
    "repository"
  ) {

    formData.append(
      "repository_url",
      sourceData.repositoryUrl ||
      ""
    );
  }


  if (
    sourceData.sourceType ===
    "internal"
  ) {

    formData.append(
      "internal_path",
      sourceData.internalPath ||
      ""
    );
  }


  const response =
    await authFetch(
      `/api/projects/${projectId}/sources/`,
      accessToken,
      setAccessToken,
      {
        method: "POST",
        body: formData,
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "분석 대상 등록에 실패했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  return normalizeSourceVersion(
    data
  );
}

export async function updateSourceVersion(
  projectId,
  sourceId,
  sourceData,
  accessToken,
  setAccessToken
) {

  const formData =
    new FormData();


  formData.append(
    "source_type",
    sourceData.sourceType
  );


  if (
    sourceData.sourceType ===
    "upload" &&
    sourceData.sourceFile
  ) {

    formData.append(
      "source_file",
      sourceData.sourceFile
    );
  }


  if (
    sourceData.sourceType ===
    "repository"
  ) {

    formData.append(
      "repository_url",
      sourceData.repositoryUrl ||
      ""
    );
  }


  if (
    sourceData.sourceType ===
    "internal"
  ) {

    formData.append(
      "internal_path",
      sourceData.internalPath ||
      ""
    );
  }


  const response =
    await authFetch(
      `/api/projects/${projectId}/sources/${sourceId}/`,
      accessToken,
      setAccessToken,
      {
        method: "PATCH",
        body: formData,
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "분석 대상 수정에 실패했습니다."
      );


    throw new Error(
      message
    );
  }


  const data =
    await response.json();


  return normalizeSourceVersion(
    data
  );
}

export async function grantProjectAccess(
  projectId,
  userId,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/projects/${projectId}/access/`,
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
            user_id:
              userId,
          }),
      }
    );


  if (!response.ok) {

    const message =
      await getApiErrorMessage(
        response,
        "프로젝트 사용자 할당에 실패했습니다."
      );


    throw new Error(
      message
    );
  }


  return await response.json();
}

export async function revokeProjectAccess(
  projectId,
  userId,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/projects/${projectId}/access/${userId}/`,
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
        "프로젝트 사용자 할당 해제에 실패했습니다."
      );


    throw new Error(
      message
    );
  }
}

export async function deleteProject(
  projectId,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/projects/${projectId}/`,
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
        "프로젝트 삭제에 실패했습니다."
      );


    throw new Error(
      message
    );
  }
}
