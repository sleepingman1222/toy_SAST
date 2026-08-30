let refreshPromise = null;


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


// ========================================
// CSRF Cookie 생성
// ========================================

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


// ========================================
// Access Token 재발급
//
// 여러 API가 동시에 401을 만나도
// Refresh 요청은 한 번만 실행
// ========================================

export async function refreshAccessToken() {

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


// ========================================
// 인증된 API 호출
// ========================================

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


// ========================================
// 로그아웃 요청
// ========================================

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


// ========================================
// API 날짜 변환
//
// Django
// 2026-08-30T01:23:45Z
//
// React
// 2026-08-30 10:23
// ========================================

function formatApiDateTime(
  value
) {

  if (!value) {
    return "-";
  }


  const date =
    new Date(
      value
    );


  if (
    Number.isNaN(
      date.getTime()
    )
  ) {

    return value;
  }


  const year =
    date.getFullYear();


  const month =
    String(
      date.getMonth() + 1
    ).padStart(
      2,
      "0"
    );


  const day =
    String(
      date.getDate()
    ).padStart(
      2,
      "0"
    );


  const hour =
    String(
      date.getHours()
    ).padStart(
      2,
      "0"
    );


  const minute =
    String(
      date.getMinutes()
    ).padStart(
      2,
      "0"
    );


  return (
    `${year}-${month}-${day} ${hour}:${minute}`
  );
}

// ========================================
// SourceVersion 응답 변환
// ========================================

function normalizeSourceVersion(
  source
) {

  return {

    id:
      source.id,

    version:
      source.version,

    language:
      source.language ||
      "",

    sourceType:
      source.source_type ??
      source.sourceType ??
      "",

    sourceFileName:
      source.source_file_name ??
      source.sourceFileName ??
      "",

    repositoryUrl:
      source.repository_url ??
      source.repositoryUrl ??
      "",

    internalPath:
      source.internal_path ??
      source.internalPath ??
      "",

    createdById:
      source.created_by_id ??
      source.createdById ??
      null,

    createdByUsername:
      source.created_by_username ??
      source.createdByUsername ??
      "",

    createdAt:
      formatApiDateTime(
        source.created_at ??
        source.createdAt
      ),
  };
}


// ========================================
// Project 응답 변환
// ========================================

function normalizeProject(
  project
) {

  return {

    id:
      project.id,

    name:
      project.name ||
      "",

    description:
      project.description ||
      "",

    createdById:
      project.created_by_id ??
      project.createdById ??
      null,

    createdByUsername:
      project.created_by_username ??
      project.createdByUsername ??
      "",

    createdAt:
      formatApiDateTime(
        project.created_at ??
        project.createdAt
      ),

    updatedAt:
      formatApiDateTime(
        project.updated_at ??
        project.updatedAt
      ),

    currentSourceVersionId:
      project.current_source_version_id ??
      project.currentSourceVersionId ??
      null,


    // ProjectAccess Backend 연결
    assignedUserIds:
      project.assigned_user_ids ??
      project.assignedUserIds ??
      [],

    sourceVersions:
      (
        project.source_versions ??
        project.sourceVersions ??
        []
      ).map(
        normalizeSourceVersion
      ),

    analysisHistory:
      project.analysisHistory ??
      [],
  };
}


// ========================================
// User 응답 변환
// ========================================

function normalizeUser(
  user
) {

  return {

    id:
      user.id,

    username:
      user.username ||
      "",

    role:
      user.role ||
      "user",

    isActive:
      user.isActive ??
      user.is_active ??
      false,

    createdAt:
      formatApiDateTime(
        user.createdAt ??
        user.date_joined
      ),

    lastLogin:
      (
        user.lastLogin ??
        user.last_login
      )
        ? formatApiDateTime(
          user.lastLogin ??
          user.last_login
        )
        : null,
  };
}


// ========================================
// API 오류 메시지
// ========================================

async function getApiErrorMessage(
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
       // SourceVersion
  "language",
  "source_type",
  "source_file",
  "repository_url",
  "internal_path",
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


// ========================================
// 프로젝트 목록 조회
//
// GET /api/projects/
// ========================================

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


// ========================================
// 프로젝트 등록
//
// POST /api/projects/
// ========================================

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


// ========================================
// 프로젝트 수정
//
// PATCH /api/projects/{id}/
// ========================================

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

// ========================================
// SourceVersion 등록
//
// POST /api/projects/{id}/sources/
// ========================================

export async function createSourceVersion(
  projectId,
  sourceData,
  accessToken,
  setAccessToken
) {

  const formData =
    new FormData();


  formData.append(
    "language",
    sourceData.language
  );


  formData.append(
    "source_type",
    sourceData.sourceType
  );


  // 파일 업로드
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


  // Repository
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


  // 내부 경로
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

// ========================================
// SourceVersion 수정
//
// PATCH /api/projects/{id}/sources/{sourceId}/
// ========================================

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
    "language",
    sourceData.language
  );


  formData.append(
    "source_type",
    sourceData.sourceType
  );


  // 파일 업로드
  //
  // 수정할 때 새 파일을 선택한 경우에만 전송
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


  // Repository
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


  // 내부 경로
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

// ========================================
// 사용자 목록 조회
//
// GET /api/users/
// ========================================

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


// ========================================
// 사용자 등록
//
// POST /api/users/
// ========================================

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


// ========================================
// 사용자 활성 / 비활성
//
// PATCH /api/users/{id}/
// ========================================

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

// ========================================
// 사용자 삭제
//
// DELETE /api/users/{id}/
// ========================================

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


// ========================================
// 프로젝트 접근 권한 부여
//
// POST /api/projects/{id}/access/
// ========================================

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


// ========================================
// 프로젝트 접근 권한 해제
//
// DELETE /api/projects/{id}/access/{userId}/
// ========================================

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


// ========================================
// 프로젝트 삭제
//
// DELETE /api/projects/{id}/
// ========================================

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