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
// 분석 언어 정규화
//
// Backend의 신규 다중 언어 필드는
// 소문자 canonical 값 배열을 사용한다.
//
// 전환 기간 동안 기존 단일 language /
// analysis_language 값도 fallback으로 읽는다.
// ========================================

function normalizeLanguageName(
  value
) {

  const normalized =
    String(
      value || ""
    )
      .trim()
      .toLowerCase();


  const languageMap = {
    python: "python",
    py: "python",

    javascript: "javascript",
    "java script": "javascript",
    js: "javascript",

    java: "java",
  };


  return (
    languageMap[normalized] ||
    normalized
  );
}


function normalizeLanguageList(
  value,
  legacyValue = ""
) {

  let values = [];


  if (Array.isArray(value)) {

    values = value;

  } else if (
    typeof value === "string" &&
    value.trim()
  ) {

    values = value.split(",");

  } else if (
    typeof legacyValue === "string" &&
    legacyValue.trim()
  ) {

    values = legacyValue.split(",");
  }


  return [
    ...new Set(
      values
        .map(
          normalizeLanguageName
        )
        .filter(
          Boolean
        )
    ),
  ];
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

    // 기존 단일 언어 필드
    // 전환 기간 동안 기존 화면 호환용으로 유지
    language:
      source.language ||
      "",

    // 실제 신규 기준값
    // Backend 자동 감지 다중 언어
    detectedLanguages:
      normalizeLanguageList(
        source.detected_languages ??
        source.detectedLanguages,
        source.language ??
        ""
      ),

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
// Vulnerability 응답 변환
// ========================================

function normalizeVulnerability(
  vulnerability
) {

  return {

    id:
      vulnerability.id,

    // 개별 취약점이 탐지된 실제 소스 언어
    analysisLanguage:
      normalizeLanguageName(
        vulnerability.analysis_language ??
        vulnerability.analysisLanguage ??
        ""
      ),

    securityWeaknessIdentifier:
      vulnerability.security_weakness_identifier ??
      vulnerability.securityWeaknessIdentifier ??
      null,

    securityWeaknessItemNumber:
      vulnerability.security_weakness_item_number ??
      vulnerability.securityWeaknessItemNumber ??
      null,

    ruleId:
      vulnerability.rule_id ??
      vulnerability.ruleId ??
      "",

    name:
      vulnerability.name ||
      "",

    severity:
      vulnerability.severity ||
      "",

    confidence:
      vulnerability.confidence ||
      "",

    filePath:
      vulnerability.file_path ??
      vulnerability.filePath ??
      "",

    line:
      vulnerability.line ??
      null,

    startLine:
      vulnerability.start_line ??
      vulnerability.startLine ??
      vulnerability.line ??
      null,

    startColumn:
      vulnerability.start_column ??
      vulnerability.startColumn ??
      null,

    endLine:
      vulnerability.end_line ??
      vulnerability.endLine ??
      null,

    endColumn:
      vulnerability.end_column ??
      vulnerability.endColumn ??
      null,

    message:
      vulnerability.message ||
      "",

    evidence:
      vulnerability.evidence ||
      "",

    recommendation:
      vulnerability.recommendation ||
      "",

    createdAt:
      formatApiDateTime(
        vulnerability.created_at ??
        vulnerability.createdAt
      ),
  };
}


// ========================================
// AnalysisRun 응답 변환
// ========================================

function normalizeAnalysisRun(
  analysis
) {

  return {

    id:
      analysis.id,

    projectId:
      analysis.project_id ??
      analysis.projectId ??
      null,

    sourceVersionId:
      analysis.source_version_id ??
      analysis.sourceVersionId ??
      null,

    sequence:
      analysis.sequence,

    status:
      analysis.status ||
      "",

    engine:
      analysis.engine ||
      "Semgrep",

    // 기존 단일 언어 Snapshot
    // 전환 기간 동안 호환용으로 유지
    analysisLanguage:
      analysis.analysis_language ??
      analysis.analysisLanguage ??
      "",

    // 분석 실행 당시 자동 감지된 다중 언어 Snapshot
    analysisLanguages:
      normalizeLanguageList(
        analysis.analysis_languages ??
        analysis.analysisLanguages,
        analysis.analysis_language ??
        analysis.analysisLanguage ??
        ""
      ),

    executedById:
      analysis.executed_by_id ??
      analysis.executedById ??
      null,

    executedByUsername:
      analysis.executed_by_username ??
      analysis.executedByUsername ??
      "",

    startedAt:
      analysis.started_at ||
      analysis.startedAt
        ? formatApiDateTime(
            analysis.started_at ??
            analysis.startedAt
          )
        : null,

    completedAt:
      analysis.completed_at ||
      analysis.completedAt
        ? formatApiDateTime(
            analysis.completed_at ??
            analysis.completedAt
          )
        : null,

    failureReason:
      analysis.failure_reason ??
      analysis.failureReason ??
      "",

    logs:
      analysis.logs ||
      "",

    rawResult:
      analysis.raw_result ??
      analysis.rawResult ??
      null,

    summary:
      analysis.summary ??
      null,

    vulnerabilities:
      (
        analysis.vulnerabilities ||
        []
      ).map(
        normalizeVulnerability
      ),

    createdAt:
      formatApiDateTime(
        analysis.created_at ??
        analysis.createdAt
      ),

    updatedAt:
      formatApiDateTime(
        analysis.updated_at ??
        analysis.updatedAt
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
      (
        project.analysis_runs ??
        project.analysisHistory ??
        []
      ).map(
        normalizeAnalysisRun
      ),
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
// AdminSummary 응답 변환
// ========================================

function normalizeAdminSummary(
  summary
) {

  return {

    totalUsers:
      summary.total_users ??
      0,

    activeUsers:
      summary.active_users ??
      0,

    totalProjects:
      summary.total_projects ??
      0,

    totalAnalysisRuns:
      summary.total_analysis_runs ??
      0,

    analysisStatus: {

      pending:
        summary.analysis_status
          ?.pending ??
        0,

      running:
        summary.analysis_status
          ?.running ??
        0,

      completed:
        summary.analysis_status
          ?.completed ??
        0,

      failed:
        summary.analysis_status
          ?.failed ??
        0,
    },

    recentAnalyses:
      (
        summary.recent_analyses ||
        []
      ).map(
        (analysis) => ({

          id:
            analysis.id,

          sequence:
            analysis.sequence,

          projectId:
            analysis.project_id ??
            null,

          projectName:
            analysis.project_name ||
            "",

          sourceVersionId:
            analysis.source_version_id ??
            null,

          sourceVersion:
            analysis.source_version ??
            null,

          // 기존 단일 언어 Snapshot
          analysisLanguage:
            analysis.analysis_language ||
            "",

          // 신규 다중 언어 Snapshot
          analysisLanguages:
            normalizeLanguageList(
              analysis.analysis_languages ??
              analysis.analysisLanguages,
              analysis.analysis_language ??
              ""
            ),

          status:
            analysis.status ||
            "",

          resultCount:
            analysis.result_count ??
            0,

          executedByUsername:
            analysis.executed_by_username ||
            "",

          startedAt:
            analysis.started_at
              ? formatApiDateTime(
                  analysis.started_at
                )
              : null,

          completedAt:
            analysis.completed_at
              ? formatApiDateTime(
                  analysis.completed_at
                )
              : null,

          createdAt:
            analysis.created_at
              ? formatApiDateTime(
                  analysis.created_at
                )
              : null,
        })
      ),
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
      "source_type",
      "source_file",
      "repository_url",
      "internal_path",
      "source_version_id",
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
// 관리자 요약 조회
//
// GET /api/admin/summary/
// ========================================

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


// ========================================
// AnalysisRun 목록 조회
//
// GET /api/projects/{id}/analyses/
// ========================================

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


// ========================================
// AnalysisRun 생성
//
// POST /api/projects/{id}/analyses/
// ========================================

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


// ========================================
// AnalysisRun 상세 조회
//
// GET /api/projects/{id}/analyses/{analysisId}/
// ========================================

export async function getProjectAnalysisRun(
  projectId,
  analysisId,
  accessToken,
  setAccessToken
) {

  const response =
    await authFetch(
      `/api/projects/${projectId}/analyses/${analysisId}/`,
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
        "분석 결과를 불러오지 못했습니다."
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