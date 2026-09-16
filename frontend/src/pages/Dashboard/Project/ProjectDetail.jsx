import {
  useEffect,
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import {
  getAdminProjectAnalysisProgress,
} from "../../../api/analysisApi";

import VulnerabilityPanel from "../../../components/Analysis/VulnerabilityPanel";

import "./ProjectDetail.css";


const ACTIVE_ANALYSIS_STATUSES = [
  "pending",
  "planning",
  "running",
];


function isActiveAnalysisStatus(
  status
) {

  return (
    ACTIVE_ANALYSIS_STATUSES
      .includes(
        status
      )
  );
}


function getLanguageDisplayName(
  language
) {

  const normalizedLanguage =
    String(
      language ||
      ""
    )
      .trim()
      .toLowerCase();


  switch (
    normalizedLanguage
  ) {

    case "java":

      return "Java";


    case "javascript":
    case "js":

      return "JavaScript";


    case "python":
    case "py":

      return "Python";


    default:

      return (
        language ||
        "-"
      );
  }
}


function getChunkStatusText(
  status
) {

  switch (
    status
  ) {

    case "pending":
    case "queued":

      return "대기";


    case "running":

      return "실행 중";


    case "retry_pending":

      return "재시도 대기";


    case "completed":

      return "완료";


    case "failed":

      return "실패";


    case "skipped":

      return "건너뜀";


    case "cancelled":

      return "취소";


    default:

      return "-";
  }
}


function formatBytes(
  bytes
) {

  const value = Number(
    bytes ||
    0
  );


  if (
    !Number.isFinite(
      value
    ) ||
    value <= 0
  ) {
    return "0 B";
  }


  if (
    value < 1024
  ) {
    return `${value} B`;
  }


  const kilobytes =
    value / 1024;


  if (
    kilobytes < 1024
  ) {
    return `${kilobytes.toFixed(1)} KB`;
  }


  const megabytes =
    kilobytes / 1024;


  if (
    megabytes < 1024
  ) {
    return `${megabytes.toFixed(1)} MB`;
  }


  const gigabytes =
    megabytes / 1024;


  return `${gigabytes.toFixed(1)} GB`;
}


function ProjectDetail({
  project,
  users = [],
  onBack,
  onEdit,
  onDelete,
  onAddSourceVersion,
  onUpdateSourceVersion,
  onRunAnalysis,
  onGrantUserAccess,
  onRevokeUserAccess,
}) {

  const {
    user,
    accessToken,
    setAccessToken,
  } = useAuth();


  const isAdmin =
    user?.role ===
    "admin";


  /* ========================================
     Modal
  ======================================== */

  const [
    showSourceModal,
    setShowSourceModal,
  ] = useState(false);


  const [
    sourceModalMode,
    setSourceModalMode,
  ] = useState("create");


  const [
    showAnalysisModal,
    setShowAnalysisModal,
  ] = useState(false);


  const [
    showUserModal,
    setShowUserModal,
  ] = useState(false);


  const [
    showDeleteModal,
    setShowDeleteModal,
  ] = useState(false);


  const [
    deletingProject,
    setDeletingProject,
  ] = useState(false);


  const [
    deleteError,
    setDeleteError,
  ] = useState("");


  const [
    accessChangingUserId,
    setAccessChangingUserId,
  ] = useState(null);


  /* ========================================
     Source Form
  ======================================== */

  const [
    sourceType,
    setSourceType,
  ] = useState("upload");


  const [
    sourceFile,
    setSourceFile,
  ] = useState(null);


  const [
    repositoryUrl,
    setRepositoryUrl,
  ] = useState("");


  const [
    internalPath,
    setInternalPath,
  ] = useState("");


  const [
    sourceError,
    setSourceError,
  ] = useState("");


  const [
    savingSource,
    setSavingSource,
  ] = useState(false);


  /* ========================================
     Analysis
  ======================================== */

  const [
    selectedAnalysisId,
    setSelectedAnalysisId,
  ] = useState(null);


  const [
    selectedAnalysisProgress,
    setSelectedAnalysisProgress,
  ] = useState(null);


  const [
    analysisProgressLoading,
    setAnalysisProgressLoading,
  ] = useState(false);


  const [
    analysisProgressError,
    setAnalysisProgressError,
  ] = useState("");


  /* ========================================
     User Search
  ======================================== */

  const [
    userSearch,
    setUserSearch,
  ] = useState("");


  /* ========================================
     SourceVersion
  ======================================== */

  const sourceVersions =
    project.sourceVersions ||
    [];


  const currentSourceVersion =
    sourceVersions.find(
      (sourceVersion) =>
        sourceVersion.id ===
        project.currentSourceVersionId
    ) || null;


  /* ========================================
     Analysis History

     과거
     ↓
     최신
  ======================================== */

  const analysisHistory =
    [
      ...(
        project.analysisHistory ||
        []
      ),
    ].sort(
      (a, b) =>
        a.sequence -
        b.sequence
    );


  /* ========================================
     관리자
     → 전체 AnalysisRun

     일반 사용자
     → completed만
  ======================================== */

  const visibleAnalysisHistory =
    isAdmin
      ? analysisHistory
      : analysisHistory.filter(
          (analysis) =>
            analysis.status ===
            "completed"
        );


  /* ========================================
     현재 SourceVersion AnalysisRun
  ======================================== */

  const currentSourceAnalyses =
    currentSourceVersion
      ? analysisHistory.filter(
          (analysis) =>
            analysis.sourceVersionId ===
            currentSourceVersion.id
        )
      : [];


  const latestCurrentAnalysis =
    currentSourceAnalyses.length > 0
      ? currentSourceAnalyses[
          currentSourceAnalyses.length - 1
        ]
      : null;


  const currentSourceHasAnalysis =
    currentSourceAnalyses.length > 0;


  const currentAnalysisIsBusy =
    isActiveAnalysisStatus(
      latestCurrentAnalysis?.status
    );


  /* ========================================
     삭제 제한

     분석 대기 / 진행 중인 작업이 있으면
     프로젝트 삭제를 허용하지 않음
  ======================================== */

  const projectHasActiveAnalysis =
    analysisHistory.some(
      (analysis) =>
        isActiveAnalysisStatus(
          analysis.status
        )
    );


  /* ========================================
     Source 관리 권한
  ======================================== */

  const canCreateFirstSource =
    isAdmin &&
    !currentSourceVersion;


  const canEditCurrentSource =
    isAdmin &&
    currentSourceVersion &&
    !currentSourceHasAnalysis;


  const canRunAnalysis =
    isAdmin &&
    currentSourceVersion &&
    !currentSourceHasAnalysis;


  const canCreateNewSource =
    isAdmin &&
    currentSourceVersion &&
    currentSourceHasAnalysis &&
    !currentAnalysisIsBusy;


  /* ========================================
     접근 사용자 관리
  ======================================== */

  const canManageAccess =
    isAdmin;


  /* ========================================
     프로젝트 이동 시 초기화
  ======================================== */

  useEffect(() => {

    setSelectedAnalysisId(
      null
    );

    setSelectedAnalysisProgress(
      null
    );

    setAnalysisProgressLoading(
      false
    );

    setAnalysisProgressError(
      ""
    );

    setShowSourceModal(
      false
    );

    setShowAnalysisModal(
      false
    );

    setShowUserModal(
      false
    );

    setShowDeleteModal(
      false
    );

    setDeletingProject(
      false
    );

    setDeleteError(
      ""
    );

    setAccessChangingUserId(
      null
    );

    setSavingSource(
      false
    );

  }, [
    project.id,
  ]);


  /* ========================================
     프로젝트 등록자
  ======================================== */

  const creator =
    users.find(
      (targetUser) =>
        targetUser.id ===
        project.createdById
    ) || null;


  const creatorName =
    creator?.username ||
    "-";


  /* ========================================
     선택 Analysis
  ======================================== */

  const selectedAnalysis =
    visibleAnalysisHistory.find(
      (analysis) =>
        analysis.id ===
        selectedAnalysisId
    ) || null;


  const selectedAnalysisProgressId =
    selectedAnalysis?.id ||
    null;


  const selectedAnalysisProgressStatus =
    selectedAnalysis?.status ||
    "";


  /* ========================================
     Analysis Chunk Progress 조회 / Polling

     관리자만 내부 Chunk 상태를 조회한다.

     pending / planning / running
     → 2초마다 갱신

     terminal 상태
     → 한 번 조회
  ======================================== */

  useEffect(() => {

    if (
      !selectedAnalysisProgressId
    ) {

      setSelectedAnalysisProgress(
        null
      );

      setAnalysisProgressLoading(
        false
      );

      setAnalysisProgressError(
        ""
      );

      return undefined;
    }


    let cancelled = false;
    let intervalId = null;


    setSelectedAnalysisProgress(
      null
    );

    setAnalysisProgressError(
      ""
    );


    const loadAnalysisProgress =
      async (
        showLoading = false
      ) => {

        if (
          showLoading &&
          !cancelled
        ) {
          setAnalysisProgressLoading(
            true
          );
        }


        try {

          const progress =
            await getAdminProjectAnalysisProgress(
              project.id,
              selectedAnalysisProgressId,
              accessToken,
              setAccessToken
            );


          if (cancelled) {
            return;
          }


          setSelectedAnalysisProgress(
            progress
          );

          setAnalysisProgressError(
            ""
          );

        } catch (error) {

          if (cancelled) {
            return;
          }


          console.error(
            "분석 Chunk 진행 정보 조회 실패:",
            error
          );


          setAnalysisProgressError(
            error.message ||
            "분석 Chunk 진행 정보를 불러오지 못했습니다."
          );

        } finally {

          if (
            showLoading &&
            !cancelled
          ) {
            setAnalysisProgressLoading(
              false
            );
          }
        }
      };


    loadAnalysisProgress(
      true
    );


    if (
      isActiveAnalysisStatus(
        selectedAnalysisProgressStatus
      )
    ) {

      intervalId =
        window.setInterval(
          () =>
            loadAnalysisProgress(
              false
            ),
          2000
        );
    }


    return () => {

      cancelled = true;


      if (
        intervalId !==
        null
      ) {
        window.clearInterval(
          intervalId
        );
      }
    };

  }, [
    project.id,
    selectedAnalysisProgressId,
    selectedAnalysisProgressStatus,
    accessToken,
    setAccessToken,
  ]);


  /* ========================================
     SourceVersion 찾기
  ======================================== */

  const getSourceVersionById = (
    sourceVersionId
  ) => {

    return (
      sourceVersions.find(
        (sourceVersion) =>
          sourceVersion.id ===
          sourceVersionId
      ) || null
    );
  };


  const selectedSourceVersion =
    selectedAnalysis
      ? getSourceVersionById(
          selectedAnalysis.sourceVersionId
        )
      : null;


  /* ========================================
     Source 언어

     앞으로 언어 정보의 기준은
     SourceVersion.language 하나만 사용.

     project.language 사용 X
     analysisLanguage 사용 X
  ======================================== */

  const getSourceLanguage = (
    sourceVersion
  ) => {

    return (
      sourceVersion?.language ||
      "-"
    );
  };


  /* ========================================
     Analysis 감지 언어

     Snapshot / Planner에서 감지된
     analysisLanguages가 있으면 그것을 우선 표시.

     아직 pending / planning 초반이라
     감지 결과가 없으면 SourceVersion 언어로
     임시 표시한다.
  ======================================== */

  const getAnalysisLanguageText = (
    analysis,
    sourceVersion
  ) => {

    const detectedLanguages =
      Array.isArray(
        analysis?.analysisLanguages
      )
        ? analysis.analysisLanguages
            .filter(
              Boolean
            )
        : [];


    if (
      detectedLanguages.length >
      0
    ) {

      return (
        detectedLanguages
          .map(
            getLanguageDisplayName
          )
          .join(
            ", "
          )
      );
    }


    if (
      analysis?.analysisLanguage
    ) {

      return (
        getLanguageDisplayName(
          analysis.analysisLanguage
        )
      );
    }


    return (
      getSourceLanguage(
        sourceVersion
      )
    );
  };


  /* ========================================
     Status
  ======================================== */

  const getStatusText = (
    status
  ) => {

    switch (
      status
    ) {

      case "pending":

        return "분석 대기";


      case "planning":

        return "분석 준비 중";


      case "running":

        return "분석 진행 중";


      case "completed":

        return "분석 완료";


      case "failed":

        return "분석 실패";


      case "cancelled":

        return "분석 취소";


      default:

        return "-";
    }
  };


  const selectedProgressPercent =
    Math.min(
      100,
      Math.max(
        0,
        Number(
          selectedAnalysisProgress
            ?.progressPercent ||
          0
        )
      )
    );


  const selectedQueuedChunkCount =
    (
      selectedAnalysisProgress
        ?.pendingChunks ||
      0
    ) +
    (
      selectedAnalysisProgress
        ?.queuedChunks ||
      0
    );


  /* ========================================
     Source Type
  ======================================== */

  const getSourceTypeText = (
    type
  ) => {

    switch (
      type
    ) {

      case "upload":

        return "파일 업로드";


      case "repository":

        return "저장소 연계";


      case "internal":

        return "내부 경로";


      default:

        return "-";
    }
  };


  /* ========================================
     Source 정보
  ======================================== */

  const getSourceInfo = (
    sourceVersion
  ) => {

    if (
      !sourceVersion
    ) {

      return "-";
    }


    switch (
      sourceVersion.sourceType
    ) {

      case "upload":

        return (
          sourceVersion.sourceFileName ||
          "-"
        );


      case "repository":

        return (
          sourceVersion.repositoryUrl ||
          "-"
        );


      case "internal":

        return (
          sourceVersion.internalPath ||
          "-"
        );


      default:

        return "-";
    }
  };


  /* ========================================
     결과 개수
  ======================================== */

  const getAnalysisResultCount = (
    analysis
  ) => {

    if (
      analysis.status !==
      "completed"
    ) {

      return "-";
    }


    if (
      analysis.summary
        ?.total !==
      undefined
    ) {

      return (
        `${analysis.summary.total}건`
      );
    }


    return (
      `${
        analysis.vulnerabilities
          ?.length ||
        0
      }건`
    );
  };


  /* ========================================
     취약점
  ======================================== */

  const selectedVulnerabilities =
    selectedAnalysis
      ?.vulnerabilities ||
    [];


  const analysisSummary =
    selectedAnalysis
      ?.summary || {

        total:
          selectedVulnerabilities.length,

        critical:
          selectedVulnerabilities.filter(
            (item) =>
              item.severity ===
              "critical"
          ).length,

        high:
          selectedVulnerabilities.filter(
            (item) =>
              item.severity ===
              "high"
          ).length,

        medium:
          selectedVulnerabilities.filter(
            (item) =>
              item.severity ===
              "medium"
          ).length,

        low:
          selectedVulnerabilities.filter(
            (item) =>
              item.severity ===
              "low"
          ).length,
      };


  /* ========================================
     Source Form 초기화
  ======================================== */

  const resetSourceForm = () => {

    setSourceType(
      "upload"
    );

    setSourceFile(
      null
    );

    setRepositoryUrl(
      ""
    );

    setInternalPath(
      ""
    );

    setSourceError(
      ""
    );
  };


  /* ========================================
     Source 등록
  ======================================== */

  const handleOpenCreateSourceModal = () => {

    resetSourceForm();


    setSourceModalMode(
      "create"
    );


    setShowSourceModal(
      true
    );
  };


  /* ========================================
     Source 수정
  ======================================== */

  const handleOpenEditSourceModal = () => {

    if (
      !currentSourceVersion ||
      !canEditCurrentSource
    ) {

      return;
    }


    setSourceModalMode(
      "edit"
    );


    setSourceType(
      currentSourceVersion.sourceType ||
      "upload"
    );


    setSourceFile(
      null
    );


    setRepositoryUrl(
      currentSourceVersion.repositoryUrl ||
      ""
    );


    setInternalPath(
      currentSourceVersion.internalPath ||
      ""
    );


    setSourceError(
      ""
    );


    setShowSourceModal(
      true
    );
  };


  /* ========================================
     Source Modal 닫기
  ======================================== */

  const handleCloseSourceModal = () => {

    setShowSourceModal(
      false
    );


    resetSourceForm();
  };


  /* ========================================
     Source 저장
  ======================================== */

  const handleSourceSubmit =
    async (
      event
    ) => {

      event.preventDefault();


      if (savingSource) {
        return;
      }


      setSourceError(
        ""
      );


      const uploadFileRequired =
        sourceType ===
          "upload" &&
        !sourceFile &&
        (
          sourceModalMode ===
            "create" ||
          currentSourceVersion
            ?.sourceType !==
            "upload"
        );


      if (uploadFileRequired) {

        setSourceError(
          "분석할 파일을 선택해주세요."
        );

        return;
      }


      if (
        sourceType ===
          "repository" &&
        !repositoryUrl.trim()
      ) {

        setSourceError(
          "저장소 주소를 입력해주세요."
        );

        return;
      }


      if (
        sourceType ===
          "internal" &&
        !internalPath.trim()
      ) {

        setSourceError(
          "내부 경로를 입력해주세요."
        );

        return;
      }


      const sourceData = {

        sourceType:
          sourceType,

        sourceFile:
          sourceType ===
            "upload"
            ? sourceFile
            : null,

        repositoryUrl:
          sourceType ===
            "repository"
            ? repositoryUrl.trim()
            : "",

        internalPath:
          sourceType ===
            "internal"
            ? internalPath.trim()
            : "",
      };


      setSavingSource(
        true
      );


      try {

        if (
          sourceModalMode ===
          "create"
        ) {

          await onAddSourceVersion?.(
            project.id,
            sourceData
          );
        }


        if (
          sourceModalMode ===
            "edit" &&
          currentSourceVersion
        ) {

          await onUpdateSourceVersion?.(
            project.id,
            currentSourceVersion.id,
            sourceData
          );
        }


        handleCloseSourceModal();

      } catch (error) {

        setSourceError(
          error.message ||
          (
            sourceModalMode ===
              "edit"
              ? "분석 대상 수정에 실패했습니다."
              : "분석 대상 등록에 실패했습니다."
          )
        );

      } finally {

        setSavingSource(
          false
        );
      }
    };


  /* ========================================
     분석 실행
  ======================================== */

  const handleOpenAnalysisModal = () => {

    if (
      !canRunAnalysis
    ) {

      return;
    }


    setShowAnalysisModal(
      true
    );
  };


  const handleAnalysisConfirm = () => {

    if (
      !currentSourceVersion ||
      !canRunAnalysis
    ) {

      return;
    }


    setShowAnalysisModal(
      false
    );


    onRunAnalysis?.(
      project.id,
      currentSourceVersion.id
    );
  };


  /* ========================================
     분석 조회
  ======================================== */

  const handleViewAnalysis = (
    analysisId
  ) => {

    setSelectedAnalysisId(
      analysisId
    );
  };


  /* ========================================
     접근 사용자
  ======================================== */

  const assignedUsers =
    canManageAccess
      ? users.filter(
          (targetUser) =>
            (
              project.assignedUserIds ||
              []
            ).includes(
              targetUser.id
            )
        )
      : [];


  const availableUsers =
    canManageAccess
      ? users.filter(
          (targetUser) => {

            if (
              targetUser.role !==
              "user"
            ) {

              return false;
            }


            if (
              !targetUser.isActive
            ) {

              return false;
            }


            if (
              (
                project.assignedUserIds ||
                []
              ).includes(
                targetUser.id
              )
            ) {

              return false;
            }


            const keyword =
              userSearch
                .trim()
                .toLowerCase();


            if (
              !keyword
            ) {

              return true;
            }


            return (
              targetUser.username
                .toLowerCase()
                .includes(
                  keyword
                )
            );
          }
        )
      : [];


  const handleOpenUserModal = () => {

    if (
      !canManageAccess
    ) {

      return;
    }


    setUserSearch(
      ""
    );


    setShowUserModal(
      true
    );
  };


  const handleGrantAccess =
    async (
      userId
    ) => {

      if (
        accessChangingUserId !==
        null
      ) {

        return;
      }


      setAccessChangingUserId(
        userId
      );


      try {

        await onGrantUserAccess?.(
          project.id,
          userId
        );

      } catch (error) {

        console.error(
          "프로젝트 사용자 할당 실패:",
          error
        );


        window.alert(
          error.message ||
          "프로젝트 사용자 할당에 실패했습니다."
        );

      } finally {

        setAccessChangingUserId(
          null
        );
      }
    };


  const handleRevokeAccess =
    async (
      userId
    ) => {

      if (
        accessChangingUserId !==
        null
      ) {

        return;
      }


      setAccessChangingUserId(
        userId
      );


      try {

        await onRevokeUserAccess?.(
          project.id,
          userId
        );

      } catch (error) {

        console.error(
          "프로젝트 사용자 할당 해제 실패:",
          error
        );


        window.alert(
          error.message ||
          "프로젝트 사용자 할당 해제에 실패했습니다."
        );

      } finally {

        setAccessChangingUserId(
          null
        );
      }
    };


  /* ========================================
     프로젝트 삭제 Modal
  ======================================== */

  const handleOpenDeleteModal =
    () => {

      if (
        !isAdmin ||
        projectHasActiveAnalysis
      ) {
        return;
      }


      setDeleteError(
        ""
      );


      setShowDeleteModal(
        true
      );
    };


  const handleCloseDeleteModal =
    () => {

      if (
        deletingProject
      ) {
        return;
      }


      setDeleteError(
        ""
      );


      setShowDeleteModal(
        false
      );
    };


  const handleDeleteConfirm =
    async () => {

      if (
        deletingProject ||
        !onDelete
      ) {
        return;
      }


      setDeleteError(
        ""
      );


      setDeletingProject(
        true
      );


      try {

        await onDelete(
          project.id
        );

      } catch (error) {

        console.error(
          "프로젝트 삭제 실패:",
          error
        );


        setDeleteError(
          error.message ||
          "프로젝트 삭제에 실패했습니다."
        );


        setDeletingProject(
          false
        );
      }
    };


  /* ========================================
     다음 Source Version
  ======================================== */

  const nextSourceVersion =
    sourceVersions.length > 0
      ? Math.max(
          ...sourceVersions.map(
            (sourceVersion) =>
              sourceVersion.version
          )
        ) + 1
      : 1;


  return (

    <div className="project-detail">


      {/* ===================================
          Header
      =================================== */}

      <div className="project-detail-header">


        <button
          className="back-button"

          onClick={
            onBack
          }
        >
          ← 목록으로
        </button>


        <div className="project-detail-title">

          <h2>
            프로젝트 상세 정보
          </h2>

          <p>
            프로젝트 정보와 분석 대상, 분석 이력을 관리합니다.
          </p>

        </div>


      </div>


      {/* ===================================
          프로젝트 기본 정보
      =================================== */}

      <section className="project-detail-section">


        <div className="project-detail-section-header">


          <div>

            <h3>
              프로젝트 기본 정보
            </h3>

            <p>
              프로젝트의 기본 정보를 확인합니다.
            </p>

          </div>


          {
            isAdmin && (

              <button
                className="project-edit-button"

                onClick={
                  onEdit
                }
              >
                프로젝트 수정
              </button>

            )
          }


        </div>


        <div className="project-detail-card">


          <div className="project-detail-row">

            <div className="detail-label">
              프로젝트명
            </div>

            <div className="detail-value">
              {project.name}
            </div>

          </div>


          <div className="project-detail-row">

            <div className="detail-label">
              설명
            </div>

            <div className="detail-value">

              {
                project.description ||
                "-"
              }

            </div>

          </div>


          <div className="project-detail-row">

            <div className="detail-label">
              등록자
            </div>

            <div className="detail-value">
              {creatorName}
            </div>

          </div>


          <div className="project-detail-row">

            <div className="detail-label">
              등록 일시
            </div>

            <div className="detail-value">

              {
                project.createdAt ||
                "-"
              }

            </div>

          </div>


        </div>


      </section>


      {/* ===================================
          현재 분석 대상
      =================================== */}

      {
        isAdmin && (

          <section className="project-detail-section">


            <div className="project-detail-section-header">


              <div>

                <h3>
                  현재 분석 대상
                </h3>

                <p>
                  다음 정적 분석에 사용할 소스를 관리합니다.
                </p>

              </div>


              {
                canCreateFirstSource && (

                  <button
                    className="source-primary-button"

                    onClick={
                      handleOpenCreateSourceModal
                    }
                  >
                    분석 대상 등록
                  </button>

                )
              }


              {
                canEditCurrentSource && (

                  <button
                    className="source-secondary-button"

                    onClick={
                      handleOpenEditSourceModal
                    }
                  >
                    분석 대상 수정
                  </button>

                )
              }


              {
                canCreateNewSource && (

                  <button
                    className="source-primary-button"

                    onClick={
                      handleOpenCreateSourceModal
                    }
                  >
                    새 분석 대상 등록
                  </button>

                )
              }


            </div>


            {
              currentSourceVersion
                ? (

                  <div className="current-source-card">


                    <div className="current-source-version">

                      Source v
                      {currentSourceVersion.version}

                    </div>


                    <div className="current-source-grid">


                      <div className="current-source-item">

                        <span>
                          소스 언어
                        </span>

                        <strong>

                          {
                            getSourceLanguage(
                              currentSourceVersion
                            )
                          }

                        </strong>

                      </div>


                      <div className="current-source-item">

                        <span>
                          소스 유형
                        </span>

                        <strong>

                          {
                            getSourceTypeText(
                              currentSourceVersion.sourceType
                            )
                          }

                        </strong>

                      </div>


                      <div className="current-source-item">

                        <span>
                          소스 정보
                        </span>

                        <strong>

                          {
                            getSourceInfo(
                              currentSourceVersion
                            )
                          }

                        </strong>

                      </div>


                      <div className="current-source-item">

                        <span>
                          등록 일시
                        </span>

                        <strong>

                          {
                            currentSourceVersion.createdAt ||
                            "-"
                          }

                        </strong>

                      </div>


                    </div>


                    {
                      currentAnalysisIsBusy && (

                        <div className="current-source-running">


                          <span
                            className={
                              `project-status ${latestCurrentAnalysis.status}`
                            }
                          >

                            {
                              getStatusText(
                                latestCurrentAnalysis.status
                              )
                            }

                          </span>


                          <p>
                            현재 분석 작업이 대기·준비·진행 중이므로 분석 대상을 변경할 수 없습니다.
                          </p>


                        </div>

                      )
                    }


                    {
                      canRunAnalysis && (

                        <div className="current-source-actions">

                          <button
                            className="analysis-run-button"

                            onClick={
                              handleOpenAnalysisModal
                            }
                          >
                            분석 실행
                          </button>

                        </div>

                      )
                    }


                  </div>

                )
                : (

                  <div className="current-source-empty">

                    <strong>
                      등록된 분석 대상이 없습니다.
                    </strong>

                    <p>
                      분석을 실행하려면 먼저 분석 대상 소스를 등록해주세요.
                    </p>

                  </div>

                )
            }


          </section>

        )
      }


      {/* ===================================
          분석 이력
      =================================== */}

      <section className="project-detail-section">


        <div className="project-detail-section-header">

          <div>

            <h3>
              분석 이력
            </h3>

            <p>
              프로젝트에서 실행된 정적 분석 이력을 확인합니다.
            </p>

          </div>

        </div>


        {
          visibleAnalysisHistory.length > 0
            ? (

              <div className="analysis-history-card">


                <div className="analysis-history-table-wrapper">


                  <table className="analysis-history-table">


                    <thead>

                      <tr>

                        <th>
                          소스 버전
                        </th>

                        <th>
                          소스 언어
                        </th>

                        <th>
                          분석 상태
                        </th>

                        <th>
                          시작 일시
                        </th>

                        <th>
                          종료 일시
                        </th>

                        <th>
                          결과
                        </th>

                        <th>
                          조회
                        </th>

                      </tr>

                    </thead>


                    <tbody>


                      {
                        visibleAnalysisHistory.map(
                          (analysis) => {

                            const sourceVersion =
                              getSourceVersionById(
                                analysis.sourceVersionId
                              );


                            const isSelected =
                              selectedAnalysisId ===
                              analysis.id;


                            return (

                              <tr
                                key={
                                  analysis.id
                                }

                                className={
                                  isSelected
                                    ? "selected"
                                    : ""
                                }
                              >


                                <td>

                                  <strong>

                                    {
                                      sourceVersion
                                        ? `v${sourceVersion.version}`
                                        : "-"
                                    }

                                  </strong>

                                </td>


                                <td>

                                  {
                                    getAnalysisLanguageText(
                                      analysis,
                                      sourceVersion
                                    )
                                  }

                                </td>


                                <td>

                                  <span
                                    className={
                                      `project-status ${analysis.status}`
                                    }
                                  >

                                    {
                                      getStatusText(
                                        analysis.status
                                      )
                                    }

                                  </span>

                                </td>


                                <td>

                                  {
                                    analysis.startedAt ||
                                    "-"
                                  }

                                </td>


                                <td>

                                  {
                                    analysis.completedAt ||
                                    "-"
                                  }

                                </td>


                                <td>

                                  {
                                    getAnalysisResultCount(
                                      analysis
                                    )
                                  }

                                </td>


                                <td>

                                  <button
                                    className="analysis-view-button"

                                    onClick={() =>
                                      handleViewAnalysis(
                                        analysis.id
                                      )
                                    }
                                  >
                                    조회
                                  </button>

                                </td>


                              </tr>

                            );
                          }
                        )
                      }


                    </tbody>


                  </table>


                </div>


              </div>

            )
            : (

              <div className="analysis-history-empty">

                {
                  isAdmin
                    ? "아직 실행된 분석이 없습니다."
                    : "조회 가능한 분석 결과가 없습니다."
                }

              </div>

            )
        }


      </section>


      {/* ===================================
          조회 결과
      =================================== */}

      {
        selectedAnalysis && (

          <section className="project-detail-section analysis-detail-section">


            <div className="analysis-detail-header">


              <div>

                <h3>
                  분석 결과 조회
                </h3>

                <p>

                  Analysis #
                  {selectedAnalysis.sequence}

                  {" · "}

                  {
                    selectedSourceVersion
                      ? `Source v${selectedSourceVersion.version}`
                      : "Source 정보 없음"
                  }

                  {" · "}

                  {
                    getAnalysisLanguageText(
                      selectedAnalysis,
                      selectedSourceVersion
                    )
                  }

                </p>

              </div>


              <span
                className={
                  `project-status ${selectedAnalysis.status}`
                }
              >

                {
                  getStatusText(
                    selectedAnalysis.status
                  )
                }

              </span>


            </div>


            {
              (

                <div className="chunk-progress-card">


                  <div className="chunk-progress-header">

                    <div>

                      <h4>
                        Chunk 처리 현황
                      </h4>

                      <p>
                        PostgreSQL에 저장된 Chunk 상태를 기준으로 표시합니다.
                      </p>

                    </div>


                    <strong>
                      {selectedProgressPercent}%
                    </strong>

                  </div>


                  <div className="chunk-progress-track">

                    <div
                      className="chunk-progress-bar"

                      style={{
                        width:
                          `${selectedProgressPercent}%`,
                      }}
                    />

                  </div>


                  {
                    analysisProgressLoading &&
                    !selectedAnalysisProgress
                      ? (

                        <div className="chunk-progress-loading">
                          Chunk 진행 정보를 불러오는 중입니다.
                        </div>

                      )
                      : analysisProgressError &&
                        !selectedAnalysisProgress
                        ? (

                          <div className="chunk-progress-error">
                            {analysisProgressError}
                          </div>

                        )
                        : selectedAnalysisProgress
                          ? (

                            <>

                              {
                                analysisProgressError && (

                                  <div className="chunk-progress-warning">
                                    최근 진행 정보를 갱신하지 못했습니다. 마지막으로 조회한 상태를 표시합니다.
                                  </div>

                                )
                              }


                              <div className="chunk-progress-stats">

                                <div>
                                  <span>전체</span>
                                  <strong>
                                    {selectedAnalysisProgress.totalChunks}
                                  </strong>
                                </div>

                                <div>
                                  <span>완료</span>
                                  <strong>
                                    {selectedAnalysisProgress.completedChunks}
                                  </strong>
                                </div>

                                <div>
                                  <span>실행 중</span>
                                  <strong>
                                    {selectedAnalysisProgress.runningChunks}
                                  </strong>
                                </div>

                                <div>
                                  <span>대기</span>
                                  <strong>
                                    {selectedQueuedChunkCount}
                                  </strong>
                                </div>

                                <div>
                                  <span>재시도 대기</span>
                                  <strong>
                                    {selectedAnalysisProgress.retryPendingChunks}
                                  </strong>
                                </div>

                                <div>
                                  <span>실패</span>
                                  <strong>
                                    {selectedAnalysisProgress.failedChunks}
                                  </strong>
                                </div>

                                <div>
                                  <span>건너뜀</span>
                                  <strong>
                                    {selectedAnalysisProgress.skippedChunks}
                                  </strong>
                                </div>

                                <div>
                                  <span>취소</span>
                                  <strong>
                                    {selectedAnalysisProgress.cancelledChunks}
                                  </strong>
                                </div>

                              </div>


                              <div className="chunk-progress-metadata">

                                <span>
                                  파일 {selectedAnalysisProgress.totalFiles}개
                                </span>

                                <span>
                                  분석 크기 {formatBytes(selectedAnalysisProgress.totalBytes)}
                                </span>

                                <span>
                                  탐지 {selectedAnalysisProgress.resultCount}건
                                </span>

                                <span>
                                  재시도 {selectedAnalysisProgress.retryCount}회
                                </span>

                              </div>


                              {
                                selectedAnalysisProgress.languages.length > 0 && (

                                  <div className="chunk-language-progress-list">

                                    {
                                      selectedAnalysisProgress.languages.map(
                                        (languageProgress) => {

                                          const waitingCount =
                                            (
                                              languageProgress.pending ||
                                              0
                                            ) +
                                            (
                                              languageProgress.queued ||
                                              0
                                            );


                                          return (

                                            <div
                                              className="chunk-language-progress-item"
                                              key={languageProgress.language}
                                            >

                                              <div className="chunk-language-progress-title">

                                                <strong>
                                                  {
                                                    getLanguageDisplayName(
                                                      languageProgress.language
                                                    )
                                                  }
                                                </strong>

                                                <span>
                                                  {languageProgress.terminal}/{languageProgress.total} 처리
                                                  {" · "}
                                                  {languageProgress.progressPercent}%
                                                </span>

                                              </div>


                                              <div className="chunk-language-progress-track">

                                                <div
                                                  style={{
                                                    width:
                                                      `${Math.min(
                                                        100,
                                                        Math.max(
                                                          0,
                                                          Number(
                                                            languageProgress.progressPercent ||
                                                            0
                                                          )
                                                        )
                                                      )}%`,
                                                  }}
                                                />

                                              </div>


                                              <p>
                                                완료 {languageProgress.completed}
                                                {" · "}
                                                실행 {languageProgress.running}
                                                {" · "}
                                                대기 {waitingCount}
                                                {" · "}
                                                재시도 {languageProgress.retryPending}
                                                {
                                                  languageProgress.failed > 0
                                                    ? ` · 실패 ${languageProgress.failed}`
                                                    : ""
                                                }
                                                {
                                                  languageProgress.skipped > 0
                                                    ? ` · 건너뜀 ${languageProgress.skipped}`
                                                    : ""
                                                }
                                              </p>

                                            </div>

                                          );
                                        }
                                      )
                                    }

                                  </div>

                                )
                              }


                              <div className="chunk-progress-table-wrapper">

                                {
                                  selectedAnalysisProgress.chunks.length > 0
                                    ? (

                                      <table className="chunk-progress-table">

                                        <thead>
                                          <tr>
                                            <th>Chunk</th>
                                            <th>언어</th>
                                            <th>파일</th>
                                            <th>상태</th>
                                            <th>재시도</th>
                                            <th>탐지</th>
                                          </tr>
                                        </thead>

                                        <tbody>

                                          {
                                            selectedAnalysisProgress.chunks.map(
                                              (chunk) => (

                                                <tr key={chunk.id}>

                                                  <td>
                                                    #{chunk.sequence}
                                                  </td>

                                                  <td>
                                                    {
                                                      getLanguageDisplayName(
                                                        chunk.language
                                                      )
                                                    }
                                                  </td>

                                                  <td>
                                                    {chunk.fileCount}개
                                                  </td>

                                                  <td>

                                                    <span
                                                      className={
                                                        `chunk-status ${chunk.status}`
                                                      }
                                                    >
                                                      {
                                                        getChunkStatusText(
                                                          chunk.status
                                                        )
                                                      }
                                                    </span>

                                                    {
                                                      chunk.statusReason && (
                                                        <small className="chunk-status-reason">
                                                          {chunk.statusReason}
                                                        </small>
                                                      )
                                                    }

                                                  </td>

                                                  <td>
                                                    {
                                                      chunk.maxRetries > 0
                                                        ? `${chunk.retryCount}/${chunk.maxRetries}`
                                                        : chunk.retryCount
                                                    }
                                                  </td>

                                                  <td>
                                                    {chunk.resultCount}건
                                                  </td>

                                                </tr>

                                              )
                                            )
                                          }

                                        </tbody>

                                      </table>

                                    )
                                    : (

                                      <div className="chunk-progress-empty">
                                        아직 생성된 Chunk가 없습니다. 분석 준비가 완료되면 Chunk 진행 정보가 표시됩니다.
                                      </div>

                                    )
                                }

                              </div>

                            </>

                          )
                          : (

                            <div className="chunk-progress-empty">
                              표시할 Chunk 진행 정보가 없습니다.
                            </div>

                          )
                  }

                </div>

              )
            }


            {
              selectedAnalysis.status ===
                "completed" && (

                <div className="analysis-completed-content">


                  <div className="analysis-summary-grid">


                    <div className="analysis-summary-card">

                      <span>
                        전체
                      </span>

                      <strong>
                        {analysisSummary.total}
                      </strong>

                    </div>


                    <div className="analysis-summary-card critical">

                      <span>
                        Critical
                      </span>

                      <strong>
                        {analysisSummary.critical}
                      </strong>

                    </div>


                    <div className="analysis-summary-card high">

                      <span>
                        High
                      </span>

                      <strong>
                        {analysisSummary.high}
                      </strong>

                    </div>


                    <div className="analysis-summary-card medium">

                      <span>
                        Medium
                      </span>

                      <strong>
                        {analysisSummary.medium}
                      </strong>

                    </div>


                    <div className="analysis-summary-card low">

                      <span>
                        Low
                      </span>

                      <strong>
                        {analysisSummary.low}
                      </strong>

                    </div>


                  </div>


                  <VulnerabilityPanel
                    vulnerabilities={
                      selectedVulnerabilities
                    }
                    resetKey={
                      selectedAnalysisId
                    }
                    variant="admin"
                  />


                </div>

              )
            }


            {
              selectedAnalysis.status ===
                "failed" && (

                <div className="analysis-failed-content">


                  <div className="analysis-failure-card">

                    <h4>
                      실패 원인
                    </h4>

                    <p>

                      {
                        selectedAnalysis.failureReason ||
                        "실패 원인 정보가 없습니다."
                      }

                    </p>

                  </div>


                  <div className="analysis-log-card">

                    <h4>
                      실패 로그
                    </h4>

                    <pre>

                      {
                        selectedAnalysis.logs ||
                        "분석 로그가 없습니다."
                      }

                    </pre>

                  </div>


                </div>

              )
            }


            {
              selectedAnalysis.status ===
                "pending" && (

                <div className="analysis-progress-box">

                  <h4>
                    분석 요청이 대기 중입니다.
                  </h4>

                  <p>
                    분석 요청이 등록되었습니다. Worker가 작업을 가져가면 분석 준비 상태로 변경됩니다.
                  </p>

                </div>

              )
            }


            {
              selectedAnalysis.status ===
                "planning" && (

                <div className="analysis-progress-box">

                  <div className="analysis-progress-spinner" />

                  <h4>
                    분석 대상을 준비하고 있습니다.
                  </h4>

                  <p>
                    소스 스냅샷을 만들고 분석 파일을 언어별 Chunk로 구성하고 있습니다.
                  </p>

                </div>

              )
            }


            {
              selectedAnalysis.status ===
                "running" && (

                <div className="analysis-progress-box">

                  <div className="analysis-progress-spinner" />

                  <h4>
                    분석이 진행 중입니다.
                  </h4>

                  <p>
                    Chunk 단위로 정적 분석을 처리하고 있습니다. 일시적인 Worker 장애가 발생하면 Recovery가 자동으로 이어서 처리합니다.
                  </p>

                </div>

              )
            }


            {
              selectedAnalysis.status ===
                "cancelled" && (

                <div className="analysis-message-box">
                  취소된 분석입니다. 이 분석에서는 새로운 취약점 결과가 생성되지 않습니다.
                </div>

              )
            }

          </section>

        )
      }


      {/* ===================================
          접근 사용자
      =================================== */}

      {
        canManageAccess && (

          <section className="project-detail-section">


            <div className="project-detail-section-header">


              <div>

                <h3>
                  접근 사용자
                </h3>

                <p>
                  프로젝트 접근 권한을 가진 사용자를 관리합니다.
                </p>

              </div>


              <button
                className="user-assign-button"

                onClick={
                  handleOpenUserModal
                }
              >
                사용자 할당
              </button>


            </div>


            <div className="project-access-card">


              {
                assignedUsers.length > 0
                  ? assignedUsers.map(
                      (assignedUser) => (

                        <div
                          className="project-access-item"

                          key={
                            assignedUser.id
                          }
                        >


                          <div>

                            <strong>
                              {assignedUser.username}
                            </strong>

                            <span>
                              일반 사용자
                            </span>

                          </div>


                          <button
                            className="access-revoke-button"

                            disabled={
                              accessChangingUserId !==
                              null
                            }

                            onClick={() =>
                              handleRevokeAccess(
                                assignedUser.id
                              )
                            }
                          >
                            {
                              accessChangingUserId ===
                                assignedUser.id
                                ? "해제 중..."
                                : "권한 해제"
                            }
                          </button>


                        </div>

                      )
                    )

                  : (

                    <div className="project-access-empty">

                      할당된 사용자가 없습니다.

                    </div>

                  )
              }


            </div>


          </section>

        )
      }


      {/* ===================================
          위험 작업
      =================================== */}

      {
        isAdmin && (

          <section className="project-detail-section">

            <div className="project-detail-section-header">

              <div>

                <h3>
                  위험 작업
                </h3>

                <p>
                  프로젝트를 영구적으로 삭제하는 작업입니다.
                </p>

              </div>

            </div>


            <div className="project-danger-card">

              <div>

                <strong>
                  프로젝트 삭제
                </strong>

                <p>

                  {
                    projectHasActiveAnalysis
                      ? (
                          "분석 대기·준비 또는 진행 중인 작업이 있어 현재 프로젝트를 삭제할 수 없습니다."
                        )
                      : (
                          "프로젝트와 관련된 소스 버전, 분석 이력, 취약점 결과 및 사용자 접근 권한이 함께 삭제됩니다."
                        )
                  }

                </p>

              </div>


              <button
                type="button"

                className="project-delete-button"

                disabled={
                  projectHasActiveAnalysis
                }

                onClick={
                  handleOpenDeleteModal
                }
              >
                프로젝트 삭제
              </button>

            </div>

          </section>

        )
      }


      {/* ===================================
          Delete Modal
      =================================== */}

      {
        showDeleteModal && (

          <div className="modal-overlay">

            <div className="project-modal">

              <div className="project-modal-header">

                <h3>
                  프로젝트 삭제
                </h3>

                <p>
                  삭제한 프로젝트는 복구할 수 없습니다.
                </p>

              </div>


              <div className="delete-confirm-info">

                <p>

                  <strong>
                    {project.name}
                  </strong>

                  {" 프로젝트를 삭제하시겠습니까?"}

                </p>


                <div className="delete-warning-box">

                  프로젝트를 삭제하면 관련 소스 버전,
                  분석 이력, 취약점 결과 및 사용자 접근 권한도
                  함께 삭제됩니다.

                </div>

              </div>


              {
                deleteError && (

                  <div className="source-form-error">
                    {deleteError}
                  </div>

                )
              }


              <div className="project-modal-actions">

                <button
                  type="button"

                  className="modal-cancel-button"

                  disabled={
                    deletingProject
                  }

                  onClick={
                    handleCloseDeleteModal
                  }
                >
                  취소
                </button>


                <button
                  type="button"

                  className="modal-danger-button"

                  disabled={
                    deletingProject
                  }

                  onClick={
                    handleDeleteConfirm
                  }
                >

                  {
                    deletingProject
                      ? "삭제 중..."
                      : "프로젝트 삭제"
                  }

                </button>

              </div>

            </div>

          </div>

        )
      }


      {/* ===================================
          Source Modal
      =================================== */}

      {
        showSourceModal && (

          <div className="modal-overlay">


            <div className="project-modal">


              <div className="project-modal-header">


                <h3>

                  {
                    sourceModalMode ===
                      "edit"
                      ? "분석 대상 수정"
                      : currentSourceVersion
                        ? "새 분석 대상 등록"
                        : "분석 대상 등록"
                  }

                </h3>


                <p>

                  {
                    sourceModalMode ===
                      "edit"
                      ? "아직 분석하지 않은 분석 대상을 수정합니다."
                      : `Source v${nextSourceVersion}을 등록합니다.`
                  }

                </p>


              </div>


              <form
                onSubmit={
                  handleSourceSubmit
                }
              >


                <div className="source-form-group">

                  <label>
                    소스 유형
                  </label>


                  <select
                    value={
                      sourceType
                    }

                    disabled={
                      savingSource
                    }

                    onChange={
                      (event) => {

                        setSourceType(
                          event.target.value
                        );

                        setSourceError(
                          ""
                        );
                      }
                    }
                  >

                    <option value="upload">
                      파일 업로드
                    </option>

                    <option value="repository">
                      저장소 연계
                    </option>

                    <option value="internal">
                      내부 경로
                    </option>

                  </select>

                </div>


                {
                  sourceType ===
                    "upload" && (

                    <div className="source-form-group">

                      <label>
                        분석 파일
                      </label>


                      {
                        sourceModalMode ===
                          "edit" &&
                        currentSourceVersion
                          ?.sourceFileName && (

                          <div className="current-file-info">

                            현재 파일:
                            {" "}
                            {
                              currentSourceVersion.sourceFileName
                            }

                          </div>

                        )
                      }


                      <input
                        type="file"

                        disabled={
                          savingSource
                        }

                        onChange={
                          (event) =>
                            setSourceFile(
                              event.target.files?.[0] ||
                              null
                            )
                        }
                      />

                    </div>

                  )
                }


                {
                  sourceType ===
                    "repository" && (

                    <div className="source-form-group">

                      <label>
                        저장소 주소
                      </label>


                      <input
                        type="text"

                        value={
                          repositoryUrl
                        }

                        disabled={
                          savingSource
                        }

                        placeholder="https://..."

                        onChange={
                          (event) =>
                            setRepositoryUrl(
                              event.target.value
                            )
                        }
                      />

                    </div>

                  )
                }


                {
                  sourceType ===
                    "internal" && (

                    <div className="source-form-group">

                      <label>
                        내부 경로
                      </label>


                      <input
                        type="text"

                        value={
                          internalPath
                        }

                        disabled={
                          savingSource
                        }

                        placeholder="/source/project"

                        onChange={
                          (event) =>
                            setInternalPath(
                              event.target.value
                            )
                        }
                      />

                    </div>

                  )
                }


                {
                  sourceError && (

                    <div className="source-form-error">

                      {sourceError}

                    </div>

                  )
                }


                <div className="project-modal-actions">


                  <button
                    type="button"

                    className="modal-cancel-button"

                    disabled={
                      savingSource
                    }

                    onClick={
                      handleCloseSourceModal
                    }
                  >
                    취소
                  </button>


                  <button
                    type="submit"

                    className="modal-primary-button"

                    disabled={
                      savingSource
                    }
                  >

                    {
                      savingSource
                        ? "저장 중..."
                        : (
                            sourceModalMode ===
                              "edit"
                              ? "수정"
                              : "등록"
                          )
                    }

                  </button>


                </div>


              </form>


            </div>


          </div>

        )
      }


      {/* ===================================
          Analysis Modal
      =================================== */}

      {
        showAnalysisModal &&
        currentSourceVersion && (

          <div className="modal-overlay">


            <div className="project-modal">


              <div className="project-modal-header">

                <h3>
                  분석 실행
                </h3>

                <p>
                  등록된 분석 대상으로 정적 분석을 실행합니다.
                </p>

              </div>


              <div className="analysis-confirm-info">


                <div>

                  <span>
                    소스 버전
                  </span>

                  <strong>
                    v{currentSourceVersion.version}
                  </strong>

                </div>


                <div>

                  <span>
                    소스 언어
                  </span>

                  <strong>

                    {
                      getSourceLanguage(
                        currentSourceVersion
                      )
                    }

                  </strong>

                </div>


                <div>

                  <span>
                    소스 정보
                  </span>

                  <strong>

                    {
                      getSourceInfo(
                        currentSourceVersion
                      )
                    }

                  </strong>

                </div>


              </div>


              <div className="project-modal-actions">


                <button
                  type="button"

                  className="modal-cancel-button"

                  onClick={() =>
                    setShowAnalysisModal(
                      false
                    )
                  }
                >
                  취소
                </button>


                <button
                  type="button"

                  className="modal-primary-button"

                  onClick={
                    handleAnalysisConfirm
                  }
                >
                  분석 실행
                </button>


              </div>


            </div>


          </div>

        )
      }


      {/* ===================================
          User Modal
      =================================== */}

      {
        showUserModal &&
        canManageAccess && (

          <div className="modal-overlay">


            <div className="project-modal">


              <div className="project-modal-header">

                <h3>
                  사용자 할당
                </h3>

                <p>
                  프로젝트에 접근 권한을 부여할 사용자를 선택합니다.
                </p>

              </div>


              <div className="user-search-area">

                <input
                  type="text"

                  value={
                    userSearch
                  }

                  placeholder="사용자 아이디 검색"

                  onChange={
                    (event) =>
                      setUserSearch(
                        event.target.value
                      )
                  }
                />

              </div>


              <div className="available-user-list">


                {
                  availableUsers.length > 0
                    ? availableUsers.map(
                        (availableUser) => (

                          <div
                            className="available-user-item"

                            key={
                              availableUser.id
                            }
                          >


                            <span>
                              {availableUser.username}
                            </span>


                            <button
                              disabled={
                                accessChangingUserId !==
                                null
                              }

                              onClick={() =>
                                handleGrantAccess(
                                  availableUser.id
                                )
                              }
                            >
                              {
                                accessChangingUserId ===
                                  availableUser.id
                                  ? "추가 중..."
                                  : "추가"
                              }
                            </button>


                          </div>

                        )
                      )

                    : (

                      <div className="available-user-empty">

                        할당 가능한 사용자가 없습니다.

                      </div>

                    )
                }


              </div>


              <div className="project-modal-actions">

                <button
                  type="button"

                  className="modal-cancel-button"

                  onClick={() =>
                    setShowUserModal(
                      false
                    )
                  }
                >
                  닫기
                </button>

              </div>


            </div>


          </div>

        )
      }





    </div>

  );
}


export default ProjectDetail;