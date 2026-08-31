import {
  useEffect,
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import "./ProjectDetail.css";


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
    selectedVulnerability,
    setSelectedVulnerability,
  ] = useState(null);


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
    latestCurrentAnalysis?.status ===
      "pending" ||
    latestCurrentAnalysis?.status ===
      "running";


  /* ========================================
     삭제 제한

     분석 대기 / 진행 중인 작업이 있으면
     프로젝트 삭제를 허용하지 않음
  ======================================== */

  const projectHasActiveAnalysis =
    analysisHistory.some(
      (analysis) =>
        analysis.status ===
          "pending" ||
        analysis.status ===
          "running"
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

    setSelectedVulnerability(
      null
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
     분석 언어

     Backend에서 자동 감지한 언어를 사용한다.

     SourceVersion.detectedLanguages
     → 현재 소스에서 감지된 언어

     AnalysisRun.analysisLanguages
     → 분석 실행 당시 언어 Snapshot
  ======================================== */

  const getLanguageLabel = (
    language
  ) => {

    switch (
      language
    ) {

      case "java":
        return "Java";

      case "javascript":
        return "JavaScript";

      case "python":
        return "Python";

      default:
        return (
          language ||
          "-"
        );
    }
  };


  const formatLanguages = (
    languages,
    fallback = "-"
  ) => {

    if (
      !Array.isArray(
        languages
      ) ||
      languages.length === 0
    ) {

      return fallback;
    }


    return languages
      .map(
        getLanguageLabel
      )
      .join(", ");
  };


  const getSourceLanguage = (
    sourceVersion
  ) => {

    return formatLanguages(
      sourceVersion?.detectedLanguages,
      "분석 실행 시 자동 감지"
    );
  };


  const getAnalysisLanguage = (
    analysis,
    sourceVersion
  ) => {

    if (
      analysis?.analysisLanguages
        ?.length > 0
    ) {

      return formatLanguages(
        analysis.analysisLanguages
      );
    }


    if (
      sourceVersion?.detectedLanguages
        ?.length > 0
    ) {

      return formatLanguages(
        sourceVersion.detectedLanguages
      );
    }


    if (
      analysis?.status ===
      "pending"
    ) {

      return "자동 감지 예정";
    }


    if (
      analysis?.status ===
      "running"
    ) {

      return "자동 감지 중";
    }


    return "-";
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


      case "running":

        return "분석 진행 중";


      case "completed":

        return "분석 완료";


      case "failed":

        return "분석 실패";


      default:

        return "-";
    }
  };


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
     Severity
  ======================================== */

  const getSeverityText = (
    severity
  ) => {

    switch (
      severity
    ) {

      case "critical":

        return "Critical";


      case "high":

        return "High";


      case "medium":

        return "Medium";


      case "low":

        return "Low";


      default:

        return "-";
    }
  };


  /* ========================================
     Confidence
  ======================================== */

  const getConfidenceText = (
    confidence
  ) => {

    switch (
      confidence
    ) {

      case "high":

        return "High";


      case "medium":

        return "Medium";


      case "low":

        return "Low";


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


    setSelectedVulnerability(
      null
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
                          분석 언어
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
                            현재 분석 작업이 처리 중이므로 분석 대상을 변경할 수 없습니다.
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
                          분석 언어
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
                                    getAnalysisLanguage(
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
                    getAnalysisLanguage(
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


                  <div className="vulnerability-card">


                    <div className="vulnerability-card-header">

                      <h4>
                        취약점 상세 정보
                      </h4>

                      <span>
                        {selectedVulnerabilities.length}건
                      </span>

                    </div>


                    {
                      selectedVulnerabilities.length > 0
                        ? (

                          <div className="vulnerability-table-wrapper">


                            <table className="vulnerability-table">


                              <thead>

                                <tr>

                                  <th>
                                    심각도
                                  </th>

                                  <th>
                                    취약점
                                  </th>

                                  <th>
                                    파일 위치
                                  </th>

                                  <th>
                                    신뢰도
                                  </th>

                                  <th>
                                    상세
                                  </th>

                                </tr>

                              </thead>


                              <tbody>


                                {
                                  selectedVulnerabilities.map(
                                    (vulnerability) => (

                                      <tr
                                        key={
                                          vulnerability.id
                                        }
                                      >


                                        <td>

                                          <span
                                            className={
                                              `vulnerability-severity ${vulnerability.severity}`
                                            }
                                          >

                                            {
                                              getSeverityText(
                                                vulnerability.severity
                                              )
                                            }

                                          </span>

                                        </td>


                                        <td>

                                          {
                                            vulnerability.name
                                          }

                                        </td>


                                        <td className="vulnerability-file">

                                          {
                                            vulnerability.filePath
                                          }

                                          {
                                            vulnerability.line
                                              ? `:${vulnerability.line}`
                                              : ""
                                          }

                                        </td>


                                        <td>

                                          {
                                            getConfidenceText(
                                              vulnerability.confidence
                                            )
                                          }

                                        </td>


                                        <td>

                                          <button
                                            className="vulnerability-detail-button"

                                            onClick={() =>
                                              setSelectedVulnerability(
                                                vulnerability
                                              )
                                            }
                                          >
                                            상세
                                          </button>

                                        </td>


                                      </tr>

                                    )
                                  )
                                }


                              </tbody>


                            </table>


                          </div>

                        )
                        : (

                          <div className="analysis-message-box">

                            탐지된 취약점이 없습니다.

                          </div>

                        )
                    }


                  </div>


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
                "running" && (

                <div className="analysis-progress-box">

                  <div className="analysis-progress-spinner" />

                  <h4>
                    분석이 진행 중입니다.
                  </h4>

                  <p>
                    분석이 완료되면 취약점 결과를 확인할 수 있습니다.
                  </p>

                </div>

              )
            }


            {
              selectedAnalysis.status ===
                "pending" && (

                <div className="analysis-progress-box">

                  <h4>
                    분석 작업이 대기 중입니다.
                  </h4>

                  <p>
                    분석 작업이 시작되면 분석 진행 상태로 변경됩니다.
                  </p>

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
                          "분석 대기 또는 진행 중인 작업이 있어 현재 프로젝트를 삭제할 수 없습니다."
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


                <div className="current-file-info">
                  ※ 분석 언어는 실제 소스코드에서 자동으로 감지됩니다.
                </div>


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
                    분석 언어
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


      {/* ===================================
          Vulnerability Modal
      =================================== */}

      {
        selectedVulnerability && (

          <div className="modal-overlay">


            <div className="vulnerability-modal">


              <div className="vulnerability-modal-header">


                <div>

                  <span
                    className={
                      `vulnerability-severity ${selectedVulnerability.severity}`
                    }
                  >

                    {
                      getSeverityText(
                        selectedVulnerability.severity
                      )
                    }

                  </span>


                  <h3>
                    {selectedVulnerability.name}
                  </h3>

                </div>


                <button
                  className="modal-close-button"

                  onClick={() =>
                    setSelectedVulnerability(
                      null
                    )
                  }
                >
                  ×
                </button>


              </div>


              <div className="vulnerability-detail-grid">


                <div>

                  <span>
                    Rule ID
                  </span>

                  <strong>

                    {
                      selectedVulnerability.ruleId ||
                      "-"
                    }

                  </strong>

                </div>


                <div>

                  <span>
                    심각도
                  </span>

                  <strong>

                    {
                      getSeverityText(
                        selectedVulnerability.severity
                      )
                    }

                  </strong>

                </div>


                <div>

                  <span>
                    신뢰도
                  </span>

                  <strong>

                    {
                      getConfidenceText(
                        selectedVulnerability.confidence
                      )
                    }

                  </strong>

                </div>


                <div>

                  <span>
                    분석 언어
                  </span>

                  <strong>

                    {
                      getLanguageLabel(
                        selectedVulnerability.analysisLanguage
                      )
                    }

                  </strong>

                </div>


                <div>

                  <span>
                    파일 위치
                  </span>

                  <strong>

                    {
                      selectedVulnerability.filePath ||
                      "-"
                    }

                    {
                      selectedVulnerability.line
                        ? `:${selectedVulnerability.line}`
                        : ""
                    }

                  </strong>

                </div>


              </div>


              <div className="vulnerability-detail-section">

                <h4>
                  메시지
                </h4>

                <p>

                  {
                    selectedVulnerability.message ||
                    "-"
                  }

                </p>

              </div>


              <div className="vulnerability-detail-section">

                <h4>
                  탐지 근거
                </h4>

                <pre>

                  {
                    selectedVulnerability.evidence ||
                    "-"
                  }

                </pre>

              </div>


              <div className="vulnerability-detail-section">

                <h4>
                  조치 권고
                </h4>

                <p>

                  {
                    selectedVulnerability.recommendation ||
                    "-"
                  }

                </p>

              </div>


            </div>


          </div>

        )
      }


    </div>

  );
}


export default ProjectDetail;