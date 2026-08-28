import { useState } from "react";

import { useAuth } from "../../../auth/useAuth";

import "./ProjectDetail.css";


function ProjectDetail({
  project,
  users = [],
  onBack,
  onEdit,
  onRunAnalysis,
  onGrantUserAccess,
  onRevokeUserAccess,
}) {

  const {
    user,
  } = useAuth();


  /* ========================================
     분석 실행 Modal
  ======================================== */

  const [
    showAnalysisModal,
    setShowAnalysisModal,
  ] = useState(false);


  /* ========================================
     사용자 할당 Modal
  ======================================== */

  const [
    showUserModal,
    setShowUserModal,
  ] = useState(false);


  /* ========================================
     사용자 검색
  ======================================== */

  const [
    userSearch,
    setUserSearch,
  ] = useState("");


  /* ========================================
     취약점 상세
  ======================================== */

  const [
    selectedVulnerability,
    setSelectedVulnerability,
  ] = useState(null);


  /* ========================================
     관리자 여부
  ======================================== */

  const isAdmin =
    user?.role === "admin";


  /* ========================================
     프로젝트 상태 문자열
  ======================================== */

  const getStatusText = (
    status
  ) => {

    switch (status) {

      case "pending":
        return "분석 전";

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
     Source Type 문자열
  ======================================== */

  const getSourceTypeText = (
    sourceType
  ) => {

    switch (sourceType) {

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

  const getSourceInfo = () => {

    switch (project.sourceType) {

      case "upload":

        return (
          project.sourceFileName ||
          "-"
        );


      case "repository":

        return (
          project.repositoryUrl ||
          "-"
        );


      case "internal":

        return (
          project.internalPath ||
          "-"
        );


      default:
        return "-";
    }
  };


  /* ========================================
     심각도 문자열
  ======================================== */

  const getSeverityText = (
    severity
  ) => {

    switch (severity) {

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
     신뢰도 문자열
  ======================================== */

  const getConfidenceText = (
    confidence
  ) => {

    switch (confidence) {

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
     접근 권한 관리 가능 여부

     관리자 +
     분석 완료 프로젝트에서만 가능
  ======================================== */

  const canManageAccess =
    isAdmin &&
    project.status === "completed";


  /* ========================================
     현재 프로젝트에 할당된 사용자
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


  /* ========================================
     할당 가능한 사용자

     일반 사용자
     +
     활성 상태
     +
     현재 미할당
  ======================================== */

  const availableUsers =
    canManageAccess
      ? users.filter(
          (targetUser) => {


            /* 관리자 제외 */

            if (
              targetUser.role !== "user"
            ) {
              return false;
            }


            /* 비활성 사용자 제외 */

            if (
              !targetUser.isActive
            ) {
              return false;
            }


            /* 이미 할당된 사용자 제외 */

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


            /* 검색어가 없으면 전체 표시 */

            if (!keyword) {
              return true;
            }


            return targetUser.username
              .toLowerCase()
              .includes(
                keyword
              );
          }
        )
      : [];


  /* ========================================
     최근 분석 정보
  ======================================== */

  const latestAnalysis =
    project.latestAnalysis ||
    null;


  const vulnerabilities =
    latestAnalysis
      ?.vulnerabilities ||
    [];


  const analysisSummary =
    latestAnalysis
      ?.summary || {

        total:
          vulnerabilities.length,

        critical:
          vulnerabilities.filter(
            (item) =>
              item.severity ===
              "critical"
          ).length,

        high:
          vulnerabilities.filter(
            (item) =>
              item.severity ===
              "high"
          ).length,

        medium:
          vulnerabilities.filter(
            (item) =>
              item.severity ===
              "medium"
          ).length,

        low:
          vulnerabilities.filter(
            (item) =>
              item.severity ===
              "low"
          ).length,
      };


  /* ========================================
     분석 실행 Modal 열기
  ======================================== */

  const handleAnalysis = () => {

    if (
      project.status !==
      "pending"
    ) {
      return;
    }


    setShowAnalysisModal(
      true
    );
  };


  /* ========================================
     분석 실행 Modal 닫기
  ======================================== */

  const handleAnalysisCancel = () => {

    setShowAnalysisModal(
      false
    );
  };


  /* ========================================
     분석 실행
  ======================================== */

  const handleAnalysisConfirm = () => {

    setShowAnalysisModal(
      false
    );


    if (
      onRunAnalysis
    ) {

      onRunAnalysis(
        project.id
      );
    }
  };


  /* ========================================
     사용자 할당 Modal 열기
  ======================================== */

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


  /* ========================================
     사용자 할당 Modal 닫기
  ======================================== */

  const handleCloseUserModal = () => {

    setUserSearch(
      ""
    );


    setShowUserModal(
      false
    );
  };


  /* ========================================
     사용자 접근 권한 추가
  ======================================== */

  const handleGrantAccess = (
    userId
  ) => {

    if (
      !canManageAccess
    ) {
      return;
    }


    if (
      onGrantUserAccess
    ) {

      onGrantUserAccess(
        project.id,
        userId
      );
    }
  };


  /* ========================================
     사용자 접근 권한 해제
  ======================================== */

  const handleRevokeAccess = (
    userId
  ) => {

    if (
      !canManageAccess
    ) {
      return;
    }


    if (
      onRevokeUserAccess
    ) {

      onRevokeUserAccess(
        project.id,
        userId
      );
    }
  };


  /* ========================================
     취약점 상세 열기
  ======================================== */

  const handleOpenVulnerability = (
    vulnerability
  ) => {

    setSelectedVulnerability(
      vulnerability
    );
  };


  /* ========================================
     취약점 상세 닫기
  ======================================== */

  const handleCloseVulnerability = () => {

    setSelectedVulnerability(
      null
    );
  };


  return (

    <div className="project-detail">


      {/* ===================================
          상단
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
            프로젝트 기본 정보와
            분석 상태를 확인할 수 있습니다.
          </p>

        </div>


      </div>


      {/* ===================================
          기본 정보
      =================================== */}

      <section className="project-detail-section">


        <div className="project-detail-section-header">

          <h3>
            기본 정보
          </h3>

        </div>


        <div className="project-detail-card">


          <div className="project-detail-row">

            <div className="detail-label">
              프로젝트 이름
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
              분석 언어
            </div>

            <div className="detail-value">
              {project.language}
            </div>

          </div>


          <div className="project-detail-row">

            <div className="detail-label">
              소스 유형
            </div>

            <div className="detail-value">

              {
                getSourceTypeText(
                  project.sourceType
                )
              }

            </div>

          </div>


          <div className="project-detail-row">

            <div className="detail-label">
              소스 정보
            </div>

            <div className="detail-value">

              {
                getSourceInfo()
              }

            </div>

          </div>


          <div className="project-detail-row">

            <div className="detail-label">
              등록 일시
            </div>

            <div className="detail-value">
              {project.createdAt}
            </div>

          </div>


          <div className="project-detail-row">

            <div className="detail-label">
              분석 상태
            </div>

            <div className="detail-value">

              <span
                className={
                  `project-status ${project.status}`
                }
              >

                {
                  getStatusText(
                    project.status
                  )
                }

              </span>

            </div>

          </div>


        </div>

      </section>


      {/* ===================================
          접근 사용자

          관리자 +
          분석 완료 프로젝트만 표시
      =================================== */}

      {
        canManageAccess && (

          <section className="project-detail-section">


            <div className="project-detail-section-header access-user-header">


              <div>

                <h3>

                  접근 사용자

                  <span>
                    {
                      ` (${assignedUsers.length})`
                    }
                  </span>

                </h3>


                <p>
                  완료된 분석 결과를
                  조회할 수 있는 사용자를 관리합니다.
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
                  ? (

                    <div className="project-access-list">


                      {
                        assignedUsers.map(
                          (
                            assignedUser
                          ) => (

                            <div
                              className="project-access-item"

                              key={
                                assignedUser.id
                              }
                            >


                              <div className="project-access-user-info">


                                <span className="project-access-username">

                                  {
                                    assignedUser.username
                                  }

                                </span>


                                <span className="project-access-role">
                                  일반 사용자
                                </span>


                                <span
                                  className={
                                    assignedUser.isActive
                                      ? "project-access-status active"
                                      : "project-access-status inactive"
                                  }
                                >

                                  {
                                    assignedUser.isActive
                                      ? "활성"
                                      : "비활성"
                                  }

                                </span>


                              </div>


                              <button
                                className="access-revoke-button"

                                onClick={() =>
                                  handleRevokeAccess(
                                    assignedUser.id
                                  )
                                }
                              >
                                권한 해제
                              </button>


                            </div>

                          )
                        )
                      }


                    </div>

                  )
                  : (

                    <div className="project-access-empty">

                      현재 분석 결과를
                      조회할 수 있도록
                      할당된 사용자가 없습니다.

                    </div>

                  )
              }


            </div>


          </section>

        )
      }


      {/* ===================================
          분석 진행 중
      =================================== */}

      {
        project.status ===
          "running" && (

          <section className="analysis-running-info">

            <h2>
              분석이 진행 중입니다.
            </h2>


            <p>
              분석이 완료될 때까지
              프로젝트 정보를
              수정할 수 없습니다.
            </p>

          </section>

        )
      }


      {/* ===================================
          분석 완료 결과

          관리자 / 권한 있는 일반 사용자
          공통으로 사용할 영역
      =================================== */}

      {
        project.status ===
          "completed" && (

          <section className="analysis-result-section">


            <div className="analysis-result-header">

              <div>

                <h3>
                  취약점 분석 결과
                </h3>


                <p>
                  가장 최근 정적 분석에서
                  탐지된 취약점입니다.
                </p>

              </div>


              {
                latestAnalysis && (

                  <div className="analysis-result-meta">

                    <span>
                      분석 엔진
                    </span>

                    <strong>
                      {
                        latestAnalysis.engine ||
                        "-"
                      }
                    </strong>

                  </div>

                )
              }


            </div>


            {/* =================================
                분석 결과 요약
            ================================= */}

            <div className="analysis-summary-grid">


              <div className="analysis-summary-card total">

                <span>
                  전체
                </span>

                <strong>
                  {
                    analysisSummary.total
                  }
                </strong>

              </div>


              <div className="analysis-summary-card critical">

                <span>
                  Critical
                </span>

                <strong>
                  {
                    analysisSummary.critical
                  }
                </strong>

              </div>


              <div className="analysis-summary-card high">

                <span>
                  High
                </span>

                <strong>
                  {
                    analysisSummary.high
                  }
                </strong>

              </div>


              <div className="analysis-summary-card medium">

                <span>
                  Medium
                </span>

                <strong>
                  {
                    analysisSummary.medium
                  }
                </strong>

              </div>


              <div className="analysis-summary-card low">

                <span>
                  Low
                </span>

                <strong>
                  {
                    analysisSummary.low
                  }
                </strong>

              </div>


            </div>


            {/* =================================
                분석 실행 정보
            ================================= */}

            {
              latestAnalysis && (

                <div className="analysis-execution-info">


                  <div>

                    <span>
                      분석 시작
                    </span>

                    <strong>
                      {
                        latestAnalysis.startedAt ||
                        "-"
                      }
                    </strong>

                  </div>


                  <div>

                    <span>
                      분석 완료
                    </span>

                    <strong>
                      {
                        latestAnalysis.completedAt ||
                        "-"
                      }
                    </strong>

                  </div>


                </div>

              )
            }


            {/* =================================
                취약점 목록
            ================================= */}

            <div className="vulnerability-list-card">


              <div className="vulnerability-list-header">

                <h4>
                  취약점 목록
                </h4>


                <span>
                  {
                    `${vulnerabilities.length}건`
                  }
                </span>

              </div>


              {
                vulnerabilities.length > 0
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

                          </tr>

                        </thead>


                        <tbody>


                          {
                            vulnerabilities.map(
                              (
                                vulnerability
                              ) => (

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

                                    <button
                                      className="vulnerability-name-button"

                                      onClick={() =>
                                        handleOpenVulnerability(
                                          vulnerability
                                        )
                                      }
                                    >

                                      {
                                        vulnerability.name
                                      }

                                    </button>

                                  </td>


                                  <td>

                                    <span className="vulnerability-file">

                                      {
                                        vulnerability.filePath
                                      }

                                      {
                                        vulnerability.line
                                          ? `:${vulnerability.line}`
                                          : ""
                                      }

                                    </span>

                                  </td>


                                  <td>

                                    {
                                      getConfidenceText(
                                        vulnerability.confidence
                                      )
                                    }

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

                    <div className="vulnerability-empty">

                      탐지된 취약점이 없습니다.

                    </div>

                  )
              }


            </div>


          </section>

        )
      }


      {/* ===================================
          분석 실패

          관리자만 오류 정보 조회
      =================================== */}

      {
        isAdmin &&
        project.status ===
          "failed" && (

          <section className="analysis-error-section">


            <div className="error-card">

              <h2>
                실패 원인
              </h2>


              <p>

                {
                  project.failureReason ||
                  "실패 원인 정보가 없습니다."
                }

              </p>

            </div>


            <div className="log-card">

              <h2>
                분석 로그
              </h2>


              <pre>

                {
                  project.logs ||
                  "분석 로그가 없습니다."
                }

              </pre>

            </div>


          </section>

        )
      }


      {/* ===================================
          프로젝트 작업

          pending + 관리자만
      =================================== */}

      {
        isAdmin &&
        project.status ===
          "pending" && (

          <div className="project-detail-actions">


            <button
              className="edit-button"

              onClick={
                onEdit
              }
            >
              수정
            </button>


            <button
              className="analysis-button"

              onClick={
                handleAnalysis
              }
            >
              분석 실행
            </button>


          </div>

        )
      }


      {/* ===================================
          분석 실행 Modal
      =================================== */}

      {
        showAnalysisModal && (

          <div className="analysis-modal-overlay">


            <div className="analysis-modal">


              <div className="analysis-modal-header">

                <h2>
                  분석 실행
                </h2>

              </div>


              <div className="analysis-modal-content">


                <p className="analysis-modal-message">

                  <strong>
                    {project.name}
                  </strong>

                  프로젝트의 정적 분석을
                  실행하시겠습니까?

                </p>


                <div className="analysis-target-info">


                  <div className="analysis-target-row">

                    <span className="analysis-target-label">
                      분석 언어
                    </span>

                    <span className="analysis-target-value">
                      {project.language}
                    </span>

                  </div>


                  <div className="analysis-target-row">

                    <span className="analysis-target-label">
                      소스 유형
                    </span>

                    <span className="analysis-target-value">

                      {
                        getSourceTypeText(
                          project.sourceType
                        )
                      }

                    </span>

                  </div>


                  <div className="analysis-target-row">

                    <span className="analysis-target-label">
                      분석 대상
                    </span>

                    <span className="analysis-target-value">

                      {
                        getSourceInfo()
                      }

                    </span>

                  </div>


                </div>


                <p className="analysis-modal-notice">

                  분석이 진행되는 동안에는
                  프로젝트 정보를 수정할 수 없습니다.

                </p>


              </div>


              <div className="analysis-modal-actions">


                <button
                  className="analysis-modal-cancel-button"

                  onClick={
                    handleAnalysisCancel
                  }
                >
                  취소
                </button>


                <button
                  className="analysis-modal-confirm-button"

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
          사용자 할당 Modal

          completed에서만 열릴 수 있음
      =================================== */}

      {
        showUserModal &&
        canManageAccess && (

          <div className="user-assign-modal-overlay">


            <div className="user-assign-modal">


              <div className="user-assign-modal-header">

                <h2>
                  사용자 할당
                </h2>


                <p>

                  <strong>
                    {project.name}
                  </strong>

                  의 분석 결과를
                  조회할 사용자를 선택합니다.

                </p>

              </div>


              <div className="user-assign-search">

                <input
                  type="text"

                  value={
                    userSearch
                  }

                  placeholder="사용자 아이디 검색"

                  autoFocus

                  onChange={
                    (event) =>
                      setUserSearch(
                        event.target.value
                      )
                  }
                />

              </div>


              <div className="user-assign-results">


                {
                  availableUsers.length > 0
                    ? (

                      availableUsers.map(
                        (
                          availableUser
                        ) => (

                          <div
                            className="user-assign-result-item"

                            key={
                              availableUser.id
                            }
                          >


                            <div className="user-assign-user-info">


                              <span className="user-assign-username">

                                {
                                  availableUser.username
                                }

                              </span>


                              <span className="user-assign-role">
                                일반 사용자
                              </span>


                              <span className="user-assign-status">
                                활성
                              </span>


                            </div>


                            <button
                              className="user-assign-add-button"

                              onClick={() =>
                                handleGrantAccess(
                                  availableUser.id
                                )
                              }
                            >
                              추가
                            </button>


                          </div>

                        )
                      )

                    )
                    : (

                      <div className="user-assign-message">

                        할당 가능한 사용자가
                        없습니다.

                      </div>

                    )
                }


              </div>


              <div className="user-assign-modal-actions">

                <button
                  className="user-assign-close-button"

                  onClick={
                    handleCloseUserModal
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
          취약점 상세 Modal
      =================================== */}

      {
        selectedVulnerability && (

          <div className="vulnerability-modal-overlay">


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


                  <h2>

                    {
                      selectedVulnerability.name
                    }

                  </h2>

                </div>


                <button
                  className="vulnerability-modal-close"

                  onClick={
                    handleCloseVulnerability
                  }
                >
                  ×
                </button>


              </div>


              <div className="vulnerability-detail-grid">


                <div className="vulnerability-detail-row">

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


                <div className="vulnerability-detail-row">

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


                <div className="vulnerability-detail-row">

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


                <div className="vulnerability-detail-row">

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

                <h3>
                  메시지
                </h3>


                <p>

                  {
                    selectedVulnerability.message ||
                    "-"
                  }

                </p>

              </div>


              <div className="vulnerability-detail-section">

                <h3>
                  탐지 근거
                </h3>


                <pre>

                  {
                    selectedVulnerability.evidence ||
                    "-"
                  }

                </pre>

              </div>


              <div className="vulnerability-detail-section">

                <h3>
                  조치 권고
                </h3>


                <p>

                  {
                    selectedVulnerability.recommendation ||
                    "-"
                  }

                </p>

              </div>


              <div className="vulnerability-modal-actions">

                <button
                  onClick={
                    handleCloseVulnerability
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