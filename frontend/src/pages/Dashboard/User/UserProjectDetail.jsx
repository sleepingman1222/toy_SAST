import {
  useEffect,
  useState,
} from "react";

import "./UserProjectDetail.css";


const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};


const VULNERABILITY_PAGE_SIZE = 10;


function UserProjectDetail({
  project,
  onBack,
}) {

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


  const [
    severitySortDescending,
    setSeveritySortDescending,
  ] = useState(false);


  const [
    vulnerabilityPage,
    setVulnerabilityPage,
  ] = useState(1);


  /* ========================================
     SourceVersion
  ======================================== */

  const sourceVersions =
    project.sourceVersions ||
    [];


  /* ========================================
     완료된 분석 이력

     일반 사용자는 completed만 표시

     최신
     ↓
     과거
  ======================================== */

  const completedAnalysisHistory =
    [
      ...(
        project.analysisHistory ||
        []
      ),
    ]
      .filter(
        (analysis) =>
          analysis.status ===
          "completed"
      )
      .sort(
        (a, b) =>
          b.sequence -
          a.sequence
      );


  /* ========================================
     프로젝트 변경 시 선택 초기화
  ======================================== */

  useEffect(() => {

    setSelectedAnalysisId(
      null
    );

    setSelectedVulnerability(
      null
    );

    setSeveritySortDescending(
      false
    );

    setVulnerabilityPage(
      1
    );

  }, [
    project.id,
  ]);


  /* ========================================
     SourceVersion 찾기
  ======================================== */

  const getSourceVersionById =
    (sourceVersionId) => {

      return (
        sourceVersions.find(
          (sourceVersion) =>
            sourceVersion.id ===
            sourceVersionId
        ) ||
        null
      );
    };


  /* ========================================
     선택 Analysis
  ======================================== */

  const selectedAnalysis =
    completedAnalysisHistory.find(
      (analysis) =>
        analysis.id ===
        selectedAnalysisId
    ) ||
    null;


  const selectedSourceVersion =
    selectedAnalysis
      ? getSourceVersionById(
          selectedAnalysis
            .sourceVersionId
        )
      : null;


  /* ========================================
     Language

     완료 분석 화면에서는
     AnalysisRun.analysisLanguages Snapshot을
     가장 먼저 사용한다.

     SourceVersion.detectedLanguages는
     보조값으로 사용하고,

     기존 단일 language / analysisLanguage는
     과거 데이터 호환용 fallback으로만 사용한다.
  ======================================== */

  const getLanguageLabel =
    (language) => {

      switch (
        (
          language ||
          ""
        ).toLowerCase()
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


  const formatLanguages =
    (
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


  const getAnalysisLanguageText =
    (
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
        sourceVersion?.language
      ) {

        return getLanguageLabel(
          sourceVersion.language
        );
      }


      if (
        analysis?.analysisLanguage
      ) {

        return getLanguageLabel(
          analysis.analysisLanguage
        );
      }


      return "-";
    };


  /* ========================================
     Analysis Result Count
  ======================================== */

  const getAnalysisResultCount =
    (analysis) => {

      if (!analysis) {
        return 0;
      }


      return (
        analysis.summary?.total ??
        analysis.vulnerabilities
          ?.length ??
        0
      );
    };


  /* ========================================
     Severity
  ======================================== */

  const getSeverityText =
    (severity) => {

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

  const getConfidenceText =
    (confidence) => {

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
     KISA 기준
  ======================================== */

  const getSecurityWeaknessIdentifier =
    (vulnerability) => {

      const identifier =
        vulnerability
          ?.securityWeaknessIdentifier ||
        vulnerability
          ?.security_weakness_identifier ||
        "";


      if (identifier) {

        return identifier;
      }


      const itemNumber =
        vulnerability
          ?.securityWeaknessItemNumber ??
        vulnerability
          ?.security_weakness_item_number ??
        null;


      if (
        itemNumber !== null
      ) {

        return (
          `KISA-SW-${String(
            itemNumber
          ).padStart(
            2,
            "0"
          )}`
        );
      }


      return "-";
    };


  const getVulnerabilityDisplayName =
    (vulnerability) => {

      const identifier =
        getSecurityWeaknessIdentifier(
          vulnerability
        );


      const name =
        vulnerability
          ?.name ||
        "-";


      return (
        identifier !== "-"
          ? `${identifier} · ${name}`
          : name
      );
    };


  /* ========================================
     파일 위치

     start / end 위치 정보가 있으면
     가능한 범위까지 표시
  ======================================== */

  const getFileLocation =
    (vulnerability) => {

      const filePath =
        vulnerability.filePath ||
        "-";


      const startLine =
        vulnerability.startLine ??
        vulnerability.line ??
        null;


      const startColumn =
        vulnerability.startColumn ??
        null;


      const endLine =
        vulnerability.endLine ??
        null;


      const endColumn =
        vulnerability.endColumn ??
        null;


      if (
        startLine === null
      ) {

        return filePath;
      }


      let location =
        `${filePath}:${startLine}`;


      if (
        startColumn !== null
      ) {

        location +=
          `:${startColumn}`;
      }


      if (
        endLine !== null
      ) {

        location +=
          ` ~ ${endLine}`;


        if (
          endColumn !== null
        ) {

          location +=
            `:${endColumn}`;
        }
      }


      return location;
    };


  /* ========================================
     Selected Vulnerabilities
  ======================================== */

  const selectedVulnerabilities =
    selectedAnalysis
      ?.vulnerabilities ||
    [];


  const displayedVulnerabilities =
    severitySortDescending
      ? [
          ...selectedVulnerabilities,
        ].sort(
          (a, b) => {

            const aSeverity =
              String(
                a.severity ||
                ""
              ).toLowerCase();

            const bSeverity =
              String(
                b.severity ||
                ""
              ).toLowerCase();


            return (
              (
                SEVERITY_RANK[
                  bSeverity
                ] ||
                0
              ) -
              (
                SEVERITY_RANK[
                  aSeverity
                ] ||
                0
              )
            );
          }
        )
      : selectedVulnerabilities;


  const vulnerabilityTotalPages =
    Math.max(
      1,
      Math.ceil(
        displayedVulnerabilities.length /
        VULNERABILITY_PAGE_SIZE
      )
    );


  const safeVulnerabilityPage =
    Math.min(
      vulnerabilityPage,
      vulnerabilityTotalPages
    );


  const vulnerabilityPageStart =
    (
      safeVulnerabilityPage -
      1
    ) *
    VULNERABILITY_PAGE_SIZE;


  const paginatedVulnerabilities =
    displayedVulnerabilities.slice(
      vulnerabilityPageStart,
      vulnerabilityPageStart +
        VULNERABILITY_PAGE_SIZE
    );


  /* ========================================
     Analysis Summary

     summary가 없으면 vulnerabilities 기준 계산
  ======================================== */

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


  useEffect(() => {

    setVulnerabilityPage(
      1
    );

  }, [
    selectedAnalysisId,
    severitySortDescending,
  ]);


  /* ========================================
     Analysis 선택
  ======================================== */

  const handleViewAnalysis =
    (analysisId) => {

      setSelectedAnalysisId(
        analysisId
      );

      setSelectedVulnerability(
        null
      );
    };


  /* ========================================
     Render
  ======================================== */

  return (

    <div className="user-project-detail">


      {/* ===================================
          Header
      =================================== */}

      <div className="user-project-detail-header">

        <button
          type="button"

          className="user-project-detail-back-button"

          onClick={
            onBack
          }
        >
          ← 목록으로
        </button>


        <div>

          <h2>
            프로젝트 상세 정보
          </h2>

          <p>
            프로젝트 정보와 완료된 정적 분석 결과를 조회합니다.
          </p>

        </div>

      </div>


      {/* ===================================
          Project Information
      =================================== */}

      <section className="user-project-detail-section">

        <div className="user-project-detail-section-header">

          <div>

            <h3>
              프로젝트 기본 정보
            </h3>

            <p>
              할당된 프로젝트의 기본 정보를 확인합니다.
            </p>

          </div>

        </div>


        <div className="user-project-info-card">


          <div className="user-project-info-row">

            <span>
              프로젝트명
            </span>

            <strong>
              {
                project.name ||
                "-"
              }
            </strong>

          </div>


          <div className="user-project-info-row">

            <span>
              설명
            </span>

            <strong>
              {
                project.description ||
                "-"
              }
            </strong>

          </div>


          <div className="user-project-info-row">

            <span>
              등록자
            </span>

            <strong>
              {
                project.createdByUsername ||
                "-"
              }
            </strong>

          </div>


          <div className="user-project-info-row">

            <span>
              등록 일시
            </span>

            <strong>
              {
                project.createdAt ||
                "-"
              }
            </strong>

          </div>


        </div>

      </section>


      {/* ===================================
          Analysis History
      =================================== */}

      <section className="user-project-detail-section">

        <div className="user-project-detail-section-header">

          <div>

            <h3>
              분석 이력
            </h3>

            <p>
              완료된 정적 분석 결과만 조회할 수 있습니다.
            </p>

          </div>


          <span className="user-analysis-history-count">

            {
              completedAnalysisHistory.length
            }건

          </span>

        </div>


        {
          completedAnalysisHistory.length > 0
            ? (

              <div className="user-analysis-history-card">

                <div className="user-analysis-history-table-wrapper">

                  <table className="user-analysis-history-table">

                    <thead>

                      <tr>

                        <th>
                          소스 버전
                        </th>

                        <th>
                          언어
                        </th>

                        <th>
                          완료 일시
                        </th>

                        <th>
                          진단 결과
                        </th>

                        <th>
                          조회
                        </th>

                      </tr>

                    </thead>


                    <tbody>

                      {
                        completedAnalysisHistory.map(
                          (analysis) => {

                            const sourceVersion =
                              getSourceVersionById(
                                analysis.sourceVersionId
                              );


                            const isSelected =
                              analysis.id ===
                              selectedAnalysisId;


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
                                  {
                                    analysis.completedAt ||
                                    "-"
                                  }
                                </td>


                                <td>

                                  <strong className="user-analysis-result-count">
                                    {
                                      getAnalysisResultCount(
                                        analysis
                                      )
                                    }건
                                  </strong>

                                </td>


                                <td>

                                  <button
                                    type="button"

                                    className="user-analysis-view-button"

                                    onClick={() =>
                                      handleViewAnalysis(
                                        analysis.id
                                      )
                                    }
                                  >
                                    {
                                      isSelected
                                        ? "조회 중"
                                        : "조회"
                                    }
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

              <div className="user-analysis-history-empty">
                조회 가능한 완료 분석 결과가 없습니다.
              </div>

            )
        }

      </section>


      {/* ===================================
          Analysis Result
      =================================== */}

      {
        selectedAnalysis && (

          <section className="user-project-detail-section">


            {/* ===============================
                Analysis Header
            =============================== */}

            <div className="user-analysis-detail-header">

              <div>

                <h3>
                  분석 결과
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


              <span className="user-analysis-completed-badge">
                분석 완료
              </span>

            </div>


            {/* ===============================
                Summary
            =============================== */}

            <div className="user-analysis-summary-grid">


              <div className="user-analysis-summary-card">

                <span>
                  전체
                </span>

                <strong>
                  {
                    analysisSummary.total ??
                    0
                  }
                </strong>

              </div>


              <div className="user-analysis-summary-card critical">

                <span>
                  Critical
                </span>

                <strong>
                  {
                    analysisSummary.critical ??
                    0
                  }
                </strong>

              </div>


              <div className="user-analysis-summary-card high">

                <span>
                  High
                </span>

                <strong>
                  {
                    analysisSummary.high ??
                    0
                  }
                </strong>

              </div>


              <div className="user-analysis-summary-card medium">

                <span>
                  Medium
                </span>

                <strong>
                  {
                    analysisSummary.medium ??
                    0
                  }
                </strong>

              </div>


              <div className="user-analysis-summary-card low">

                <span>
                  Low
                </span>

                <strong>
                  {
                    analysisSummary.low ??
                    0
                  }
                </strong>

              </div>


            </div>


            {/* ===============================
                Vulnerability
            =============================== */}

            <div className="user-vulnerability-card">

              <div className="user-vulnerability-card-header">

                <div>

                  <h4>
                    취약점 상세 정보
                  </h4>

                  <p>
                    분석에서 탐지된 취약점의 위치와 진단 정보를 확인합니다.
                  </p>

                </div>


                <span>
                  {
                    selectedVulnerabilities.length
                  }건
                </span>

              </div>


              {
                selectedVulnerabilities.length > 0
                  ? (

                    <div className="user-vulnerability-table-wrapper">

                      <table className="user-vulnerability-table">

                        <thead>

                          <tr>

                            <th>

                              <button
                                type="button"

                                title="심각도 높은 순으로 정렬"

                                aria-pressed={
                                  severitySortDescending
                                }

                                onClick={() =>
                                  setSeveritySortDescending(
                                    true
                                  )
                                }

                                style={{
                                  padding: 0,
                                  color: "inherit",
                                  background: "none",
                                  border: "none",
                                  font: "inherit",
                                  fontWeight: "inherit",
                                  cursor: "pointer",
                                }}
                              >
                                심각도
                                {
                                  severitySortDescending
                                    ? " ↓"
                                    : ""
                                }
                              </button>

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
                            paginatedVulnerabilities.map(
                              (vulnerability) => (

                                <tr
                                  key={
                                    vulnerability.id
                                  }
                                >


                                  <td>

                                    <span
                                      className={
                                        `user-vulnerability-severity ${vulnerability.severity}`
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

                                    <strong className="user-vulnerability-name">
                                      {
                                        getVulnerabilityDisplayName(
                                          vulnerability
                                        )
                                      }
                                    </strong>

                                  </td>


                                  <td>

                                    <span className="user-vulnerability-location">
                                      {
                                        getFileLocation(
                                          vulnerability
                                        )
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


                                  <td>

                                    <button
                                      type="button"

                                      className="user-vulnerability-detail-button"

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


                      {
                        vulnerabilityTotalPages > 1 && (

                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              gap: "6px",
                              padding: "16px",
                              borderTop:
                                "1px solid #f0f1f3",
                            }}
                          >

                            <button
                              type="button"

                              disabled={
                                safeVulnerabilityPage <=
                                1
                              }

                              onClick={() =>
                                setVulnerabilityPage(
                                  (current) =>
                                    Math.max(
                                      1,
                                      current - 1
                                    )
                                )
                              }

                              style={{
                                padding: "6px 10px",
                                border:
                                  "1px solid #d1d5db",
                                borderRadius: "6px",
                                backgroundColor:
                                  "#ffffff",
                                cursor:
                                  safeVulnerabilityPage <= 1
                                    ? "not-allowed"
                                    : "pointer",
                                opacity:
                                  safeVulnerabilityPage <= 1
                                    ? 0.5
                                    : 1,
                              }}
                            >
                              이전
                            </button>


                            {
                              Array.from(
                                {
                                  length:
                                    vulnerabilityTotalPages,
                                },
                                (_, index) =>
                                  index + 1
                              ).map(
                                (pageNumber) => (

                                  <button
                                    key={
                                      pageNumber
                                    }

                                    type="button"

                                    onClick={() =>
                                      setVulnerabilityPage(
                                        pageNumber
                                      )
                                    }

                                    aria-current={
                                      pageNumber ===
                                      safeVulnerabilityPage
                                        ? "page"
                                        : undefined
                                    }

                                    style={{
                                      minWidth: "34px",
                                      padding: "6px 9px",
                                      color:
                                        pageNumber ===
                                        safeVulnerabilityPage
                                          ? "#ffffff"
                                          : "#374151",
                                      backgroundColor:
                                        pageNumber ===
                                        safeVulnerabilityPage
                                          ? "#2563eb"
                                          : "#ffffff",
                                      border:
                                        pageNumber ===
                                        safeVulnerabilityPage
                                          ? "1px solid #2563eb"
                                          : "1px solid #d1d5db",
                                      borderRadius: "6px",
                                      fontWeight: 600,
                                      cursor: "pointer",
                                    }}
                                  >
                                    {pageNumber}
                                  </button>

                                )
                              )
                            }


                            <button
                              type="button"

                              disabled={
                                safeVulnerabilityPage >=
                                vulnerabilityTotalPages
                              }

                              onClick={() =>
                                setVulnerabilityPage(
                                  (current) =>
                                    Math.min(
                                      vulnerabilityTotalPages,
                                      current + 1
                                    )
                                )
                              }

                              style={{
                                padding: "6px 10px",
                                border:
                                  "1px solid #d1d5db",
                                borderRadius: "6px",
                                backgroundColor:
                                  "#ffffff",
                                cursor:
                                  safeVulnerabilityPage >=
                                  vulnerabilityTotalPages
                                    ? "not-allowed"
                                    : "pointer",
                                opacity:
                                  safeVulnerabilityPage >=
                                  vulnerabilityTotalPages
                                    ? 0.5
                                    : 1,
                              }}
                            >
                              다음
                            </button>

                          </div>

                        )
                      }

                    </div>

                  )
                  : (

                    <div className="user-vulnerability-empty">

                      <strong>
                        탐지된 보안약점이 없습니다.
                      </strong>

                      <p>
                        해당 분석에서는 진단 결과가 발견되지 않았습니다.
                      </p>

                    </div>

                  )
              }

            </div>


          </section>

        )
      }


      {/* ===================================
          Vulnerability Modal
      =================================== */}

      {
        selectedVulnerability && (

          <div className="user-vulnerability-modal-overlay">

            <div className="user-vulnerability-modal">


              {/* =============================
                  Modal Header
              ============================= */}

              <div className="user-vulnerability-modal-header">

                <div>

                  <div className="user-vulnerability-modal-badges">

                    <span className="user-kisa-identifier">
                      {
                        getSecurityWeaknessIdentifier(
                          selectedVulnerability
                        )
                      }
                    </span>


                    <span
                      className={
                        `user-vulnerability-severity ${selectedVulnerability.severity}`
                      }
                    >
                      {
                        getSeverityText(
                          selectedVulnerability.severity
                        )
                      }
                    </span>

                  </div>


                  <h3>
                    {
                      getVulnerabilityDisplayName(
                        selectedVulnerability
                      )
                    }
                  </h3>

                </div>


                <button
                  type="button"

                  className="user-vulnerability-modal-close"

                  aria-label="닫기"

                  onClick={() =>
                    setSelectedVulnerability(
                      null
                    )
                  }
                >
                  ×
                </button>

              </div>


              {/* =============================
                  Detail Information
              ============================= */}

              <div className="user-vulnerability-detail-grid">


                <div>

                  <span>
                    KISA 기준
                  </span>

                  <strong>
                    {
                      getSecurityWeaknessIdentifier(
                        selectedVulnerability
                      )
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


                <div className="user-vulnerability-detail-location">

                  <span>
                    파일 위치
                  </span>

                  <strong>
                    {
                      getFileLocation(
                        selectedVulnerability
                      )
                    }
                  </strong>

                </div>


              </div>


              {/* =============================
                  Message
              ============================= */}

              <div className="user-vulnerability-detail-section">

                <h4>
                  진단 메시지
                </h4>

                <p>
                  {
                    selectedVulnerability.message ||
                    "-"
                  }
                </p>

              </div>


              {/* =============================
                  Evidence
              ============================= */}

              <div className="user-vulnerability-detail-section">

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


              {/* =============================
                  Recommendation
              ============================= */}

              <div className="user-vulnerability-detail-section">

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


              <div className="user-vulnerability-modal-footer">

                <button
                  type="button"

                  onClick={() =>
                    setSelectedVulnerability(
                      null
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


export default UserProjectDetail;