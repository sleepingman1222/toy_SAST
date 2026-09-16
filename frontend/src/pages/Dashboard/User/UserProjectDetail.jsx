import {
  useEffect,
  useState,
} from "react";

import VulnerabilityPanel from "../../../components/Analysis/VulnerabilityPanel";

import "./UserProjectDetail.css";


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
     Selected Vulnerabilities
  ======================================== */

  const selectedVulnerabilities =
    selectedAnalysis
      ?.vulnerabilities ||
    [];


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


  /* ========================================
     Analysis 선택
  ======================================== */

  const handleViewAnalysis =
    (analysisId) => {

      setSelectedAnalysisId(
        analysisId
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

            <VulnerabilityPanel
              vulnerabilities={
                selectedVulnerabilities
              }
              resetKey={
                selectedAnalysisId
              }
              variant="user"
              getLanguageLabel={
                getLanguageLabel
              }
            />


          </section>

        )
      }





    </div>

  );
}


export default UserProjectDetail;