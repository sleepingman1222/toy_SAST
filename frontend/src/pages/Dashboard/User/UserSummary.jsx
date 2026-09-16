import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import {
  getProjectAnalysisRuns,
} from "../../../api/analysisApi";

import "./UserSummary.css";


function UserSummary({
  projects = [],
  projectsLoading = false,
  projectsError = "",
}) {

  const {
    accessToken,
    setAccessToken,
  } = useAuth();


  /* ========================================
     프로젝트별 완료 분석 이력
  ======================================== */

  const [
    analysisByProject,
    setAnalysisByProject,
  ] = useState({});


  const [
    analysesLoading,
    setAnalysesLoading,
  ] = useState(false);


  const [
    analysesError,
    setAnalysesError,
  ] = useState("");


  const projectIdsKey =
    projects
      .map(
        (project) =>
          project.id
      )
      .sort(
        (a, b) =>
          a - b
      )
      .join(",");


  /* ========================================
     일반 사용자 분석 이력 조회

     Backend 정책상 일반 사용자는
     completed AnalysisRun만 반환받는다.
  ======================================== */

  useEffect(() => {

    let cancelled = false;


    if (
      projectsLoading ||
      projectsError
    ) {

      setAnalysisByProject({});
      setAnalysesLoading(false);
      setAnalysesError("");

      return () => {
        cancelled = true;
      };
    }


    if (projects.length === 0) {

      setAnalysisByProject({});
      setAnalysesLoading(false);
      setAnalysesError("");

      return () => {
        cancelled = true;
      };
    }


    const loadAnalyses =
      async () => {

        setAnalysesLoading(
          true
        );

        setAnalysesError(
          ""
        );


        try {

          const results = [];


          for (
            const project
            of projects
          ) {

            const analyses =
              await getProjectAnalysisRuns(
                project.id,
                accessToken,
                setAccessToken
              );


            results.push([
              project.id,
              analyses,
            ]);
          }


          if (cancelled) {
            return;
          }


          setAnalysisByProject(
            Object.fromEntries(
              results
            )
          );

        } catch (error) {

          if (cancelled) {
            return;
          }


          console.error(
            "일반 사용자 분석 이력 조회 실패:",
            error
          );


          setAnalysisByProject({});


          setAnalysesError(
            error.message ||
            "분석 이력을 불러오지 못했습니다."
          );

        } finally {

          if (!cancelled) {

            setAnalysesLoading(
              false
            );
          }
        }
      };


    loadAnalyses();


    return () => {
      cancelled = true;
    };

  }, [
    projectIdsKey,
    projectsLoading,
    projectsError,
    accessToken,
    setAccessToken,
  ]);


  /* ========================================
     프로젝트별 분석 결과 평탄화
  ======================================== */

  const completedAnalyses =
    useMemo(
      () => {

        return projects
          .flatMap(
            (project) => {

              const analyses =
                analysisByProject[
                  project.id
                ] || [];


              return analyses.map(
                (analysis) => ({
                  ...analysis,
                  project,
                })
              );
            }
          )
          .filter(
            (analysis) =>
              analysis.status ===
              "completed"
          );
      },
      [
        projects,
        analysisByProject,
      ]
    );


  /* ========================================
     Summary 통계
  ======================================== */

  const assignedProjectCount =
    projects.length;


  const completedProjectCount =
    projects.filter(
      (project) =>
        (
          analysisByProject[
            project.id
          ] || []
        ).some(
          (analysis) =>
            analysis.status ===
            "completed"
        )
    ).length;


  const totalFindingCount =
    completedAnalyses.reduce(
      (total, analysis) => {

        const resultCount =
          analysis.summary?.total ??
          analysis.vulnerabilities?.length ??
          0;


        return (
          total + resultCount
        );
      },
      0
    );


  /* ========================================
     최근 완료 분석 5건
  ======================================== */

  const recentAnalyses =
    useMemo(
      () => {

        return [
          ...completedAnalyses,
        ]
          .sort(
            (a, b) => {

              const aDate =
                a.completedAt ||
                a.createdAt ||
                "";

              const bDate =
                b.completedAt ||
                b.createdAt ||
                "";


              return bDate.localeCompare(
                aDate
              );
            }
          )
          .slice(
            0,
            5
          );
      },
      [completedAnalyses]
    );


  /* ========================================
     SourceVersion 표시
  ======================================== */

  const getSourceVersionText =
    (analysis) => {

      const sourceVersion =
        (
          analysis.project
            ?.sourceVersions ||
          []
        ).find(
          (source) =>
            source.id ===
            analysis.sourceVersionId
        );


      if (!sourceVersion) {
        return "-";
      }


      return (
        `v${sourceVersion.version}`
      );
    };


  /* ========================================
     결과 건수
  ======================================== */

  const getResultCount =
    (analysis) => {

      return (
        analysis.summary?.total ??
        analysis.vulnerabilities?.length ??
        0
      );
    };


  /* ========================================
     Loading / Error
  ======================================== */

  const loading =
    projectsLoading ||
    analysesLoading;


  const error =
    projectsError ||
    analysesError;


  return (

    <div className="user-summary">


      {/* ===================================
          Header
      =================================== */}

      <div className="user-summary-header">

        <h2>
          사용자 요약
        </h2>

        <p>
          할당된 프로젝트와 완료된 분석 결과를 확인합니다.
        </p>

      </div>


      {/* ===================================
          Loading
      =================================== */}

      {
        loading && (

          <div className="user-summary-state-card">
            사용자 요약 정보를 불러오는 중입니다.
          </div>

        )
      }


      {/* ===================================
          Error
      =================================== */}

      {
        !loading &&
        error && (

          <div className="user-summary-state-card error">
            {error}
          </div>

        )
      }


      {/* ===================================
          Summary
      =================================== */}

      {
        !loading &&
        !error && (

          <>

            <div className="user-summary-card-grid">


              <div className="user-summary-card">

                <span className="user-summary-card-label">
                  할당 프로젝트
                </span>

                <strong className="user-summary-card-value">
                  {assignedProjectCount}
                </strong>

              </div>


              <div className="user-summary-card">

                <span className="user-summary-card-label">
                  분석 완료 프로젝트
                </span>

                <strong className="user-summary-card-value">
                  {completedProjectCount}
                </strong>

              </div>


              <div className="user-summary-card">

                <span className="user-summary-card-label">
                  발견된 진단 결과
                </span>

                <strong className="user-summary-card-value">
                  {totalFindingCount}
                </strong>

              </div>


            </div>


            {/* =============================
                Recent Analysis
            ============================= */}

            <section className="user-summary-section">

              <div className="user-summary-section-header">

                <h3>
                  최근 분석 결과
                </h3>

                <p>
                  할당된 프로젝트에서 최근 완료된 분석 5건을 확인합니다.
                </p>

              </div>


              <div className="user-recent-analysis-card">

                {
                  recentAnalyses.length > 0
                    ? (

                      <div className="user-recent-analysis-table-wrapper">

                        <table className="user-recent-analysis-table">

                          <thead>

                            <tr>

                              <th>
                                프로젝트
                              </th>

                              <th>
                                Source
                              </th>

                              <th>
                                상태
                              </th>

                              <th>
                                진단 결과
                              </th>

                              <th>
                                완료 일시
                              </th>

                            </tr>

                          </thead>


                          <tbody>

                            {
                              recentAnalyses.map(
                                (analysis) => (

                                  <tr
                                    key={
                                      analysis.id
                                    }
                                  >

                                    <td>

                                      <div className="user-recent-analysis-project">

                                        <strong>
                                          {
                                            analysis
                                              .project
                                              ?.name ||
                                            "-"
                                          }
                                        </strong>

                                        <span>
                                          Analysis #{analysis.sequence}
                                        </span>

                                      </div>

                                    </td>


                                    <td>
                                      {
                                        getSourceVersionText(
                                          analysis
                                        )
                                      }
                                    </td>


                                    <td>

                                      <span className="user-analysis-status completed">
                                        분석 완료
                                      </span>

                                    </td>


                                    <td>
                                      {
                                        getResultCount(
                                          analysis
                                        )
                                      }건
                                    </td>


                                    <td>
                                      {
                                        analysis.completedAt ||
                                        analysis.createdAt ||
                                        "-"
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

                      <div className="user-recent-analysis-empty">
                        아직 조회 가능한 완료 분석 결과가 없습니다.
                      </div>

                    )
                }

              </div>

            </section>

          </>

        )
      }


    </div>
  );
}


export default UserSummary;