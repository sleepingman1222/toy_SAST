import {
  useEffect,
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import {
  getAdminSummary,
} from "../../../api/api";

import "./AdminSummary.css";


function AdminSummary() {

  const {
    accessToken,
    setAccessToken,
  } = useAuth();


  /* ========================================
     Summary Data
  ======================================== */

  const [
    summary,
    setSummary,
  ] = useState(null);


  const [
    loading,
    setLoading,
  ] = useState(true);


  const [
    error,
    setError,
  ] = useState("");


  /* ========================================
     관리자 요약 조회
  ======================================== */

  useEffect(() => {

    let cancelled = false;


    const loadSummary =
      async () => {

        try {

          setLoading(
            true
          );

          setError(
            ""
          );


          const data =
            await getAdminSummary(
              accessToken,
              setAccessToken
            );


          if (cancelled) {
            return;
          }


          setSummary(
            data
          );

        } catch (loadError) {

          if (cancelled) {
            return;
          }


          console.error(
            "관리자 요약 조회 실패:",
            loadError
          );


          setError(
            loadError.message ||
            "관리자 요약 정보를 불러오지 못했습니다."
          );

        } finally {

          if (!cancelled) {

            setLoading(
              false
            );
          }
        }
      };


    loadSummary();


    return () => {
      cancelled = true;
    };

  }, [
    accessToken,
    setAccessToken,
  ]);


  /* ========================================
     상태 표시
  ======================================== */

  const getStatusText = (
    analysisStatus
  ) => {

    switch (analysisStatus) {

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
     분석 결과 건수 표시
  ======================================== */

  const getResultText = (
    analysis
  ) => {

    if (
      analysis.status !==
      "completed"
    ) {
      return "-";
    }


    return (
      `${analysis.resultCount}건`
    );
  };


  /* ========================================
     Loading
  ======================================== */

  if (loading) {

    return (
      <div className="admin-summary">

        <div className="admin-summary-header">

          <h2>
            관리자 요약
          </h2>

          <p>
            시스템의 사용자, 프로젝트 및 분석 현황을 확인합니다.
          </p>

        </div>


        <div className="summary-state-card">
          관리자 요약 정보를 불러오는 중입니다.
        </div>

      </div>
    );
  }


  /* ========================================
     Error
  ======================================== */

  if (
    error ||
    !summary
  ) {

    return (
      <div className="admin-summary">

        <div className="admin-summary-header">

          <h2>
            관리자 요약
          </h2>

          <p>
            시스템의 사용자, 프로젝트 및 분석 현황을 확인합니다.
          </p>

        </div>


        <div className="summary-state-card error">
          {error || "관리자 요약 정보를 불러오지 못했습니다."}
        </div>

      </div>
    );
  }


  return (

    <div className="admin-summary">


      {/* ===================================
          Header
      =================================== */}

      <div className="admin-summary-header">

        <h2>
          관리자 요약
        </h2>

        <p>
          시스템의 사용자, 프로젝트 및 분석 현황을 확인합니다.
        </p>

      </div>


      {/* ===================================
          Main Summary
      =================================== */}

      <div className="summary-card-grid">


        <div className="summary-card">

          <span className="summary-card-label">
            전체 사용자
          </span>

          <strong className="summary-card-value">
            {summary.totalUsers}
          </strong>

        </div>


        <div className="summary-card">

          <span className="summary-card-label">
            활성 사용자
          </span>

          <strong className="summary-card-value">
            {summary.activeUsers}
          </strong>

        </div>


        <div className="summary-card">

          <span className="summary-card-label">
            전체 프로젝트
          </span>

          <strong className="summary-card-value">
            {summary.totalProjects}
          </strong>

        </div>


      </div>


      {/* ===================================
          Analysis Status
      =================================== */}

      <section className="summary-section">


        <div className="summary-section-header">

          <h3>
            현재 분석 상태
          </h3>

          <p>
            각 프로젝트의 현재 분석 대상에 대한 최신 분석 상태입니다.
          </p>

        </div>


        <div className="analysis-status-grid">


          <div className="analysis-status-card pending">

            <span>
              분석 대기
            </span>

            <strong>
              {summary.analysisStatus.pending}
            </strong>

          </div>


          <div className="analysis-status-card running">

            <span>
              분석 진행 중
            </span>

            <strong>
              {summary.analysisStatus.running}
            </strong>

          </div>


          <div className="analysis-status-card completed">

            <span>
              분석 완료
            </span>

            <strong>
              {summary.analysisStatus.completed}
            </strong>

          </div>


          <div className="analysis-status-card failed">

            <span>
              분석 실패
            </span>

            <strong>
              {summary.analysisStatus.failed}
            </strong>

          </div>


        </div>


      </section>


      {/* ===================================
          Recent Analyses
      =================================== */}

      <section className="summary-section">


        <div className="summary-section-header">

          <h3>
            최근 분석 이력
          </h3>

          <p>
            최근 실행된 분석 5건을 확인합니다.
          </p>

        </div>


        <div className="recent-analysis-card">

          {
            summary.recentAnalyses.length > 0
              ? (

                <div className="recent-analysis-table-wrapper">

                  <table className="recent-analysis-table">

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
                          결과
                        </th>

                        <th>
                          실행자
                        </th>

                        <th>
                          실행 일시
                        </th>

                      </tr>

                    </thead>


                    <tbody>

                      {
                        summary.recentAnalyses.map(
                          (analysis) => (

                            <tr
                              key={analysis.id}
                            >

                              <td>

                                <div className="recent-analysis-project">

                                  <strong>
                                    {analysis.projectName || "-"}
                                  </strong>

                                  <span>
                                    Analysis #{analysis.sequence}
                                  </span>

                                </div>

                              </td>


                              <td>

                                {
                                  analysis.sourceVersion
                                    ? `v${analysis.sourceVersion}`
                                    : "-"
                                }

                              </td>


                              <td>

                                <span
                                  className={
                                    `recent-analysis-status ${analysis.status}`
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
                                  getResultText(
                                    analysis
                                  )
                                }
                              </td>


                              <td>
                                {analysis.executedByUsername || "-"}
                              </td>


                              <td>
                                {
                                  analysis.startedAt ||
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

                <div className="recent-analysis-empty">
                  아직 실행된 분석이 없습니다.
                </div>

              )
          }

        </div>


      </section>


    </div>

  );
}


export default AdminSummary;