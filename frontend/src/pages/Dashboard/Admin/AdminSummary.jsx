import "./AdminSummary.css";


function AdminSummary({
  users = [],
  projects = [],
}) {

  /* ========================================
     사용자 통계
  ======================================== */

  const totalUsers =
    users.length;


  const activeUsers =
    users.filter(
      (user) =>
        user.isActive
    ).length;


  /* ========================================
     프로젝트 통계
  ======================================== */

  const totalProjects =
    projects.length;


  /* ========================================
     현재 SourceVersion 찾기
  ======================================== */

  const getCurrentSourceVersion = (
    project
  ) => {

    return (
      (
        project.sourceVersions ||
        []
      ).find(
        (sourceVersion) =>
          sourceVersion.id ===
          project.currentSourceVersionId
      ) || null
    );
  };


  /* ========================================
     현재 SourceVersion의
     최신 AnalysisRun 찾기
  ======================================== */

  const getLatestCurrentAnalysis = (
    project
  ) => {

    const currentSourceVersion =
      getCurrentSourceVersion(
        project
      );


    if (
      !currentSourceVersion
    ) {

      return null;
    }


    const currentAnalyses =
      (
        project.analysisHistory ||
        []
      )
        .filter(
          (analysis) =>
            analysis.sourceVersionId ===
            currentSourceVersion.id
        )
        .sort(
          (a, b) =>
            b.sequence -
            a.sequence
        );


    return (
      currentAnalyses[0] ||
      null
    );
  };


  /* ========================================
     AnalysisRun 상태별 프로젝트 수

     SourceVersion은 있지만
     AnalysisRun이 없는 프로젝트는
     아직 분석 실행 전이므로
     상태 통계에서 제외한다.
  ======================================== */

  const pendingProjects =
    projects.filter(
      (project) =>
        getLatestCurrentAnalysis(
          project
        )?.status ===
        "pending"
    ).length;


  const runningProjects =
    projects.filter(
      (project) =>
        getLatestCurrentAnalysis(
          project
        )?.status ===
        "running"
    ).length;


  const completedProjects =
    projects.filter(
      (project) =>
        getLatestCurrentAnalysis(
          project
        )?.status ===
        "completed"
    ).length;


  const failedProjects =
    projects.filter(
      (project) =>
        getLatestCurrentAnalysis(
          project
        )?.status ===
        "failed"
    ).length;


  /* ========================================
     전체 AnalysisRun 수
  ======================================== */

  const totalAnalysisRuns =
    projects.reduce(
      (
        total,
        project
      ) =>
        total +
        (
          project.analysisHistory
            ?.length ||
          0
        ),
      0
    );


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
            {totalUsers}
          </strong>

        </div>


        <div className="summary-card">

          <span className="summary-card-label">
            활성 사용자
          </span>

          <strong className="summary-card-value">
            {activeUsers}
          </strong>

        </div>


        <div className="summary-card">

          <span className="summary-card-label">
            전체 프로젝트
          </span>

          <strong className="summary-card-value">
            {totalProjects}
          </strong>

        </div>


        <div className="summary-card">

          <span className="summary-card-label">
            전체 분석 실행
          </span>

          <strong className="summary-card-value">
            {totalAnalysisRuns}
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

        </div>


        <div className="analysis-status-grid">


          <div className="analysis-status-card pending">

            <span>
              분석 대기
            </span>

            <strong>
              {pendingProjects}
            </strong>

          </div>


          <div className="analysis-status-card running">

            <span>
              분석 진행 중
            </span>

            <strong>
              {runningProjects}
            </strong>

          </div>


          <div className="analysis-status-card completed">

            <span>
              분석 완료
            </span>

            <strong>
              {completedProjects}
            </strong>

          </div>


          <div className="analysis-status-card failed">

            <span>
              분석 실패
            </span>

            <strong>
              {failedProjects}
            </strong>

          </div>


        </div>


      </section>


    </div>

  );
}


export default AdminSummary;