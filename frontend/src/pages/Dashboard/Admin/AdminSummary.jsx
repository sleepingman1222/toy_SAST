import "./AdminSummary.css";


function AdminSummary({
  users = [],
  projects = [],
}) {

  /* ========================================
     사용자 현황
  ======================================== */

  const totalUsers =
    users.length;


  const activeUsers =
    users.filter(
      (user) =>
        user.isActive
    ).length;


  /* ========================================
     프로젝트 전체
  ======================================== */

  const totalProjects =
    projects.length;


  /* ========================================
     프로젝트 상태별 개수
  ======================================== */

  const pendingProjects =
    projects.filter(
      (project) =>
        project.status ===
        "pending"
    ).length;


  const runningProjects =
    projects.filter(
      (project) =>
        project.status ===
        "running"
    ).length;


  const completedProjects =
    projects.filter(
      (project) =>
        project.status ===
        "completed"
    ).length;


  const failedProjects =
    projects.filter(
      (project) =>
        project.status ===
        "failed"
    ).length;


  return (

    <div className="admin-summary">


      {/* ===================================
          상단 설명
      =================================== */}

      <div className="admin-summary-description">

        사용자와 프로젝트의
        현재 상태를 확인할 수 있습니다.

      </div>


      {/* ===================================
          핵심 요약
      =================================== */}

      <section className="summary-section">


        <h2>
          전체 현황
        </h2>


        <div className="summary-card-grid">


          {/* 전체 사용자 */}

          <div className="summary-card">

            <span className="summary-card-label">
              전체 사용자
            </span>

            <strong className="summary-card-value">
              {totalUsers}
            </strong>

          </div>


          {/* 활성 사용자 */}

          <div className="summary-card">

            <span className="summary-card-label">
              활성 사용자
            </span>

            <strong className="summary-card-value">
              {activeUsers}
            </strong>

          </div>


          {/* 전체 프로젝트 */}

          <div className="summary-card">

            <span className="summary-card-label">
              전체 프로젝트
            </span>

            <strong className="summary-card-value">
              {totalProjects}
            </strong>

          </div>


          {/* 분석 완료 */}

          <div className="summary-card">

            <span className="summary-card-label">
              분석 완료
            </span>

            <strong className="summary-card-value">
              {completedProjects}
            </strong>

          </div>


        </div>


      </section>


      {/* ===================================
          프로젝트 상태
      =================================== */}

      <section className="summary-section">


        <h2>
          프로젝트 현황
        </h2>


        <div className="project-status-summary">


          {/* 분석 전 */}

          <div className="project-status-summary-row">

            <div className="project-status-summary-label">

              <span
                className="project-status pending"
              >
                분석 전
              </span>

            </div>


            <strong>
              {pendingProjects}
            </strong>

          </div>


          {/* 분석 진행 중 */}

          <div className="project-status-summary-row">

            <div className="project-status-summary-label">

              <span
                className="project-status running"
              >
                분석 진행 중
              </span>

            </div>


            <strong>
              {runningProjects}
            </strong>

          </div>


          {/* 분석 완료 */}

          <div className="project-status-summary-row">

            <div className="project-status-summary-label">

              <span
                className="project-status completed"
              >
                분석 완료
              </span>

            </div>


            <strong>
              {completedProjects}
            </strong>

          </div>


          {/* 분석 실패 */}

          <div className="project-status-summary-row">

            <div className="project-status-summary-label">

              <span
                className="project-status failed"
              >
                분석 실패
              </span>

            </div>


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