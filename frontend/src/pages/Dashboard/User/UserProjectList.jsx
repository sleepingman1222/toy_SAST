import {
  useEffect,
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import {
  getProjectAnalysisRuns,
} from "../../../api/api";

import UserProjectDetail from "./UserProjectDetail";

import "./UserProjectList.css";


function UserProjectList({
  projects = [],
  projectsLoading = false,
  projectsError = "",
}) {

  const {
    accessToken,
    setAccessToken,
  } = useAuth();


  /* ========================================
     Search
  ======================================== */

  const [
    search,
    setSearch,
  ] = useState("");


  /* ========================================
     Selected Project
  ======================================== */

  const [
    selectedProjectId,
    setSelectedProjectId,
  ] = useState(null);


  /* ========================================
     Analysis History
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


  /* ========================================
     Project IDs

     실제 프로젝트 목록이 변경됐을 때
     AnalysisRun 다시 조회
  ======================================== */

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
     AnalysisRun 조회

     일반 사용자 Backend 응답
     → completed AnalysisRun만
  ======================================== */

  useEffect(() => {

    let cancelled =
      false;


    if (
      projectsLoading ||
      projectsError ||
      projects.length === 0
    ) {

      setAnalysisByProject(
        {}
      );

      setAnalysesLoading(
        false
      );

      setAnalysesError(
        ""
      );


      return () => {

        cancelled =
          true;
      };
    }


    const loadAnalysisHistory =
      async () => {

        setAnalysesLoading(
          true
        );

        setAnalysesError(
          ""
        );


        try {

          const results =
            await Promise.all(

              projects.map(
                async (
                  project
                ) => {

                  const analysisHistory =
                    await getProjectAnalysisRuns(
                      project.id,
                      accessToken,
                      setAccessToken
                    );


                  return [
                    project.id,
                    analysisHistory,
                  ];
                }
              )

            );


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
            "프로젝트 분석 이력 조회 실패:",
            error
          );


          setAnalysesError(
            error.message ||
            "분석 결과를 불러오지 못했습니다."
          );

        } finally {

          if (!cancelled) {

            setAnalysesLoading(
              false
            );
          }
        }
      };


    loadAnalysisHistory();


    return () => {

      cancelled =
        true;
    };

  }, [
    projectIdsKey,
    projectsLoading,
    projectsError,
    accessToken,
    setAccessToken,
  ]);


  /* ========================================
     Project Analysis History
  ======================================== */

  const getAnalysisHistory =
    (project) => {

      return (
        analysisByProject[
          project.id
        ] ||
        []
      );
    };


  /* ========================================
     Latest Completed Analysis
  ======================================== */

  const getLatestCompletedAnalysis =
    (project) => {

      return [
        ...getAnalysisHistory(
          project
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
        )[0] ||
        null;
    };


  /* ========================================
     Analysis SourceVersion
  ======================================== */

  const getAnalysisSourceVersion =
    (
      project,
      analysis
    ) => {

      if (!analysis) {
        return null;
      }


      return (
        (
          project.sourceVersions ||
          []
        ).find(
          (sourceVersion) =>
            sourceVersion.id ===
            analysis.sourceVersionId
        ) ||
        null
      );
    };


  /* ========================================
     Language

     분석 이력에서는 AnalysisRun의
     analysisLanguages Snapshot을 우선 사용한다.

     SourceVersion의 detectedLanguages는
     이전 응답 / 연결 보조용 fallback으로 사용한다.
  ======================================== */

  const getLanguageLabel = (
    language
  ) => {

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
      .join(", "
      );
  };


  const getAnalysisLanguageText = (
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
     Finding Count

     completed 분석이 없으면 null
     completed 분석 결과가 0건이면 0
  ======================================== */

  const getAnalysisResultCount =
    (analysis) => {

      if (!analysis) {
        return null;
      }


      return (
        analysis.summary?.total ??
        analysis.vulnerabilities
          ?.length ??
        0
      );
    };


  /* ========================================
     Selected Project

     AnalysisRun을 함께 넣어서
     UserProjectDetail에 전달
  ======================================== */

  const originalSelectedProject =
    projects.find(
      (project) =>
        project.id ===
        selectedProjectId
    ) ||
    null;


  const selectedProject =
    originalSelectedProject
      ? {
          ...originalSelectedProject,

          analysisHistory:
            getAnalysisHistory(
              originalSelectedProject
            ),
        }
      : null;


  /* ========================================
     Search

     Backend에서 이미
     ProjectAccess가 부여된 프로젝트만 반환

     completed 분석이 없어도
     프로젝트 자체는 검색 / 조회 가능
  ======================================== */

  const keyword =
    search
      .trim()
      .toLowerCase();


  const filteredProjects =
    projects.filter(
      (project) => {

        if (!keyword) {
          return true;
        }


        const latestAnalysis =
          getLatestCompletedAnalysis(
            project
          );


        const sourceVersion =
          getAnalysisSourceVersion(
            project,
            latestAnalysis
          );


        const projectName =
          (
            project.name ||
            ""
          ).toLowerCase();


        const description =
          (
            project.description ||
            ""
          ).toLowerCase();


        const creatorName =
          (
            project.createdByUsername ||
            ""
          ).toLowerCase();


        const language =
          getAnalysisLanguageText(
            latestAnalysis,
            sourceVersion
          ).toLowerCase();


        return (
          projectName.includes(
            keyword
          ) ||
          description.includes(
            keyword
          ) ||
          creatorName.includes(
            keyword
          ) ||
          language.includes(
            keyword
          )
        );
      }
    );


  /* ========================================
     Project Detail
  ======================================== */

  if (selectedProject) {

    return (

      <UserProjectDetail
        project={
          selectedProject
        }

        onBack={() =>
          setSelectedProjectId(
            null
          )
        }
      />

    );
  }


  /* ========================================
     Project List
  ======================================== */

  return (

    <div className="user-project-list">


      {/* ===================================
          Header
      =================================== */}

      <div className="user-project-list-header">

        <h2>
          프로젝트 조회
        </h2>

        <p>
          나에게 할당된 프로젝트와 완료된 분석 결과를 조회할 수 있습니다.
        </p>

      </div>


      {/* ===================================
          Project Count
      =================================== */}

      <div className="user-project-status-area">

        <span className="user-project-status-label">
          조회 가능 프로젝트
        </span>

        <strong className="user-project-status-count">
          {projects.length}
        </strong>

        <span className="user-project-status-unit">
          개
        </span>

      </div>


      {/* ===================================
          Search
      =================================== */}

      <div className="user-project-toolbar">

        <div className="user-project-search">

          <input
            type="text"

            value={
              search
            }

            placeholder="프로젝트명, 설명, 등록자 또는 언어 검색"

            onChange={
              (event) =>
                setSearch(
                  event.target.value
                )
            }
          />

        </div>

      </div>


      {/* ===================================
          Analysis Error
      =================================== */}

      {
        !projectsLoading &&
        !projectsError &&
        analysesError && (

          <div className="user-project-empty error">
            {analysesError}
          </div>

        )
      }


      {/* ===================================
          Table
      =================================== */}

      <div className="user-project-table-card">

        <div className="user-project-table-wrapper">

          <table className="user-project-table">

            <thead>

              <tr>

                <th>
                  프로젝트
                </th>

                <th>
                  설명
                </th>

                <th>
                  분석 Source
                </th>

                <th>
                  언어
                </th>

                <th>
                  진단 결과
                </th>

              </tr>

            </thead>


            <tbody>

              {
                projectsLoading
                  ? (

                    <tr>

                      <td
                        className="user-project-empty"
                        colSpan="5"
                      >
                        프로젝트를 불러오는 중입니다.
                      </td>

                    </tr>

                  )

                  : projectsError
                    ? (

                      <tr>

                        <td
                          className="user-project-empty error"
                          colSpan="5"
                        >
                          {projectsError}
                        </td>

                      </tr>

                    )

                    : filteredProjects.length > 0
                      ? filteredProjects.map(
                          (project) => {

                            const latestAnalysis =
                              getLatestCompletedAnalysis(
                                project
                              );


                            const sourceVersion =
                              getAnalysisSourceVersion(
                                project,
                                latestAnalysis
                              );


                            const findingCount =
                              getAnalysisResultCount(
                                latestAnalysis
                              );


                            return (

                              <tr
                                key={
                                  project.id
                                }
                              >


                                {/* =====================
                                    Project
                                ===================== */}

                                <td>

                                  <div className="user-project-name-cell">

                                    <button
                                      type="button"

                                      className="user-project-name-button"

                                      disabled={
                                        analysesLoading
                                      }

                                      onClick={() =>
                                        setSelectedProjectId(
                                          project.id
                                        )
                                      }
                                    >
                                      {
                                        project.name
                                      }
                                    </button>


                                    <span>
                                      등록자{" "}
                                      {
                                        project.createdByUsername ||
                                        "-"
                                      }
                                    </span>

                                  </div>

                                </td>


                                {/* =====================
                                    Description
                                ===================== */}

                                <td>

                                  <div className="user-project-description">

                                    {
                                      project.description ||
                                      "-"
                                    }

                                  </div>

                                </td>


                                {/* =====================
                                    Analysis Source
                                ===================== */}

                                <td>

                                  {
                                    analysesLoading
                                      ? "..."
                                      : (
                                          sourceVersion
                                            ? `v${sourceVersion.version}`
                                            : "-"
                                        )
                                  }

                                </td>


                                {/* =====================
                                    Language
                                ===================== */}

                                <td>

                                  {
                                    analysesLoading
                                      ? "..."
                                      : getAnalysisLanguageText(
                                          latestAnalysis,
                                          sourceVersion
                                        )
                                  }

                                </td>


                                {/* =====================
                                    Finding Count
                                ===================== */}

                                <td>

                                  {
                                    analysesLoading
                                      ? (
                                        "불러오는 중..."
                                      )
                                      : latestAnalysis
                                        ? (

                                          <span className="user-project-finding-count">
                                            {findingCount}건
                                          </span>

                                        )
                                        : (

                                          <span className="user-project-finding-count">
                                            완료 결과 없음
                                          </span>

                                        )
                                  }

                                </td>


                              </tr>

                            );
                          }
                        )

                      : (

                        <tr>

                          <td
                            className="user-project-empty"
                            colSpan="5"
                          >
                            {
                              projects.length === 0
                                ? "현재 할당된 프로젝트가 없습니다."
                                : "검색 조건에 해당하는 프로젝트가 없습니다."
                            }
                          </td>

                        </tr>

                      )
              }

            </tbody>

          </table>

        </div>

      </div>


      {/* ===================================
          Result Count
      =================================== */}

      {
        !projectsLoading &&
        !projectsError &&
        projects.length > 0 && (

          <div className="user-project-list-footer">

            총{" "}

            <strong>
              {
                filteredProjects.length
              }
            </strong>

            개의 프로젝트가 표시되고 있습니다.

          </div>

        )
      }


    </div>

  );
}


export default UserProjectList;