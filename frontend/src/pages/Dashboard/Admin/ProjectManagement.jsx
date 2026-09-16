import {
  useEffect,
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import {
  createProject,
  createSourceVersion,
  deleteProject,
  grantProjectAccess,
  revokeProjectAccess,
  updateProject,
  updateSourceVersion,
} from "../../../api/projectApi";

import {
  createAnalysisRun,
  getProjectAnalysisRuns,
} from "../../../api/analysisApi";

import ProjectCreate from "./ProjectCreate";
import ProjectEdit from "./ProjectEdit";

import ProjectDetail from "../Project/ProjectDetail";

import "./ProjectManagement.css";


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


function ProjectManagement({
  users,
  projects,
  setProjects,
  projectsLoading,
  projectsError,
}) {
  const {
    accessToken,
    setAccessToken,
  } = useAuth();


  /* ========================================
     검색
  ======================================== */

  const [
    search,
    setSearch,
  ] = useState("");


  /* ========================================
     선택 프로젝트
  ======================================== */

  const [
    selectedProjectId,
    setSelectedProjectId,
  ] = useState(null);


  /* ========================================
     화면 Mode
  ======================================== */

  const [
    viewMode,
    setViewMode,
  ] = useState("list");


  /* ========================================
     선택 프로젝트
  ======================================== */

  const selectedProject =
    projects.find(
      (project) =>
        project.id ===
        selectedProjectId
    ) ||
    null;


  /* ========================================
     선택 프로젝트 분석 진행 여부
  ======================================== */

  const selectedProjectHasActiveAnalysis =
    (
      selectedProject?.analysisHistory ||
      []
    ).some(
      (analysis) =>
        isActiveAnalysisStatus(
          analysis.status
        )
    );


  /* ========================================
     AnalysisRun 조회 / Polling

     상세 화면 진입 시 즉시 조회
     pending / planning / running 존재 시 2초마다 갱신
  ======================================== */

  useEffect(() => {

    if (
      viewMode !== "detail" ||
      !selectedProjectId
    ) {
      return undefined;
    }


    let cancelled = false;
    let intervalId = null;


    const refreshAnalysisHistory =
      async () => {

        try {

          const analysisHistory =
            await getProjectAnalysisRuns(
              selectedProjectId,
              accessToken,
              setAccessToken
            );


          if (cancelled) {
            return;
          }


          setProjects(
            (prevProjects) =>
              prevProjects.map(
                (project) =>
                  project.id ===
                    selectedProjectId
                    ? {
                        ...project,
                        analysisHistory,
                      }
                    : project
              )
          );

        } catch (error) {

          if (cancelled) {
            return;
          }


          console.error(
            "분석 이력 조회 실패:",
            error
          );
        }
      };


    refreshAnalysisHistory();


    if (
      selectedProjectHasActiveAnalysis
    ) {

      intervalId =
        window.setInterval(
          refreshAnalysisHistory,
          2000
        );
    }


    return () => {

      cancelled = true;


      if (intervalId !== null) {

        window.clearInterval(
          intervalId
        );
      }
    };

  }, [
    viewMode,
    selectedProjectId,
    selectedProjectHasActiveAnalysis,
    accessToken,
    setAccessToken,
    setProjects,
  ]);


  /* ========================================
     등록자 표시
  ======================================== */

  const getCreatorName = (
    project
  ) => {

    // ------------------------------------
    // Backend API가 내려준 username
    // ------------------------------------

    if (
      project.createdByUsername
    ) {
      return (
        project.createdByUsername
      );
    }


    // ------------------------------------
    // 기존 Mock 호환
    // ------------------------------------

    const creator =
      users.find(
        (targetUser) =>
          targetUser.id ===
          project.createdById
      );


    return (
      creator?.username ||
      "-"
    );
  };


  /* ========================================
     프로젝트 등록 화면
  ======================================== */

  const handleOpenCreate =
    () => {

      setViewMode(
        "create"
      );
    };


  /* ========================================
     프로젝트 등록

     POST /api/projects/
  ======================================== */

  const handleCreateProject =
    async (
      projectData
    ) => {

      try {
        const newProject =
          await createProject(
            {
              name:
                projectData.name,

              description:
                projectData.description,
            },
            accessToken,
            setAccessToken
          );


        // Django가 생성한 실제 프로젝트를
        // React State에 추가
        setProjects(
          (prevProjects) => [
            ...prevProjects,
            newProject,
          ]
        );


        setSelectedProjectId(
          newProject.id
        );


        setViewMode(
          "detail"
        );

      } catch (error) {
        console.error(
          "프로젝트 등록 실패:",
          error
        );

        window.alert(
          error.message ||
          "프로젝트 등록에 실패했습니다."
        );
      }
    };


  /* ========================================
     프로젝트 상세
  ======================================== */

  const handleOpenProject = (
    projectId
  ) => {

    setSelectedProjectId(
      projectId
    );


    setViewMode(
      "detail"
    );
  };


  /* ========================================
     프로젝트 수정 화면
  ======================================== */

  const handleOpenEdit =
    () => {

      if (
        !selectedProject
      ) {
        return;
      }


      setViewMode(
        "edit"
      );
    };


  /* ========================================
     프로젝트 수정

     PATCH /api/projects/{id}/
  ======================================== */

  const handleUpdateProject =
    async (
      updatedProject
    ) => {

      try {
        const savedProject =
          await updateProject(
            updatedProject.id,
            {
              name:
                updatedProject.name,

              description:
                updatedProject.description,
            },
            accessToken,
            setAccessToken
          );


        /*
         * 프로젝트 기본정보 수정 응답으로 인해
         * 현재 화면의 SourceVersion / AnalysisRun /
         * ProjectAccess 상태가 사라지지 않도록
         * 기존 세부 데이터를 보존한다.
         */

        const mergedProject = {
          ...updatedProject,
          ...savedProject,

          assignedUserIds:
            updatedProject.assignedUserIds ||
            [],

          sourceVersions:
            updatedProject.sourceVersions ||
            [],

          analysisHistory:
            updatedProject.analysisHistory ||
            [],

          currentSourceVersionId:
            updatedProject.currentSourceVersionId ??
            savedProject.currentSourceVersionId ??
            null,
        };


        setProjects(
          (prevProjects) =>
            prevProjects.map(
              (project) =>
                project.id ===
                mergedProject.id
                  ? mergedProject
                  : project
            )
        );


        setViewMode(
          "detail"
        );

      } catch (error) {
        console.error(
          "프로젝트 수정 실패:",
          error
        );

        window.alert(
          error.message ||
          "프로젝트 수정에 실패했습니다."
        );
      }
    };


  /* ========================================
     프로젝트 삭제

     DELETE /api/projects/{id}/
  ======================================== */

  const handleDeleteProject =
    async (
      projectId
    ) => {

      await deleteProject(
        projectId,
        accessToken,
        setAccessToken
      );


      // Django 삭제 성공 후
      // React State에서도 제거
      setProjects(
        (prevProjects) =>
          prevProjects.filter(
            (project) =>
              project.id !==
              projectId
          )
      );


      // 삭제한 프로젝트 상세 화면에서
      // 프로젝트 목록으로 이동
      setSelectedProjectId(
        null
      );


      setViewMode(
        "list"
      );
    };


  /* ========================================
     SourceVersion 등록

     POST
     /api/projects/{id}/sources/
  ======================================== */

  const handleAddSourceVersion =
    async (
      projectId,
      sourceData
    ) => {

      const newSourceVersion =
        await createSourceVersion(
          projectId,
          sourceData,
          accessToken,
          setAccessToken
        );


      setProjects(
        (prevProjects) =>
          prevProjects.map(
            (project) => {

              if (
                project.id !==
                projectId
              ) {
                return project;
              }


              return {
                ...project,

                sourceVersions: [
                  ...(
                    project.sourceVersions ||
                    []
                  ),
                  newSourceVersion,
                ],

                currentSourceVersionId:
                  newSourceVersion.id,
              };
            }
          )
      );


      return newSourceVersion;
    };


  /* ========================================
     미분석 SourceVersion 수정

     PATCH
     /api/projects/{id}/sources/{sourceId}/
  ======================================== */

  const handleUpdateSourceVersion =
    async (
      projectId,
      sourceVersionId,
      sourceData
    ) => {

      const savedSourceVersion =
        await updateSourceVersion(
          projectId,
          sourceVersionId,
          sourceData,
          accessToken,
          setAccessToken
        );


      setProjects(
        (prevProjects) =>
          prevProjects.map(
            (project) => {

              if (
                project.id !==
                projectId
              ) {
                return project;
              }


              return {
                ...project,

                sourceVersions:
                  (
                    project.sourceVersions ||
                    []
                  ).map(
                    (sourceVersion) =>
                      sourceVersion.id ===
                        sourceVersionId
                        ? savedSourceVersion
                        : sourceVersion
                  ),

                currentSourceVersionId:
                  savedSourceVersion.id,
              };
            }
          )
      );


      return savedSourceVersion;
    };


  /* ========================================
     AnalysisRun 생성

     POST
     /api/projects/{id}/analyses/
  ======================================== */

  const handleRunAnalysis =
    async (
      projectId,
      sourceVersionId
    ) => {

      try {

        const newAnalysisRun =
          await createAnalysisRun(
            projectId,
            sourceVersionId,
            accessToken,
            setAccessToken
          );


        setProjects(
          (prevProjects) =>
            prevProjects.map(
              (project) => {

                if (
                  project.id !==
                  projectId
                ) {
                  return project;
                }


                const analysisHistory =
                  project.analysisHistory ||
                  [];


                const exists =
                  analysisHistory.some(
                    (analysis) =>
                      analysis.id ===
                      newAnalysisRun.id
                  );


                return {
                  ...project,

                  analysisHistory:
                    exists
                      ? analysisHistory.map(
                          (analysis) =>
                            analysis.id ===
                              newAnalysisRun.id
                              ? newAnalysisRun
                              : analysis
                        )
                      : [
                          ...analysisHistory,
                          newAnalysisRun,
                        ],
                };
              }
            )
        );


        return newAnalysisRun;

      } catch (error) {

        console.error(
          "분석 실행 실패:",
          error
        );


        window.alert(
          error.message ||
          "분석 실행에 실패했습니다."
        );


        return null;
      }
    };


  /* ========================================
     사용자 접근 권한 부여

     POST /api/projects/{id}/access/
  ======================================== */

  const handleGrantUserAccess =
    async (
      projectId,
      userId
    ) => {

      const targetUser =
        users.find(
          (target) =>
            target.id ===
            userId
        );


      if (!targetUser) {

        throw new Error(
          "사용자를 찾을 수 없습니다."
        );
      }


      if (
        targetUser.role !==
        "user"
      ) {

        throw new Error(
          "일반 사용자만 프로젝트에 할당할 수 있습니다."
        );
      }


      if (
        !targetUser.isActive
      ) {

        throw new Error(
          "비활성 사용자는 프로젝트에 할당할 수 없습니다."
        );
      }


      await grantProjectAccess(
        projectId,
        userId,
        accessToken,
        setAccessToken
      );


      setProjects(
        (prevProjects) =>
          prevProjects.map(
            (project) => {

              if (
                project.id !==
                projectId
              ) {

                return project;
              }


              const assignedUserIds =
                project.assignedUserIds ||
                [];


              if (
                assignedUserIds.includes(
                  userId
                )
              ) {

                return project;
              }


              return {
                ...project,

                assignedUserIds: [
                  ...assignedUserIds,
                  userId,
                ],
              };
            }
          )
      );
    };


  /* ========================================
     사용자 접근 권한 해제

     DELETE
     /api/projects/{id}/access/{userId}/
  ======================================== */

  const handleRevokeUserAccess =
    async (
      projectId,
      userId
    ) => {

      await revokeProjectAccess(
        projectId,
        userId,
        accessToken,
        setAccessToken
      );


      setProjects(
        (prevProjects) =>
          prevProjects.map(
            (project) => {

              if (
                project.id !==
                projectId
              ) {

                return project;
              }


              return {
                ...project,

                assignedUserIds:
                  (
                    project.assignedUserIds ||
                    []
                  ).filter(
                    (assignedUserId) =>
                      assignedUserId !==
                      userId
                  ),
              };
            }
          )
      );
    };


  /* ========================================
     검색
  ======================================== */

  const filteredProjects =
    projects.filter(
      (project) => {

        const keyword =
          search
            .trim()
            .toLowerCase();


        if (!keyword) {
          return true;
        }


        const creatorName =
          getCreatorName(
            project
          ).toLowerCase();


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


        return (
          projectName.includes(
            keyword
          ) ||
          description.includes(
            keyword
          ) ||
          creatorName.includes(
            keyword
          )
        );
      }
    );


  /* ========================================
     프로젝트 등록
  ======================================== */

  if (
    viewMode ===
    "create"
  ) {
    return (
      <ProjectCreate
        onCreate={
          handleCreateProject
        }

        onCancel={() =>
          setViewMode(
            "list"
          )
        }
      />
    );
  }


  /* ========================================
     프로젝트 수정
  ======================================== */

  if (
    viewMode ===
      "edit" &&
    selectedProject
  ) {
    return (
      <ProjectEdit
        project={
          selectedProject
        }

        onSave={
          handleUpdateProject
        }

        onCancel={() =>
          setViewMode(
            "detail"
          )
        }
      />
    );
  }


  /* ========================================
     프로젝트 상세
  ======================================== */

  if (
    viewMode ===
      "detail" &&
    selectedProject
  ) {
    return (
      <ProjectDetail
        project={
          selectedProject
        }

        users={
          users
        }

        onBack={() => {
          setSelectedProjectId(
            null
          );

          setViewMode(
            "list"
          );
        }}

        onEdit={
          handleOpenEdit
        }

        onDelete={
          handleDeleteProject
        }

        onAddSourceVersion={
          handleAddSourceVersion
        }

        onUpdateSourceVersion={
          handleUpdateSourceVersion
        }

        onRunAnalysis={
          handleRunAnalysis
        }

        onGrantUserAccess={
          handleGrantUserAccess
        }

        onRevokeUserAccess={
          handleRevokeUserAccess
        }
      />
    );
  }


  /* ========================================
     프로젝트 목록
  ======================================== */

  return (
    <div className="project-management">

      <div className="project-management-toolbar">

        <div className="project-management-description">
          등록된 프로젝트를 조회하고 관리할 수 있습니다.
        </div>


        <button
          type="button"

          className="project-create-button"

          onClick={
            handleOpenCreate
          }
        >
          프로젝트 등록
        </button>

      </div>


      <div className="project-search-area">

        <input
          type="text"

          value={
            search
          }

          placeholder="프로젝트명, 설명 또는 등록자 검색"

          onChange={
            (event) =>
              setSearch(
                event.target.value
              )
          }
        />

      </div>


      <div className="project-table-wrapper">

        <table className="project-table">

          <thead>
            <tr>
              <th>
                프로젝트명
              </th>

              <th>
                설명
              </th>

              <th>
                등록자
              </th>

              <th>
                등록 일시
              </th>
            </tr>
          </thead>


          <tbody>

            {
              projectsLoading
                ? (
                    <tr>
                      <td
                        className="project-empty"
                        colSpan="4"
                      >
                        프로젝트를 불러오는 중입니다.
                      </td>
                    </tr>
                  )

                : projectsError
                  ? (
                      <tr>
                        <td
                          className="project-empty"
                          colSpan="4"
                        >
                          {
                            projectsError
                          }
                        </td>
                      </tr>
                    )

                  : filteredProjects.length > 0
                    ? filteredProjects.map(
                        (project) => (

                          <tr
                            key={
                              project.id
                            }
                          >

                            <td>
                              <button
                                type="button"

                                className="project-name-button"

                                onClick={() =>
                                  handleOpenProject(
                                    project.id
                                  )
                                }
                              >
                                {
                                  project.name
                                }
                              </button>
                            </td>


                            <td>
                              {
                                project.description ||
                                "-"
                              }
                            </td>


                            <td>
                              {
                                getCreatorName(
                                  project
                                )
                              }
                            </td>


                            <td>
                              {
                                project.createdAt ||
                                "-"
                              }
                            </td>

                          </tr>

                        )
                      )

                    : (
                        <tr>
                          <td
                            className="project-empty"
                            colSpan="4"
                          >
                            등록된 프로젝트가 없습니다.
                          </td>
                        </tr>
                      )
            }

          </tbody>

        </table>

      </div>

    </div>
  );
}


export default ProjectManagement;