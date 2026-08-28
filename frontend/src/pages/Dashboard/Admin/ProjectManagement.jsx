import { useState } from "react";

import ProjectCreate from "./ProjectCreat";
import ProjectEdit from "./ProjectEdit";

import ProjectDetail from "../Project/ProjectDetail";

import "./ProjectManagement.css";


function ProjectManagement({
  users,
  projects,
  setProjects,
}) {

  /* ========================================
     검색
  ======================================== */

  const [
    search,
    setSearch,
  ] = useState("");


  /* ========================================
     현재 선택 프로젝트
  ======================================== */

  const [
    selectedProject,
    setSelectedProject,
  ] = useState(null);


  /* ========================================
     화면 Mode

     list
     create
     detail
     edit
  ======================================== */

  const [
    viewMode,
    setViewMode,
  ] = useState("list");


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
     프로젝트 등록 화면
  ======================================== */

  const handleCreateProject = () => {

    setViewMode(
      "create"
    );
  };


  /* ========================================
     프로젝트 상세 화면
  ======================================== */

  const handleOpenProject = (
    project
  ) => {

    setSelectedProject(
      project
    );

    setViewMode(
      "detail"
    );
  };


  /* ========================================
     프로젝트 수정 완료
  ======================================== */

  const handleUpdateProject = (
    updatedProject
  ) => {

    setProjects(
      (prevProjects) =>
        prevProjects.map(
          (project) =>
            project.id ===
            updatedProject.id

              ? updatedProject

              : project
        )
    );


    setSelectedProject(
      updatedProject
    );


    setViewMode(
      "detail"
    );
  };


  /* ========================================
     분석 실행

     Mock에서는
     pending → running

     completed / failed는
     나중에 Backend + Celery 처리
  ======================================== */

  const handleRunAnalysis = (
    projectId
  ) => {

    setProjects(
      (prevProjects) =>
        prevProjects.map(
          (project) => {

            if (
              project.id === projectId &&
              project.status === "pending"
            ) {

              return {
                ...project,

                status: "running",
              };
            }


            return project;
          }
        )
    );


    setSelectedProject(
      (prevProject) => {

        if (
          prevProject &&
          prevProject.id === projectId &&
          prevProject.status === "pending"
        ) {

          return {
            ...prevProject,

            status: "running",
          };
        }


        return prevProject;
      }
    );
  };


  /* ========================================
     사용자 접근 권한 부여

     정책:
     completed 프로젝트만 가능
  ======================================== */

  const handleGrantUserAccess = (
    projectId,
    userId
  ) => {

    const targetUser =
      users.find(
        (user) =>
          user.id === userId
      );


    /* 사용자가 존재하지 않음 */

    if (!targetUser) {
      return;
    }


    /* 일반 사용자만 가능 */

    if (
      targetUser.role !== "user"
    ) {
      return;
    }


    /* 활성 사용자만 신규 할당 가능 */

    if (
      !targetUser.isActive
    ) {
      return;
    }


    /* ====================================
       프로젝트 State 수정
    ==================================== */

    setProjects(
      (prevProjects) =>
        prevProjects.map(
          (project) => {

            if (
              project.id !== projectId
            ) {
              return project;
            }


            /* =================================
               분석 완료 프로젝트만
               사용자 할당 가능
            ================================= */

            if (
              project.status !==
              "completed"
            ) {
              return project;
            }


            const assignedUserIds =
              project.assignedUserIds ||
              [];


            /* 이미 할당된 사용자 */

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


    /* ====================================
       현재 상세 화면 즉시 반영
    ==================================== */

    setSelectedProject(
      (prevProject) => {

        if (
          !prevProject ||
          prevProject.id !==
            projectId
        ) {
          return prevProject;
        }


        /* completed만 가능 */

        if (
          prevProject.status !==
          "completed"
        ) {
          return prevProject;
        }


        const assignedUserIds =
          prevProject.assignedUserIds ||
          [];


        if (
          assignedUserIds.includes(
            userId
          )
        ) {
          return prevProject;
        }


        return {
          ...prevProject,

          assignedUserIds: [
            ...assignedUserIds,
            userId,
          ],
        };
      }
    );
  };


  /* ========================================
     사용자 접근 권한 해제

     정책:
     completed 프로젝트만 가능
  ======================================== */

  const handleRevokeUserAccess = (
    projectId,
    userId
  ) => {

    /* ====================================
       프로젝트 State 수정
    ==================================== */

    setProjects(
      (prevProjects) =>
        prevProjects.map(
          (project) => {

            if (
              project.id !== projectId
            ) {
              return project;
            }


            /* completed만 가능 */

            if (
              project.status !==
              "completed"
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
                  (id) =>
                    id !== userId
                ),
            };
          }
        )
    );


    /* ====================================
       상세 화면 즉시 반영
    ==================================== */

    setSelectedProject(
      (prevProject) => {

        if (
          !prevProject ||
          prevProject.id !==
            projectId
        ) {
          return prevProject;
        }


        if (
          prevProject.status !==
          "completed"
        ) {
          return prevProject;
        }


        return {
          ...prevProject,

          assignedUserIds:
            (
              prevProject.assignedUserIds ||
              []
            ).filter(
              (id) =>
                id !== userId
            ),
        };
      }
    );
  };


  /* ========================================
     프로젝트 검색
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


        return project.name
          .toLowerCase()
          .includes(
            keyword
          );
      }
    );


  /* ========================================
     프로젝트 등록
  ======================================== */

  if (
    viewMode === "create"
  ) {

    return (

      <ProjectCreate

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
    viewMode === "edit" &&
    selectedProject
  ) {

    return (

      <ProjectEdit

        project={
          selectedProject
        }

        onCancel={() =>
          setViewMode(
            "detail"
          )
        }

        onSave={
          handleUpdateProject
        }

      />

    );
  }


  /* ========================================
     프로젝트 상세
  ======================================== */

  if (
    viewMode === "detail" &&
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

          setSelectedProject(
            null
          );

          setViewMode(
            "list"
          );
        }}

        onEdit={() =>
          setViewMode(
            "edit"
          )
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

          등록된 프로젝트를
          조회하고 관리할 수 있습니다.

        </div>


        <button
          className="project-create-button"

          onClick={
            handleCreateProject
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

          placeholder="프로젝트 이름 검색"

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
                분석 언어
              </th>

              <th>
                등록 일시
              </th>

              <th>
                분석 상태
              </th>

            </tr>

          </thead>


          <tbody>


            {
              filteredProjects.length > 0
                ? (

                  filteredProjects.map(
                    (project) => (

                      <tr
                        key={
                          project.id
                        }
                      >


                        <td>

                          <button
                            className="project-name-button"

                            onClick={() =>
                              handleOpenProject(
                                project
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
                            project.language
                          }
                        </td>


                        <td>
                          {
                            project.createdAt
                          }
                        </td>


                        <td>

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

                        </td>


                      </tr>

                    )
                  )

                )
                : (

                  <tr>

                    <td
                      className="project-empty"

                      colSpan="4"
                    >

                      검색 결과가 없습니다.

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