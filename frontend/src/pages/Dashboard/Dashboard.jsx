import {
  useEffect,
  useState,
} from "react";

import {
  useAuth,
} from "../../auth/useAuth";

import {
  getProjects,
} from "../../api/projectApi";

import {
  getUsers,
} from "../../api/userApi";

import SideBar from "../../components/SideBar/SideBar";

import AdminSummary from "./Admin/AdminSummary";
import UserManagement from "./Admin/UserManagement";
import ProjectManagement from "./Admin/ProjectManagement";

import UserSummary from "./User/UserSummary";
import UserProjectList from "./User/UserProjectList";
import MyPage from "./MyPage/MyPage";

import "./Dashboard.css";


function Dashboard() {

  const {
    user,
    accessToken,
    setAccessToken,
    logout,
  } = useAuth();


  /* ========================================
     Shared State
  ======================================== */

  const [
    users,
    setUsers,
  ] = useState([]);


  const [
    projects,
    setProjects,
  ] = useState([]);


  /* ========================================
     User Loading / Error
  ======================================== */

  const [
    usersLoading,
    setUsersLoading,
  ] = useState(false);


  const [
    usersError,
    setUsersError,
  ] = useState("");


  /* ========================================
     Project Loading / Error
  ======================================== */

  const [
    projectsLoading,
    setProjectsLoading,
  ] = useState(false);


  const [
    projectsError,
    setProjectsError,
  ] = useState("");


  /* ========================================
     사용자 목록 조회

     관리자만 사용자 목록 조회
  ======================================== */

  useEffect(
    () => {

      let cancelled =
        false;


      if (
        user?.role !==
        "admin"
      ) {

        setUsers([]);
        setUsersLoading(false);
        setUsersError("");


        return () => {

          cancelled =
            true;
        };
      }


      const loadUsers =
        async () => {

          setUsersLoading(
            true
          );

          setUsersError(
            ""
          );


          try {

            const userList =
              await getUsers(
                accessToken,
                setAccessToken
              );


            if (
              !cancelled
            ) {

              setUsers(
                userList
              );
            }

          } catch (error) {

            console.error(
              "사용자 목록 조회 실패:",
              error
            );


            if (
              !cancelled
            ) {

              setUsersError(
                error.message ||
                "사용자 목록을 불러오지 못했습니다."
              );
            }

          } finally {

            if (
              !cancelled
            ) {

              setUsersLoading(
                false
              );
            }
          }
        };


      loadUsers();


      return () => {

        cancelled =
          true;
      };
    },
    [
      user?.role,
      accessToken,
      setAccessToken,
    ]
  );


  /* ========================================
     프로젝트 목록 조회

     관리자
     → 전체 프로젝트

     일반 사용자
     → Backend에서 ProjectAccess가 있는
       프로젝트만 반환하도록 수정 예정
  ======================================== */

  useEffect(
    () => {

      let cancelled =
        false;


      if (!user?.role) {

        setProjects([]);
        setProjectsLoading(false);
        setProjectsError("");


        return () => {

          cancelled =
            true;
        };
      }


      const loadProjects =
        async () => {

          setProjectsLoading(
            true
          );

          setProjectsError(
            ""
          );


          try {

            const projectList =
              await getProjects(
                accessToken,
                setAccessToken
              );


            if (
              !cancelled
            ) {

              setProjects(
                projectList
              );
            }

          } catch (error) {

            console.error(
              "프로젝트 목록 조회 실패:",
              error
            );


            if (
              !cancelled
            ) {

              setProjectsError(
                error.message ||
                "프로젝트 목록을 불러오지 못했습니다."
              );
            }

          } finally {

            if (
              !cancelled
            ) {

              setProjectsLoading(
                false
              );
            }
          }
        };


      loadProjects();


      return () => {

        cancelled =
          true;
      };
    },
    [
      user?.role,
      accessToken,
      setAccessToken,
    ]
  );


  /* ========================================
     Sidebar
  ======================================== */

  const [
    selectedMenu,
    setSelectedMenu,
  ] = useState(
    "summary"
  );


  /* ========================================
     현재 페이지 제목
  ======================================== */

  const getPageTitle =
    () => {

      switch (
        selectedMenu
      ) {

        case "summary":

          return "요약";


        case "users":

          return "사용자 관리";


        case "projects":

          return (
            user?.role ===
            "admin"
              ? "프로젝트 관리"
              : "프로젝트 조회"
          );


        case "mypage":

          return "마이페이지";


        default:

          return "";
      }
    };


  /* ========================================
     로그아웃
  ======================================== */

  const handleLogout =
    async () => {

      await logout();
    };


  /* ========================================
     관리자 화면
  ======================================== */

  const renderAdminContent =
    () => {

      switch (
        selectedMenu
      ) {

        case "summary":

          return (

            <AdminSummary />

          );


        case "users":

          return (

            <UserManagement
              users={
                users
              }

              setUsers={
                setUsers
              }

              projects={
                projects
              }

              setProjects={
                setProjects
              }

              usersLoading={
                usersLoading
              }

              usersError={
                usersError
              }
            />

          );


        case "projects":

          return (

            <ProjectManagement
              users={
                users
              }

              projects={
                projects
              }

              setProjects={
                setProjects
              }

              projectsLoading={
                projectsLoading
              }

              projectsError={
                projectsError
              }
            />

          );


        case "mypage":

          return (
            <MyPage />
          );


        default:

          return (

            <AdminSummary />

          );
      }
    };


  /* ========================================
     일반 사용자 화면
  ======================================== */

  const renderUserContent =
    () => {

      switch (
        selectedMenu
      ) {

        case "summary":

          return (

            <UserSummary
              projects={
                projects
              }

              projectsLoading={
                projectsLoading
              }

              projectsError={
                projectsError
              }
            />

          );


        case "projects":

          return (

            <UserProjectList
              projects={
                projects
              }

              setProjects={
                setProjects
              }

              projectsLoading={
                projectsLoading
              }

              projectsError={
                projectsError
              }
            />

          );


        case "mypage":

          return (
            <MyPage />
          );


        default:

          return (

            <UserSummary
              projects={
                projects
              }

              projectsLoading={
                projectsLoading
              }

              projectsError={
                projectsError
              }
            />

          );
      }
    };


  /* ========================================
     Content
  ======================================== */

  const renderContent =
    () => {

      if (
        user?.role ===
        "admin"
      ) {

        return (
          renderAdminContent()
        );
      }


      return (
        renderUserContent()
      );
    };


  /* ========================================
     Dashboard
  ======================================== */

  return (

    <div className="dashboard">

      <SideBar
        role={
          user?.role
        }

        selectedMenu={
          selectedMenu
        }

        onMenuChange={
          setSelectedMenu
        }
      />


      <main className="dashboard-main">

        <header className="dashboard-topbar">

          <div className="dashboard-page-title">

            {
              getPageTitle()
            }

          </div>


          <div className="dashboard-user">

            <div className="dashboard-user-info">

              <span className="dashboard-username">

                {
                  user?.username ||
                  "-"
                }

              </span>


              <span
                className={
                  `dashboard-role ${
                    user?.role ===
                    "admin"
                      ? "admin"
                      : "user"
                  }`
                }
              >

                {
                  user?.role ===
                  "admin"
                    ? "관리자"
                    : "일반 사용자"
                }

              </span>

            </div>


            <button
              type="button"

              className="logout-button"

              onClick={
                handleLogout
              }
            >
              로그아웃
            </button>

          </div>

        </header>


        <div className="dashboard-content">

          {
            renderContent()
          }

        </div>

      </main>

    </div>
  );
}


export default Dashboard;