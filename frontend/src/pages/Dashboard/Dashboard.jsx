import { useState } from "react";

import { useAuth } from "../../auth/useAuth";

import SideBar from "../../components/SideBar/SideBar";

import AdminSummary from "./Admin/AdminSummary";
import UserManagement from "./Admin/UserManagement";
import ProjectManagement from "./Admin/ProjectManagement";

import MyPage from "./MyPage/MyPage";

import "./Dashboard.css";


/* ========================================
   임시 사용자 데이터

   나중에 Backend API로 교체
======================================== */

const initialUsers = [
  {
    id: 1,
    username: "admin",
    role: "admin",
    isActive: true,
    createdAt: "2026-08-20 09:00",
  },

  {
    id: 2,
    username: "user01",
    role: "user",
    isActive: true,
    createdAt: "2026-08-21 10:20",
  },

  {
    id: 3,
    username: "user02",
    role: "user",
    isActive: true,
    createdAt: "2026-08-22 14:10",
  },

  {
    id: 4,
    username: "user03",
    role: "user",
    isActive: false,
    createdAt: "2026-08-23 11:40",
  },

  {
    id: 5,
    username: "tester01",
    role: "user",
    isActive: true,
    createdAt: "2026-08-24 16:30",
  },
];


/* ========================================
   임시 프로젝트 데이터

   정책

   completed 상태의 프로젝트만
   일반 사용자 접근 권한을 부여할 수 있음

   assignedUserIds
   → 완료된 프로젝트의 분석 결과를
     조회할 수 있는 사용자 ID

   latestAnalysis
   → 가장 최근 분석 결과
======================================== */

const initialProjects = [
  {
    id: 1,

    name: "Project A",

    description:
      "Java 기반 정적 분석 테스트 프로젝트입니다.",

    language: "Java",

    sourceType: "upload",

    sourceFileName:
      "project-a-source.zip",

    repositoryUrl: "",

    internalPath: "",

    createdAt:
      "2026-08-28 09:30",

    status: "pending",

    assignedUserIds: [],
  },

  {
    id: 2,

    name: "Project B",

    description:
      "Python 기반 보안 분석 프로젝트입니다.",

    language: "Python",

    sourceType: "repository",

    sourceFileName: "",

    repositoryUrl:
      "https://example.com/project-b.git",

    internalPath: "",

    createdAt:
      "2026-08-27 14:20",

    status: "running",

    assignedUserIds: [],
  },

  {
    id: 3,

    name: "Project C",

    description:
      "JavaScript 기반 보안 분석 프로젝트입니다.",

    language: "JavaScript",

    sourceType: "internal",

    sourceFileName: "",

    repositoryUrl: "",

    internalPath:
      "/source/project-c",

    createdAt:
      "2026-08-26 11:10",

    status: "completed",

    assignedUserIds: [
      2,
      5,
    ],


    /* ====================================
       최근 분석 결과 Mock Data
    ==================================== */

    latestAnalysis: {
      id: 101,

      engine: "Semgrep",

      startedAt:
        "2026-08-26 11:30",

      completedAt:
        "2026-08-26 11:35",

      summary: {
        total: 4,
        critical: 0,
        high: 2,
        medium: 1,
        low: 1,
      },

      vulnerabilities: [
        {
          id: 1,

          ruleId:
            "SAST-001",

          name:
            "SQL Injection",

          severity:
            "high",

          confidence:
            "high",

          filePath:
            "src/UserDAO.js",

          line:
            84,

          message:
            "사용자 입력값이 SQL Query에 직접 사용되고 있습니다.",

          evidence:
            'query = "SELECT * FROM users WHERE id = " + userId;',

          recommendation:
            "Parameterized Query를 사용하여 사용자 입력값이 SQL 문자열에 직접 결합되지 않도록 수정하세요.",
        },

        {
          id: 2,

          ruleId:
            "SAST-002",

          name:
            "Path Traversal",

          severity:
            "high",

          confidence:
            "medium",

          filePath:
            "src/FileUtil.js",

          line:
            42,

          message:
            "사용자 입력 경로가 검증 없이 파일 접근에 사용되고 있습니다.",

          evidence:
            "fs.readFileSync(basePath + inputPath);",

          recommendation:
            "파일 경로를 정규화하고 허용된 작업 경로 내부인지 검증한 후 파일에 접근하세요.",
        },

        {
          id: 3,

          ruleId:
            "SAST-003",

          name:
            "Cross-Site Scripting",

          severity:
            "medium",

          confidence:
            "high",

          filePath:
            "src/Board.js",

          line:
            127,

          message:
            "외부 입력값이 HTML에 직접 출력되고 있습니다.",

          evidence:
            "element.innerHTML = userInput;",

          recommendation:
            "사용자 입력값을 안전하게 이스케이프하거나 textContent와 같은 안전한 DOM API를 사용하세요.",
        },

        {
          id: 4,

          ruleId:
            "SAST-004",

          name:
            "Hardcoded Credential",

          severity:
            "low",

          confidence:
            "high",

          filePath:
            "src/config.js",

          line:
            10,

          message:
            "소스 코드에서 인증 정보로 추정되는 값이 발견되었습니다.",

          evidence:
            'password = "example-password";',

          recommendation:
            "인증 정보는 소스 코드에 직접 저장하지 말고 환경 변수 또는 별도의 비밀정보 저장소를 사용하세요.",
        },
      ],
    },
  },

  {
    id: 4,

    name: "Project D",

    description:
      "분석 실패 상태 확인을 위한 테스트 프로젝트입니다.",

    language: "Java",

    sourceType: "upload",

    sourceFileName:
      "project-d-source.zip",

    repositoryUrl: "",

    internalPath: "",

    createdAt:
      "2026-08-25 13:40",

    status: "failed",

    failureReason:
      "분석 엔진 실행 중 오류가 발생했습니다.",

    logs:
      "10:01 분석 작업 시작\n" +
      "10:02 분석 엔진 실행\n" +
      "10:03 분석 엔진 오류 발생",

    assignedUserIds: [],
  },
];


function Dashboard() {

  const {
    user,
    logout,
  } = useAuth();


  /* ========================================
     현재 선택된 SideBar 메뉴
  ======================================== */

  const [
    selectedMenu,
    setSelectedMenu,
  ] = useState("summary");


  /* ========================================
     공통 사용자 State
  ======================================== */

  const [
    users,
    setUsers,
  ] = useState(initialUsers);


  /* ========================================
     공통 프로젝트 State
  ======================================== */

  const [
    projects,
    setProjects,
  ] = useState(initialProjects);


  /* ========================================
     로그아웃
  ======================================== */

  const handleLogout = async () => {

    await logout();
  };


  /* ========================================
     현재 메뉴 제목
  ======================================== */

  const getMenuTitle = () => {

    switch (selectedMenu) {

      case "users":
        return "사용자 관리";

      case "projects":

        return user.role === "admin"
          ? "프로젝트 관리"
          : "프로젝트 조회";

      case "mypage":
        return "마이페이지";

      case "summary":

      default:
        return "요약";
    }
  };


  /* ========================================
     Main Content
  ======================================== */

  const renderContent = () => {


    /* ====================================
       관리자
    ==================================== */

    if (
      user.role === "admin"
    ) {

      switch (selectedMenu) {

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
            />

          );


        case "mypage":

          return (
            <MyPage />
          );


        case "summary":

        default:

          return (
            <AdminSummary
              users={users}
              projects={projects}
            />
          );
      }
    }


    /* ====================================
       일반 사용자

       프로젝트 조회는
       이후 구현
    ==================================== */

    switch (selectedMenu) {

      case "mypage":

        return (
          <MyPage />
        );


      case "projects":

        return (

          <div>

            일반 사용자 프로젝트 조회 화면은
            이후 구현합니다.

          </div>

        );


      case "summary":

      default:

        return (

          <div>
            일반 사용자 요약
          </div>

        );
    }
  };


  return (

    <div className="dashboard-layout">


      <SideBar
        role={
          user.role
        }

        selectedMenu={
          selectedMenu
        }

        onMenuChange={
          setSelectedMenu
        }
      />


      <div className="dashboard-main">


        <div className="dashboard-topbar">


          <div className="dashboard-page-title">

            {
              getMenuTitle()
            }

          </div>


          <div className="dashboard-user">


            <span className="dashboard-username">

              {
                user.username
              }

            </span>


            <button
              className="logout-button"

              onClick={
                handleLogout
              }
            >
              로그아웃
            </button>


          </div>


        </div>


        <main className="dashboard-content">

          {
            renderContent()
          }

        </main>


      </div>


    </div>
  );
}


export default Dashboard;