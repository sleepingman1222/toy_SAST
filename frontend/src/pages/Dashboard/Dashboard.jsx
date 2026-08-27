import {
  useNavigate,
} from "react-router-dom";

import Header
  from "../../components/Header/Header";

import SideBar
  from "../../components/SideBar/SideBar";

import AdminDashboardContent
  from "./AdminDashboardContent";

import UserDashboardContent
  from "./UserDashboardContent";

import {
  logoutRequest,
} from "../../api/api";

import "./Dashboard.css";


function Dashboard({
  user,
  setUser,
  accessToken,
  setAccessToken,
}) {

  const navigate =
    useNavigate();


  const handleLogout =
    async () => {

      try {

        const response =
          await logoutRequest();


        if (!response.ok) {

          console.error(
            "서버 로그아웃 실패:",
            response.status
          );

        }

      } catch (error) {

        console.error(
          "로그아웃 요청 실패:",
          error
        );

      } finally {

        // Access Token 메모리 제거
        setAccessToken(null);

        // 사용자 제거
        setUser(null);

        // 로그인 화면 이동
        navigate(
          "/login"
        );
      }
    };


  return (
    <div className="dashboard-layout">

      <SideBar
        role={
          user.role
        }
      />


      <div className="dashboard-main">

        <Header
          username={
            user.username
          }

          onLogout={
            handleLogout
          }
        />


        <main className="dashboard-content">

          {
            user.role === "admin"
              ? (
                <AdminDashboardContent />
              )
              : (
                <UserDashboardContent />
              )
          }

        </main>

      </div>

    </div>
  );
}


export default Dashboard;