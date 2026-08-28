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
import {
  useAuth,
} from "../../auth/useAuth";

function Dashboard({

}) {

  const {
    user,
    logout,
  } = useAuth();

  const navigate =
    useNavigate();


  const handleLogout =
    async () => {

      await logout();

      navigate(
        "/login"
      );
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