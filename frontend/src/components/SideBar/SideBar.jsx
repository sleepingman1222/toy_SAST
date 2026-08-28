import "./SideBar.css";

function SideBar({ role }) {
  return (
    <aside className="sidebar">

      <div className="sidebar-logo">
        MySAST
      </div>

      <nav className="sidebar-menu">

        <button className="sidebar-menu-item">
          요약
        </button>

        {role === "admin" && (
          <>
            <button className="sidebar-menu-item">
              사용자 관리
            </button>

            <button className="sidebar-menu-item">
              프로젝트 관리
            </button>

            <button className="sidebar-menu-item">
              시스템 설정
            </button>
          </>
        )}

        {role === "user" && (
          <>
            <button className="sidebar-menu-item">
              내 프로젝트
            </button>

            <button className="sidebar-menu-item">
              내 정보
            </button>
          </>
        )}

      </nav>

    </aside>
  );
}

export default SideBar;