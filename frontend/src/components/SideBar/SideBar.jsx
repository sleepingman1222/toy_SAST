import "./SideBar.css";


function SideBar({
  role,
  selectedMenu,
  onMenuChange,
}) {

  return (
    <aside className="sidebar">

      <button
        type="button"
        className="sidebar-logo"
        onClick={() =>
          onMenuChange("summary")
        }
      >
        MySAST
      </button>


      <nav className="sidebar-menu">

        <button
          className={
            selectedMenu === "summary"
              ? "sidebar-button active"
              : "sidebar-button"
          }

          onClick={() =>
            onMenuChange("summary")
          }
        >
          요약
        </button>


        {
          role === "admin" && (
            <>

              <button
                className={
                  selectedMenu === "users"
                    ? "sidebar-button active"
                    : "sidebar-button"
                }

                onClick={() =>
                  onMenuChange("users")
                }
              >
                사용자 관리
              </button>


              <button
                className={
                  selectedMenu === "projects"
                    ? "sidebar-button active"
                    : "sidebar-button"
                }

                onClick={() =>
                  onMenuChange("projects")
                }
              >
                프로젝트 관리
              </button>


              <button
                className={
                  selectedMenu === "mypage"
                    ? "sidebar-button active"
                    : "sidebar-button"
                }

                onClick={() =>
                  onMenuChange("mypage")
                }
              >
                마이페이지
              </button>

            </>
          )
        }

      </nav>

    </aside>
  );
}


export default SideBar;