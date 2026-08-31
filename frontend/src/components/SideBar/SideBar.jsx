import "./SideBar.css";


function SideBar({
  role,
  selectedMenu,
  onMenuChange,
}) {

  return (

    <aside className="sidebar">


      {/* ===================================
          Logo
      =================================== */}

      <button
        type="button"

        className="sidebar-logo"

        onClick={() =>
          onMenuChange(
            "summary"
          )
        }
      >
        MySAST
      </button>


      {/* ===================================
          Menu
      =================================== */}

      <nav className="sidebar-menu">


        {/* =================================
            요약

            관리자 / 일반 사용자 공통
        ================================= */}

        <button
          type="button"

          className={
            selectedMenu ===
            "summary"
              ? "sidebar-button active"
              : "sidebar-button"
          }

          onClick={() =>
            onMenuChange(
              "summary"
            )
          }
        >
          요약
        </button>


        {/* =================================
            사용자 관리

            관리자 전용
        ================================= */}

        {
          role === "admin" && (

            <button
              type="button"

              className={
                selectedMenu ===
                "users"
                  ? "sidebar-button active"
                  : "sidebar-button"
              }

              onClick={() =>
                onMenuChange(
                  "users"
                )
              }
            >
              사용자 관리
            </button>

          )
        }


        {/* =================================
            프로젝트

            관리자
            → 프로젝트 관리

            일반 사용자
            → 프로젝트 조회
        ================================= */}

        {
          (
            role === "admin" ||
            role === "user"
          ) && (

            <button
              type="button"

              className={
                selectedMenu ===
                "projects"
                  ? "sidebar-button active"
                  : "sidebar-button"
              }

              onClick={() =>
                onMenuChange(
                  "projects"
                )
              }
            >
              {
                role === "admin"
                  ? "프로젝트 관리"
                  : "프로젝트 조회"
              }
            </button>

          )
        }


        {/* =================================
            마이페이지

            관리자 / 일반 사용자 공통
        ================================= */}

        {
          (
            role === "admin" ||
            role === "user"
          ) && (

            <button
              type="button"

              className={
                selectedMenu ===
                "mypage"
                  ? "sidebar-button active"
                  : "sidebar-button"
              }

              onClick={() =>
                onMenuChange(
                  "mypage"
                )
              }
            >
              마이페이지
            </button>

          )
        }


      </nav>


    </aside>

  );
}


export default SideBar;