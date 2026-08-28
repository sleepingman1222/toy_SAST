import {
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import "./MyPage.css";


function MyPage() {

  const {
    user,
  } = useAuth();


  /*
   * 마이페이지 내부 화면 상태
   *
   * info
   * → 계정 정보 화면
   *
   * password
   * → 비밀번호 변경 화면
   *
   * 지금은 password 화면은
   * 다음 단계에서 구현
   */
  const [
    viewMode,
    setViewMode,
  ] = useState("info");


  /*
   * 비밀번호 변경 버튼
   */
  const handlePasswordChange = () => {

    setViewMode(
      "password"
    );
  };


  /*
   * 비밀번호 변경 화면은
   * 다음 단계에서 구현
   */
  if (
    viewMode === "password"
  ) {

    return (
      <div>
        비밀번호 변경 화면
      </div>
    );
  }


  return (
    <div className="mypage">


      {/* =========================
          계정 정보
      ========================= */}

      <section className="mypage-section">


        <div className="mypage-section-header">

          <div>

            <h2>
              계정 정보
            </h2>

            <p>
              현재 로그인된 계정 정보를
              확인할 수 있습니다.
            </p>

          </div>

        </div>



        <div className="account-info-card">


          {/* 아이디 */}

          <div className="account-info-row">

            <span className="account-info-label">
              아이디
            </span>

            <span className="account-info-value">
              {
                user.username
              }
            </span>

          </div>



          {/* 권한 */}

          <div className="account-info-row">

            <span className="account-info-label">
              권한
            </span>

            <span className="account-info-value">

              {
                user.role === "admin"
                  ? "관리자"
                  : "일반 사용자"
              }

            </span>

          </div>


        </div>



        {/* =========================
            비밀번호 변경 버튼
        ========================= */}

        <div className="mypage-actions">

          <button
            type="button"

            className="password-change-button"

            onClick={
              handlePasswordChange
            }
          >
            비밀번호 변경
          </button>

        </div>


      </section>


    </div>
  );
}


export default MyPage;