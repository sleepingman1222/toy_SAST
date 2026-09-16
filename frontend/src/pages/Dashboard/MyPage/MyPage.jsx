import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import {
  changeMyPassword,
} from "../../../api/authApi";

import "./MyPage.css";


function MyPage() {

  const {
    user,
    accessToken,
    setAccessToken,
    logout,
  } = useAuth();


  /* ========================================
     Password Modal
  ======================================== */

  const [
    showPasswordModal,
    setShowPasswordModal,
  ] = useState(false);


  /* ========================================
     Password Form
  ======================================== */

  const [
    currentPassword,
    setCurrentPassword,
  ] = useState("");

  const [
    newPassword,
    setNewPassword,
  ] = useState("");

  const [
    newPasswordConfirm,
    setNewPasswordConfirm,
  ] = useState("");


  /* ========================================
     Request State
  ======================================== */

  const [
    changingPassword,
    setChangingPassword,
  ] = useState(false);

  const [
    passwordError,
    setPasswordError,
  ] = useState("");


  /* ========================================
     Role
  ======================================== */

  const roleText =
    user?.role ===
    "admin"
      ? "관리자"
      : "일반 사용자";


  /* ========================================
     Reset
  ======================================== */

  const resetPasswordForm =
    useCallback(
      () => {

        setCurrentPassword(
          ""
        );

        setNewPassword(
          ""
        );

        setNewPasswordConfirm(
          ""
        );

        setPasswordError(
          ""
        );
      },
      []
    );


  /* ========================================
     Modal Open / Close
  ======================================== */

  const handleOpenPasswordModal =
    () => {

      resetPasswordForm();

      setShowPasswordModal(
        true
      );
    };


  const handleClosePasswordModal =
    useCallback(
      () => {

        if (
          changingPassword
        ) {
          return;
        }


        setShowPasswordModal(
          false
        );

        resetPasswordForm();
      },
      [
        changingPassword,
        resetPasswordForm,
      ]
    );


  /* ========================================
     ESC Close
  ======================================== */

  useEffect(
    () => {

      if (
        !showPasswordModal
      ) {
        return undefined;
      }


      const handleKeyDown =
        (event) => {

          if (
            event.key ===
            "Escape"
          ) {

            handleClosePasswordModal();
          }
        };


      window.addEventListener(
        "keydown",
        handleKeyDown
      );


      return () => {

        window.removeEventListener(
          "keydown",
          handleKeyDown
        );
      };
    },
    [
      showPasswordModal,
      handleClosePasswordModal,
    ]
  );


  /* ========================================
     Password Change
  ======================================== */

  const handleChangePassword =
    async (
      event
    ) => {

      event.preventDefault();

      setPasswordError(
        ""
      );


      if (
        !currentPassword ||
        !newPassword ||
        !newPasswordConfirm
      ) {

        setPasswordError(
          "현재 비밀번호, 새 비밀번호, 새 비밀번호 확인을 모두 입력해주세요."
        );

        return;
      }


      if (
        newPassword !==
        newPasswordConfirm
      ) {

        setPasswordError(
          "새 비밀번호와 확인 비밀번호가 일치하지 않습니다."
        );

        return;
      }


      if (
        currentPassword ===
        newPassword
      ) {

        setPasswordError(
          "현재 비밀번호와 다른 새 비밀번호를 입력해주세요."
        );

        return;
      }


      setChangingPassword(
        true
      );


      try {

        const result =
          await changeMyPassword(
            {
              currentPassword,
              newPassword,
              newPasswordConfirm,
            },
            accessToken,
            setAccessToken
          );


        const successMessage =
          result?.message ||
          "비밀번호가 변경되었습니다. 새 비밀번호로 다시 로그인해주세요.";


        resetPasswordForm();

        setShowPasswordModal(
          false
        );


        /*
         * Backend에서 현재 Refresh Token을
         * blacklist하고 Refresh Cookie를 삭제한다.
         *
         * Frontend에서도 현재 Access Token을
         * 즉시 제거하기 위해 공통 logout()을 호출한다.
         */

        window.alert(
          successMessage
        );


        await logout();

      } catch (error) {

        console.error(
          "비밀번호 변경 실패:",
          error
        );


        setPasswordError(
          error.message ||
          "비밀번호 변경에 실패했습니다."
        );

      } finally {

        setChangingPassword(
          false
        );
      }
    };


  /* ========================================
     Render
  ======================================== */

  return (

    <div className="my-page">

      <div className="my-page-header">

        <h2>
          마이페이지
        </h2>

        <p>
          현재 계정 정보를 확인하고
          계정 보안 설정을 관리할 수 있습니다.
        </p>

      </div>


      <div className="my-page-grid">

        {/* =================================
            Account Information
        ================================= */}

        <section className="my-page-card">

          <div className="my-page-card-header">

            <div>

              <h3>
                계정 정보
              </h3>

              <p>
                현재 로그인한 계정입니다.
              </p>

            </div>

          </div>


          <div className="my-page-account-list">

            <div className="my-page-account-item">

              <span>
                아이디
              </span>

              <strong>
                {
                  user?.username ||
                  "-"
                }
              </strong>

            </div>


            <div className="my-page-account-item">

              <span>
                역할
              </span>

              <strong
                className={
                  `my-page-role ${
                    user?.role ===
                    "admin"
                      ? "admin"
                      : "user"
                  }`
                }
              >
                {roleText}
              </strong>

            </div>

          </div>

        </section>


        {/* =================================
            Security
        ================================= */}

        <section className="my-page-card">

          <div className="my-page-card-header">

            <div>

              <h3>
                계정 보안
              </h3>

              <p>
                주기적으로 안전한 비밀번호로
                변경하는 것을 권장합니다.
              </p>

            </div>

          </div>


          <div className="my-page-security-content">

            <div className="my-page-security-description">

              <strong>
                비밀번호
              </strong>

              <span>
                현재 비밀번호를 확인한 뒤
                새 비밀번호로 변경합니다.
              </span>

            </div>


            <button
              type="button"
              className="my-page-password-open-button"
              onClick={
                handleOpenPasswordModal
              }
            >
              비밀번호 변경
            </button>

          </div>

        </section>

      </div>


      {/* ===================================
          Password Change Modal
      =================================== */}

      {
        showPasswordModal && (

          <div
            className="my-page-modal-overlay"
            role="presentation"
            onMouseDown={
              (event) => {

                if (
                  event.target ===
                  event.currentTarget
                ) {

                  handleClosePasswordModal();
                }
              }
            }
          >

            <div
              className="my-page-modal"
              role="dialog"
              aria-modal="true"
              aria-labelledby="password-change-modal-title"
            >

              <div className="my-page-modal-header">

                <div>

                  <h3
                    id="password-change-modal-title"
                  >
                    비밀번호 변경
                  </h3>

                  <p>
                    현재 비밀번호를 확인한 후
                    새 비밀번호를 설정합니다.
                  </p>

                </div>


                <button
                  type="button"
                  className="my-page-modal-close-button"
                  aria-label="비밀번호 변경 창 닫기"
                  disabled={
                    changingPassword
                  }
                  onClick={
                    handleClosePasswordModal
                  }
                >
                  ×
                </button>

              </div>


              <form
                className="my-page-password-form"
                onSubmit={
                  handleChangePassword
                }
              >

                <div className="my-page-form-group">

                  <label
                    htmlFor="current-password"
                  >
                    현재 비밀번호
                  </label>

                  <input
                    id="current-password"
                    type="password"
                    autoComplete="current-password"
                    autoFocus
                    value={
                      currentPassword
                    }
                    disabled={
                      changingPassword
                    }
                    onChange={
                      (event) => {

                        setCurrentPassword(
                          event.target.value
                        );

                        setPasswordError(
                          ""
                        );
                      }
                    }
                    placeholder="현재 비밀번호"
                  />

                </div>


                <div className="my-page-form-group">

                  <label
                    htmlFor="new-password"
                  >
                    새 비밀번호
                  </label>

                  <input
                    id="new-password"
                    type="password"
                    autoComplete="new-password"
                    value={
                      newPassword
                    }
                    disabled={
                      changingPassword
                    }
                    onChange={
                      (event) => {

                        setNewPassword(
                          event.target.value
                        );

                        setPasswordError(
                          ""
                        );
                      }
                    }
                    placeholder="새 비밀번호"
                  />

                  <span className="my-page-password-help">
                    현재 비밀번호와 다른 값을 사용하고,
                    시스템 비밀번호 정책을 충족해야 합니다.
                  </span>

                </div>


                <div className="my-page-form-group">

                  <label
                    htmlFor="new-password-confirm"
                  >
                    새 비밀번호 확인
                  </label>

                  <input
                    id="new-password-confirm"
                    type="password"
                    autoComplete="new-password"
                    value={
                      newPasswordConfirm
                    }
                    disabled={
                      changingPassword
                    }
                    onChange={
                      (event) => {

                        setNewPasswordConfirm(
                          event.target.value
                        );

                        setPasswordError(
                          ""
                        );
                      }
                    }
                    placeholder="새 비밀번호 다시 입력"
                  />

                </div>


                {
                  passwordError && (

                    <div
                      className="my-page-message error"
                      role="alert"
                    >
                      {passwordError}
                    </div>

                  )
                }


                <div className="my-page-modal-actions">

                  <button
                    type="button"
                    className="my-page-modal-cancel-button"
                    disabled={
                      changingPassword
                    }
                    onClick={
                      handleClosePasswordModal
                    }
                  >
                    취소
                  </button>


                  <button
                    type="submit"
                    className="my-page-password-button"
                    disabled={
                      changingPassword
                    }
                  >
                    {
                      changingPassword
                        ? "변경 중..."
                        : "변경"
                    }
                  </button>

                </div>

              </form>

            </div>

          </div>

        )
      }

    </div>
  );
}


export default MyPage;
