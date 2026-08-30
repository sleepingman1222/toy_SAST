import {
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import "./UserDetail.css";


function UserDetail({
  user,
  onBack,
  onToggleStatus,
  onDelete,
}) {

  const {
    user:
      loginUser,
  } = useAuth();


  const [
    showStatusModal,
    setShowStatusModal,
  ] = useState(false);


  const [
    statusChanging,
    setStatusChanging,
  ] = useState(false);


  const [
    showDeleteModal,
    setShowDeleteModal,
  ] = useState(false);


  const [
    deletingUser,
    setDeletingUser,
  ] = useState(false);


  const [
    deleteError,
    setDeleteError,
  ] = useState("");


  /* ========================================
     현재 로그인 사용자 확인
  ======================================== */

  const isCurrentUser =
    loginUser?.id != null
      ? (
          loginUser.id ===
          user.id
        )
      : (
          loginUser?.username ===
          user.username
        );


  /* ========================================
     역할 표시
  ======================================== */

  const getRoleText = (
    role
  ) => {

    if (
      role ===
      "admin"
    ) {

      return "관리자";
    }


    return "일반 사용자";
  };


  /* ========================================
     상태 버튼
  ======================================== */

  const handleStatusButton =
    () => {

      if (
        isCurrentUser
      ) {

        return;
      }


      setShowStatusModal(
        true
      );
    };


  /* ========================================
     상태 변경 확정
  ======================================== */

  const handleStatusConfirm =
    async () => {

      if (
        statusChanging
      ) {

        return;
      }


      setStatusChanging(
        true
      );


      try {

        await onToggleStatus(
          user.id
        );


        setShowStatusModal(
          false
        );

      } catch (error) {

        console.error(
          "사용자 상태 변경 실패:",
          error
        );


        window.alert(
          error.message ||
          "사용자 상태 변경에 실패했습니다."
        );

      } finally {

        setStatusChanging(
          false
        );
      }
    };


  /* ========================================
     계정 삭제 Modal 열기
  ======================================== */

  const handleDeleteButton =
    () => {

      if (
        isCurrentUser
      ) {

        return;
      }


      setDeleteError(
        ""
      );


      setShowDeleteModal(
        true
      );
    };


  /* ========================================
     계정 삭제 Modal 닫기
  ======================================== */

  const handleCloseDeleteModal =
    () => {

      if (
        deletingUser
      ) {

        return;
      }


      setShowDeleteModal(
        false
      );


      setDeleteError(
        ""
      );
    };


  /* ========================================
     계정 삭제 확정
  ======================================== */

  const handleDeleteConfirm =
    async () => {

      if (
        deletingUser ||
        isCurrentUser
      ) {

        return;
      }


      setDeletingUser(
        true
      );


      setDeleteError(
        ""
      );


      try {

        await onDelete(
          user.id
        );

      } catch (error) {

        console.error(
          "사용자 삭제 실패:",
          error
        );


        setDeleteError(
          error.message ||
          "사용자 삭제에 실패했습니다."
        );


        setDeletingUser(
          false
        );
      }
    };


  /* ========================================
     화면
  ======================================== */

  return (

    <div className="user-detail">

      <button
        type="button"

        className="user-detail-back-button"

        onClick={
          onBack
        }
      >
        ← 목록으로
      </button>


      <div className="user-detail-header">

        <h2>
          사용자 상세 정보
        </h2>

        <p>
          사용자 계정 정보와
          프로젝트 할당 현황을
          확인할 수 있습니다.
        </p>

      </div>


      {/* ===================================
          계정 정보
      =================================== */}

      <section className="user-detail-section">

        <div className="user-detail-section-header">

          <h3>
            계정 정보
          </h3>

        </div>


        <div className="user-detail-card">

          <div className="user-detail-row">

            <div className="user-detail-label">
              아이디
            </div>

            <div className="user-detail-value">
              {
                user.username
              }
            </div>

          </div>


          <div className="user-detail-row">

            <div className="user-detail-label">
              역할
            </div>

            <div className="user-detail-value">

              <span
                className={
                  user.role ===
                  "admin"
                    ? "user-role admin"
                    : "user-role user"
                }
              >

                {
                  getRoleText(
                    user.role
                  )
                }

              </span>

            </div>

          </div>


          <div className="user-detail-row">

            <div className="user-detail-label">
              상태
            </div>

            <div className="user-detail-value">

              <span
                className={
                  user.isActive
                    ? "user-detail-status active"
                    : "user-detail-status inactive"
                }
              >

                {
                  user.isActive
                    ? "활성"
                    : "비활성"
                }

              </span>

            </div>

          </div>


          <div className="user-detail-row">

            <div className="user-detail-label">
              생성일
            </div>

            <div className="user-detail-value">

              {
                user.createdAt ||
                "-"
              }

            </div>

          </div>

        </div>

      </section>


      {/* ===================================
          할당 프로젝트
      =================================== */}

      {
        user.role !==
        "admin" && (

          <section className="user-detail-section">

            <div className="user-detail-section-header">

              <h3>

                할당 프로젝트

                <span>

                  {
                    ` (${user.assignedProjects.length})`
                  }

                </span>

              </h3>


              <p>
                프로젝트 접근 권한은
                프로젝트 관리에서 변경할 수 있습니다.
              </p>

            </div>


            <div className="assigned-project-card">

              {
                user.assignedProjects.length > 0
                  ? (

                    <div className="assigned-project-list">

                      {
                        user.assignedProjects.map(
                          (project) => (

                            <div
                              className="assigned-project-item"

                              key={
                                project.id
                              }
                            >

                              <span className="assigned-project-name">

                                {
                                  project.name
                                }

                              </span>

                            </div>

                          )
                        )
                      }

                    </div>

                  )
                  : (

                    <div className="assigned-project-empty">

                      할당된 프로젝트가
                      없습니다.

                    </div>

                  )
              }

            </div>

          </section>

        )
      }


      {/* ===================================
          계정 상태
      =================================== */}

      <section className="user-detail-section">

        <div className="user-detail-section-header">

          <h3>
            계정 상태
          </h3>

          <p>
            계정의 시스템 이용 여부를
            관리합니다.
          </p>

        </div>


        <div className="user-account-control">

          <div>

            <strong>

              {
                user.isActive
                  ? "활성 계정"
                  : "비활성 계정"
              }

            </strong>


            <p>

              {
                user.isActive
                  ? "현재 시스템에 로그인할 수 있는 계정입니다."
                  : "현재 시스템 로그인이 제한된 계정입니다."
              }

            </p>

          </div>


          <button
            type="button"

            className={
              user.isActive
                ? "user-disable-button"
                : "user-enable-button"
            }

            disabled={
              isCurrentUser ||
              statusChanging
            }

            onClick={
              handleStatusButton
            }
          >

            {
              user.isActive
                ? "비활성화"
                : "활성화"
            }

          </button>

        </div>


        {
          isCurrentUser && (

            <div className="current-user-notice">

              현재 로그인 중인 계정의
              상태는 변경할 수 없습니다.

            </div>

          )
        }

      </section>


      {/* ===================================
          위험 작업
      =================================== */}

      <section className="user-detail-section">

        <div className="user-detail-section-header">

          <h3>
            위험 작업
          </h3>

          <p>
            사용자 계정을 영구적으로 삭제합니다.
          </p>

        </div>


        <div className="user-danger-card">

          <div>

            <strong>
              계정 삭제
            </strong>

            <p>
              계정을 삭제하면 해당 사용자의 프로젝트 접근 권한도 함께 제거됩니다.
              프로젝트 생성 또는 분석 이력 등 보존해야 할 기록이 연결된 계정은 삭제할 수 없습니다.
            </p>

          </div>


          <button
            type="button"

            className="user-delete-button"

            disabled={
              isCurrentUser ||
              deletingUser
            }

            onClick={
              handleDeleteButton
            }
          >
            계정 삭제
          </button>

        </div>


        {
          isCurrentUser && (

            <div className="current-user-notice">

              현재 로그인 중인 계정은
              삭제할 수 없습니다.

            </div>

          )
        }

      </section>


      {/* ===================================
          계정 삭제 Modal
      =================================== */}

      {
        showDeleteModal && (

          <div className="user-status-modal-overlay">

            <div className="user-status-modal">

              <div className="user-status-modal-header">

                <h2>
                  계정 삭제
                </h2>

              </div>


              <div className="user-status-modal-content">

                <p>

                  <strong>
                    {user.username}
                  </strong>

                  {" 계정을 삭제하시겠습니까?"}

                </p>


                <div className="user-delete-modal-notice">

                  삭제한 계정은 복구할 수 없습니다.
                  해당 사용자의 프로젝트 접근 권한은 함께 제거됩니다.
                  프로젝트 생성 또는 분석 이력 등 보존해야 할 기록이 연결되어 있으면
                  계정 삭제가 거부되며 비활성화를 이용해야 합니다.

                </div>


                {
                  deleteError && (

                    <div className="user-delete-error">
                      {deleteError}
                    </div>

                  )
                }

              </div>


              <div className="user-status-modal-actions">

                <button
                  type="button"

                  className="user-status-modal-cancel"

                  disabled={
                    deletingUser
                  }

                  onClick={
                    handleCloseDeleteModal
                  }
                >
                  취소
                </button>


                <button
                  type="button"

                  className="user-delete-modal-confirm"

                  disabled={
                    deletingUser
                  }

                  onClick={
                    handleDeleteConfirm
                  }
                >

                  {
                    deletingUser
                      ? "삭제 중..."
                      : "계정 삭제"
                  }

                </button>

              </div>

            </div>

          </div>

        )
      }


      {/* ===================================
          확인 Modal
      =================================== */}

      {
        showStatusModal && (

          <div className="user-status-modal-overlay">

            <div className="user-status-modal">

              <div className="user-status-modal-header">

                <h2>

                  {
                    user.isActive
                      ? "계정 비활성화"
                      : "계정 활성화"
                  }

                </h2>

              </div>


              <div className="user-status-modal-content">

                <p>

                  <strong>
                    {
                      user.username
                    }
                  </strong>


                  {
                    user.isActive
                      ? " 계정을 비활성화하시겠습니까?"
                      : " 계정을 활성화하시겠습니까?"
                  }

                </p>


                <div className="user-status-modal-notice">

                  {
                    user.isActive
                      ? (
                          "비활성화하면 해당 사용자의 모든 프로젝트 접근 권한이 해제됩니다. 재활성화해도 기존 권한은 자동으로 복구되지 않습니다."
                        )
                      : (
                          "활성화하면 해당 사용자가 다시 시스템에 로그인할 수 있습니다. 이전 프로젝트 접근 권한은 자동으로 복구되지 않습니다."
                        )
                  }

                </div>

              </div>


              <div className="user-status-modal-actions">

                <button
                  type="button"

                  className="user-status-modal-cancel"

                  disabled={
                    statusChanging
                  }

                  onClick={() =>
                    setShowStatusModal(
                      false
                    )
                  }
                >
                  취소
                </button>


                <button
                  type="button"

                  className={
                    user.isActive
                      ? "user-status-modal-disable"
                      : "user-status-modal-enable"
                  }

                  disabled={
                    statusChanging
                  }

                  onClick={
                    handleStatusConfirm
                  }
                >

                  {
                    statusChanging
                      ? "처리 중..."
                      : (
                          user.isActive
                            ? "비활성화"
                            : "활성화"
                        )
                  }

                </button>

              </div>

            </div>

          </div>

        )
      }

    </div>
  );
}


export default UserDetail;