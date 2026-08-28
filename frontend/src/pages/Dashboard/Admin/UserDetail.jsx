import { useState } from "react";

import { useAuth } from "../../../auth/useAuth";

import "./UserDetail.css";


function UserDetail({
  user,
  onBack,
  onToggleStatus,
}) {

  const {
    user: loginUser,
  } = useAuth();


  const [
    showStatusModal,
    setShowStatusModal,
  ] = useState(false);


  const isCurrentUser =
    loginUser?.username ===
    user.username;


  const getRoleText = (role) => {

    if (role === "admin") {
      return "관리자";
    }

    return "일반 사용자";
  };


  const handleStatusButton = () => {

    if (isCurrentUser) {
      return;
    }

    setShowStatusModal(true);
  };


  const handleStatusConfirm = () => {

    onToggleStatus(user.id);

    setShowStatusModal(false);
  };


  return (

    <div className="user-detail">

      <button
        className="user-detail-back-button"
        onClick={onBack}
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
              {user.username}
            </div>

          </div>


          <div className="user-detail-row">

            <div className="user-detail-label">
              역할
            </div>

            <div className="user-detail-value">

              <span
                className={
                  user.role === "admin"
                    ? "user-role admin"
                    : "user-role user"
                }
              >
                {getRoleText(user.role)}
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
              {user.createdAt}
            </div>

          </div>

        </div>

      </section>


      {/* ===================================
          할당 프로젝트
      =================================== */}

      {
        user.role !== "admin" && (

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
                              key={project.id}
                            >

                              <span className="assigned-project-name">
                                {project.name}
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
          계정 상태 관리
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
            className={
              user.isActive
                ? "user-disable-button"
                : "user-enable-button"
            }

            disabled={isCurrentUser}

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
          활성 / 비활성 확인 Modal
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
                    {user.username}
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
                      ? "비활성화된 계정은 시스템에 로그인할 수 없습니다. 기존 프로젝트 할당 정보는 유지됩니다."
                      : "활성화하면 해당 사용자가 다시 시스템에 로그인할 수 있습니다."
                  }

                </div>

              </div>


              <div className="user-status-modal-actions">

                <button
                  className="user-status-modal-cancel"
                  onClick={() =>
                    setShowStatusModal(false)
                  }
                >
                  취소
                </button>


                <button
                  className={
                    user.isActive
                      ? "user-status-modal-disable"
                      : "user-status-modal-enable"
                  }

                  onClick={
                    handleStatusConfirm
                  }
                >

                  {
                    user.isActive
                      ? "비활성화"
                      : "활성화"
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