import {
  useState,
} from "react";

import {
  useAuth,
} from "../../../auth/useAuth";

import {
  createUser,
  deleteUser,
  updateUserStatus,
} from "../../../api/api";

import UserCreate from "./UserCreate";
import UserDetail from "./UserDetail";

import "./UserManagement.css";


function UserManagement({
  users,
  setUsers,
  projects,
  setProjects,
  usersLoading,
  usersError,
}) {

  const {
    accessToken,
    setAccessToken,
  } = useAuth();


  /* ========================================
     검색
  ======================================== */

  const [
    search,
    setSearch,
  ] = useState("");


  /* ========================================
     화면 Mode
  ======================================== */

  const [
    viewMode,
    setViewMode,
  ] = useState(
    "list"
  );


  /* ========================================
     선택 사용자 ID
  ======================================== */

  const [
    selectedUserId,
    setSelectedUserId,
  ] = useState(null);


  /* ========================================
     선택 사용자
  ======================================== */

  const selectedUser =
    users.find(
      (user) =>
        user.id ===
        selectedUserId
    ) ||
    null;


  /* ========================================
     할당 프로젝트 조회

     ProjectAccess Backend 연결 전에는
     project.assignedUserIds 기준
  ======================================== */

  const getAssignedProjects = (
    userId
  ) => {

    return projects
      .filter(
        (project) =>
          (
            project.assignedUserIds ||
            []
          ).includes(
            userId
          )
      )
      .map(
        (project) => ({
          id:
            project.id,

          name:
            project.name,
        })
      );
  };


  /* ========================================
     사용자 상세
  ======================================== */

  const handleOpenUser = (
    user
  ) => {

    setSelectedUserId(
      user.id
    );


    setViewMode(
      "detail"
    );
  };


  /* ========================================
     계정 등록 화면
  ======================================== */

  const handleCreateUser =
    () => {

      setViewMode(
        "create"
      );
    };


  /* ========================================
     계정 등록

     POST /api/users/
  ======================================== */

  const handleAddUser =
    async (
      userData
    ) => {

      const newUser =
        await createUser(
          userData,
          accessToken,
          setAccessToken
        );


      setUsers(
        (prevUsers) => [
          newUser,
          ...prevUsers,
        ]
      );


      setViewMode(
        "list"
      );


      return newUser;
    };


  /* ========================================
     활성 / 비활성 상태 변경

     PATCH /api/users/{id}/
  ======================================== */

  const handleToggleUserStatus =
    async (
      userId
    ) => {

      const targetUser =
        users.find(
          (user) =>
            user.id ===
            userId
        );


      if (!targetUser) {

        throw new Error(
          "사용자를 찾을 수 없습니다."
        );
      }


      const nextIsActive =
        !targetUser.isActive;


      const updatedUser =
        await updateUserStatus(
          userId,
          nextIsActive,
          accessToken,
          setAccessToken
        );


      // ------------------------------------
      // User State 갱신
      // ------------------------------------

      setUsers(
        (prevUsers) =>
          prevUsers.map(
            (user) =>
              user.id ===
              updatedUser.id
                ? updatedUser
                : user
          )
      );


      // ------------------------------------
      // 비활성화 시
      // Backend에서 ProjectAccess 삭제
      //
      // ProjectAccess API 연결 전까지
      // Frontend 임시 State도 맞춰줌
      // ------------------------------------

      if (
        !updatedUser.isActive
      ) {

        setProjects(
          (prevProjects) =>
            prevProjects.map(
              (project) => ({

                ...project,

                assignedUserIds:
                  (
                    project.assignedUserIds ||
                    []
                  ).filter(
                    (assignedUserId) =>
                      assignedUserId !==
                      userId
                  ),

              })
            )
        );
      }


      return updatedUser;
    };


  /* ========================================
     계정 삭제

     DELETE /api/users/{id}/
  ======================================== */

  const handleDeleteUser =
    async (
      userId
    ) => {

      const targetUser =
        users.find(
          (user) =>
            user.id ===
            userId
        );


      if (!targetUser) {

        throw new Error(
          "사용자를 찾을 수 없습니다."
        );
      }


      await deleteUser(
        userId,
        accessToken,
        setAccessToken
      );


      // ------------------------------------
      // User State에서 제거
      // ------------------------------------

      setUsers(
        (prevUsers) =>
          prevUsers.filter(
            (user) =>
              user.id !==
              userId
          )
      );


      // ------------------------------------
      // Backend에서는 삭제 시
      // 해당 사용자의 ProjectAccess도 제거
      //
      // Frontend State도 즉시 맞춰줌
      // ------------------------------------

      setProjects(
        (prevProjects) =>
          prevProjects.map(
            (project) => ({

              ...project,

              assignedUserIds:
                (
                  project.assignedUserIds ||
                  []
                ).filter(
                  (assignedUserId) =>
                    assignedUserId !==
                    userId
                ),

            })
          )
      );


      setSelectedUserId(
        null
      );


      setViewMode(
        "list"
      );
    };


  /* ========================================
     검색
  ======================================== */

  const filteredUsers =
    users.filter(
      (user) => {

        const keyword =
          search
            .trim()
            .toLowerCase();


        if (!keyword) {

          return true;
        }


        return (
          user.username
            .toLowerCase()
            .includes(
              keyword
            )
        );
      }
    );


  /* ========================================
     계정 등록 화면
  ======================================== */

  if (
    viewMode ===
    "create"
  ) {

    return (

      <UserCreate
        users={
          users
        }

        onCancel={() =>
          setViewMode(
            "list"
          )
        }

        onCreate={
          handleAddUser
        }
      />

    );
  }


  /* ========================================
     사용자 상세
  ======================================== */

  if (
    viewMode ===
      "detail" &&
    selectedUser
  ) {

    const assignedProjects =
      getAssignedProjects(
        selectedUser.id
      );


    const detailUser = {

      ...selectedUser,

      assignedProjects,
    };


    return (

      <UserDetail
        user={
          detailUser
        }

        onBack={() => {

          setSelectedUserId(
            null
          );


          setViewMode(
            "list"
          );
        }}

        onToggleStatus={
          handleToggleUserStatus
        }

        onDelete={
          handleDeleteUser
        }
      />

    );
  }


  /* ========================================
     사용자 목록
  ======================================== */

  return (

    <div className="user-management">

      <div className="user-management-toolbar">

        <div className="user-management-description">

          등록된 사용자 계정을
          조회하고 관리할 수 있습니다.

        </div>


        <button
          type="button"

          className="user-create-button"

          onClick={
            handleCreateUser
          }
        >
          계정 등록
        </button>

      </div>


      <div className="user-search-area">

        <input
          type="text"

          value={
            search
          }

          placeholder="사용자 아이디 검색"

          onChange={
            (event) =>
              setSearch(
                event.target.value
              )
          }
        />

      </div>


      <div className="user-table-wrapper">

        <table className="user-table">

          <thead>

            <tr>

              <th>
                아이디
              </th>

              <th>
                역할
              </th>

              <th>
                상태
              </th>

              <th>
                할당 프로젝트
              </th>

              <th>
                생성일
              </th>

            </tr>

          </thead>


          <tbody>

            {
              usersLoading
                ? (

                  <tr>

                    <td
                      className="user-empty"
                      colSpan="5"
                    >
                      사용자 목록을 불러오는 중입니다.
                    </td>

                  </tr>

                )

                : usersError
                  ? (

                    <tr>

                      <td
                        className="user-empty"
                        colSpan="5"
                      >
                        {
                          usersError
                        }
                      </td>

                    </tr>

                  )

                  : filteredUsers.length > 0
                    ? (

                      filteredUsers.map(
                        (user) => {

                          const assignedProjects =
                            getAssignedProjects(
                              user.id
                            );


                          return (

                            <tr
                              key={
                                user.id
                              }
                            >

                              <td>

                                <button
                                  type="button"

                                  className="user-name-button"

                                  onClick={() =>
                                    handleOpenUser(
                                      user
                                    )
                                  }
                                >
                                  {
                                    user.username
                                  }
                                </button>

                              </td>


                              <td>

                                {
                                  user.role ===
                                  "admin"
                                    ? "관리자"
                                    : "일반 사용자"
                                }

                              </td>


                              <td>

                                <span
                                  className={
                                    user.isActive
                                      ? "user-status active"
                                      : "user-status inactive"
                                  }
                                >

                                  {
                                    user.isActive
                                      ? "활성"
                                      : "비활성"
                                  }

                                </span>

                              </td>


                              <td>

                                {
                                  user.role ===
                                  "admin"
                                    ? "-"
                                    : `${assignedProjects.length}개`
                                }

                              </td>


                              <td>

                                {
                                  user.createdAt ||
                                  "-"
                                }

                              </td>

                            </tr>

                          );
                        }
                      )

                    )

                    : (

                      <tr>

                        <td
                          className="user-empty"

                          colSpan="5"
                        >
                          등록된 사용자가 없습니다.
                        </td>

                      </tr>

                    )
            }

          </tbody>

        </table>

      </div>

    </div>
  );
}


export default UserManagement;