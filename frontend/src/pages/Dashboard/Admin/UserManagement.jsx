import { useState } from "react";

import UserCreate from "./UserCreate";
import UserDetail from "./UserDetail";

import "./UserManagement.css";


function UserManagement({
  users,
  setUsers,
  projects,
}) {

  /* ========================================
     검색
  ======================================== */

  const [
    search,
    setSearch,
  ] = useState("");


  /* ========================================
     화면 Mode

     list
     create
     detail
  ======================================== */

  const [
    viewMode,
    setViewMode,
  ] = useState("list");


  /* ========================================
     선택 사용자 ID

     사용자 객체 자체를 저장하지 않고
     ID만 저장

     이렇게 하면 users State가 변경되어도
     항상 최신 사용자 정보를 가져올 수 있음
  ======================================== */

  const [
    selectedUserId,
    setSelectedUserId,
  ] = useState(null);


  /* ========================================
     현재 선택 사용자
  ======================================== */

  const selectedUser =
    users.find(
      (user) =>
        user.id === selectedUserId
    ) || null;


  /* ========================================
     특정 사용자에게 할당된 프로젝트 조회

     Project.assignedUserIds 기준으로 계산
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
          id: project.id,
          name: project.name,
        })
      );
  };


  /* ========================================
     사용자 상세 열기
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

  const handleCreateUser = () => {

    setViewMode(
      "create"
    );
  };


  /* ========================================
     계정 등록
  ======================================== */

  const handleAddUser = (
    newUser
  ) => {

    /*
     UserCreate에서 혹시
     assignedProjects가 넘어오더라도

     이제 사용자 객체에서는
     프로젝트 관계를 저장하지 않음
    */

    const {
      assignedProjects,
      ...userData
    } = newUser;


    setUsers(
      (prevUsers) => [
        ...prevUsers,
        userData,
      ]
    );


    setViewMode(
      "list"
    );
  };


  /* ========================================
     활성 / 비활성 상태 변경
  ======================================== */

  const handleToggleUserStatus = (
    userId
  ) => {

    setUsers(
      (prevUsers) =>
        prevUsers.map(
          (user) => {

            if (
              user.id !== userId
            ) {
              return user;
            }


            return {
              ...user,

              isActive:
                !user.isActive,
            };
          }
        )
    );
  };


  /* ========================================
     사용자 검색
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


        return user.username
          .toLowerCase()
          .includes(
            keyword
          );
      }
    );


  /* ========================================
     계정 등록 화면
  ======================================== */

  if (
    viewMode === "create"
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
     사용자 상세 화면
  ======================================== */

  if (
    viewMode === "detail" &&
    selectedUser
  ) {

    /*
     프로젝트 관계는 여기에서
     실시간으로 계산한다.

     따라서 ProjectManagement에서
     권한을 변경하면 이 값도 변경됨.
    */

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

      />

    );
  }


  /* ========================================
     사용자 목록
  ======================================== */

  return (

    <div className="user-management">


      {/* ===================================
          상단
      =================================== */}

      <div className="user-management-toolbar">


        <div className="user-management-description">

          등록된 사용자 계정을
          조회하고 관리할 수 있습니다.

        </div>


        <button
          className="user-create-button"

          onClick={
            handleCreateUser
          }
        >
          계정 등록
        </button>


      </div>


      {/* ===================================
          검색
      =================================== */}

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


      {/* ===================================
          사용자 목록
      =================================== */}

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
              filteredUsers.length > 0
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


                          {/* 아이디 */}

                          <td>

                            <button
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


                          {/* 역할 */}

                          <td>

                            {
                              user.role ===
                                "admin"
                                ? "관리자"
                                : "일반 사용자"
                            }

                          </td>


                          {/* 상태 */}

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


                          {/* 할당 프로젝트 */}

                          <td>

                            {
                              user.role ===
                                "admin"
                                ? "-"
                                : `${assignedProjects.length}개`
                            }

                          </td>


                          {/* 생성일 */}

                          <td>
                            {
                              user.createdAt
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
                      검색 결과가 없습니다.
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