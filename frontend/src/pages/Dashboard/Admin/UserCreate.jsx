import { useState } from "react";

import "./UserCreate.css";


function UserCreate({
  users,
  onCancel,
  onCreate,
}) {

  const [formData, setFormData] =
    useState({
      username: "",
      password: "",
      passwordConfirm: "",
      role: "user",
    });


  const [error, setError] =
    useState("");


  const handleChange = (event) => {

    const {
      name,
      value,
    } = event.target;


    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };


  const handleSubmit = (event) => {

    event.preventDefault();


    const username =
      formData.username.trim();


    if (!username) {

      setError(
        "아이디를 입력해주세요."
      );

      return;
    }


    const duplicated =
      users.some(
        (user) =>
          user.username.toLowerCase() ===
          username.toLowerCase()
      );


    if (duplicated) {

      setError(
        "이미 존재하는 아이디입니다."
      );

      return;
    }


    if (!formData.password) {

      setError(
        "초기 비밀번호를 입력해주세요."
      );

      return;
    }


    if (
      formData.password !==
      formData.passwordConfirm
    ) {

      setError(
        "비밀번호가 일치하지 않습니다."
      );

      return;
    }


    const now =
      new Date();


    const formattedDate =
      `${now.getFullYear()}-` +
      `${String(
        now.getMonth() + 1
      ).padStart(2, "0")}-` +
      `${String(
        now.getDate()
      ).padStart(2, "0")} ` +
      `${String(
        now.getHours()
      ).padStart(2, "0")}:` +
      `${String(
        now.getMinutes()
      ).padStart(2, "0")}`;


    const newUser = {

      id:
        users.length > 0
          ? Math.max(
              ...users.map(
                (user) => user.id
              )
            ) + 1
          : 1,

      username,

      role:
        formData.role,

      isActive: true,

      createdAt:
        formattedDate,

      assignedProjects: [],
    };


    onCreate(newUser);
  };


  return (

    <div className="user-create">

      <button
        className="user-create-back-button"
        onClick={onCancel}
      >
        ← 목록으로
      </button>


      <div className="user-create-header">

        <h2>
          계정 등록
        </h2>

        <p>
          시스템에서 사용할
          사용자 계정을 등록합니다.
        </p>

      </div>


      <form
        className="user-create-form"
        onSubmit={handleSubmit}
      >

        <div className="user-form-group">

          <label htmlFor="username">
            아이디
            <span>*</span>
          </label>

          <input
            id="username"
            name="username"
            type="text"
            value={
              formData.username
            }
            onChange={
              handleChange
            }
            placeholder="사용자 아이디"
          />

        </div>


        <div className="user-form-group">

          <label htmlFor="password">
            초기 비밀번호
            <span>*</span>
          </label>

          <input
            id="password"
            name="password"
            type="password"
            value={
              formData.password
            }
            onChange={
              handleChange
            }
            placeholder="초기 비밀번호"
          />

        </div>


        <div className="user-form-group">

          <label htmlFor="passwordConfirm">
            비밀번호 확인
            <span>*</span>
          </label>

          <input
            id="passwordConfirm"
            name="passwordConfirm"
            type="password"
            value={
              formData.passwordConfirm
            }
            onChange={
              handleChange
            }
            placeholder="비밀번호 확인"
          />

        </div>


        <div className="user-form-group">

          <label htmlFor="role">
            역할
            <span>*</span>
          </label>

          <select
            id="role"
            name="role"
            value={
              formData.role
            }
            onChange={
              handleChange
            }
          >

            <option value="user">
              일반 사용자
            </option>

            <option value="admin">
              관리자
            </option>

          </select>

        </div>


        {
          error && (

            <div className="user-create-error">
              {error}
            </div>

          )
        }


        <div className="user-create-actions">

          <button
            type="button"
            className="user-create-cancel-button"
            onClick={onCancel}
          >
            취소
          </button>


          <button
            type="submit"
            className="user-create-submit-button"
          >
            등록
          </button>

        </div>

      </form>

    </div>

  );
}


export default UserCreate;