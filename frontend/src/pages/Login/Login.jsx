import {
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

import {
  useAuth,
} from "../../auth/useAuth";

import "./Login.css";


function Login() {
  const [username, setUsername] =
    useState("");

  const [password, setPassword] =
    useState("");

  const [error, setError] =
    useState("");

  const {
    login,
  } = useAuth();

  const navigate =
    useNavigate();


  const handleLogin = async () => {
    try {
      setError("");

      const response =
        await fetch(
          "/api/login/",
          {
            method: "POST",

            credentials:
              "include",

            headers: {
              "Content-Type":
                "application/json",
            },

            body:
              JSON.stringify({
                username,
                password,
              }),
          }
        );

      const data =
        await response.json();


      if (response.status === 401) {
        setError(
          "아이디 또는 비밀번호가 올바르지 않습니다."
        );

        return;
      }


      if (response.status === 429) {
        setError(
          "로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요."
        );

        return;
      }


      if (!response.ok) {
        setError(
          "로그인 처리 중 오류가 발생했습니다."
        );

        return;
      }


      login(
        {
          username:
            data.username,

          role:
            data.role,
        },

        data.access
      );


      navigate(
        "/dashboard"
      );

    } catch (error) {
      console.error(
        "로그인 실패:",
        error
      );

      setError(
        "서버와 연결할 수 없습니다."
      );
    }
  };


  return (
    <div className="login-page">

      <div className="login-card">

        <h1>
          Login
        </h1>


        <div className="input-group">

          <label>
            아이디
          </label>

          <input
            type="text"

            value={
              username
            }

            onChange={
              (e) =>
                setUsername(
                  e.target.value
                )
            }

            placeholder="아이디를 입력하세요"
          />

        </div>


        <div className="input-group">

          <label>
            비밀번호
          </label>

          <input
            type="password"

            value={
              password
            }

            onChange={
              (e) =>
                setPassword(
                  e.target.value
                )
            }

            placeholder="비밀번호를 입력하세요"
          />

        </div>


        {
          error && (
            <p className="login-error">
              {error}
            </p>
          )
        }


        <button
          className="login-button"

          onClick={
            handleLogin
          }
        >
          로그인
        </button>

      </div>

    </div>
  );
}


export default Login;