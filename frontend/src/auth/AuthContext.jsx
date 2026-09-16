import {
  useEffect,
  useState,
} from "react";

import {
  authFetch,
} from "../api/client";

import {
  initializeCsrf,
  logoutRequest,
} from "../api/authApi";

import {
  AuthContext,
} from "./authContext";


export function AuthProvider({ children }) {
  const [user, setUser] =
    useState(null);

  const [accessToken, setAccessToken] =
    useState(null);

  const [loading, setLoading] =
    useState(true);


  useEffect(() => {
    const restoreUser = async () => {
      try {
        // 1. CSRF Cookie 준비
        await initializeCsrf();

        // 2. 로그인 상태 복구
        const response = await authFetch(
          "/api/me/",
          null,
          setAccessToken
        );

        // refresh_token이 없거나
        // 인증에 실패한 경우
        if (!response.ok) {
          setUser(null);
          setAccessToken(null);

          return;
        }

        // 3. 현재 로그인 사용자 조회
        const data =
          await response.json();

        setUser({
          username: data.username,
          role: data.role,
        });

      } catch (error) {
        console.error(
          "로그인 상태 복구 실패:",
          error
        );

        setUser(null);
        setAccessToken(null);

      } finally {
        // 인증 확인이 끝났음을 표시
        setLoading(false);
      }
    };

    restoreUser();

  }, []);


  // 로그인 성공 시 호출
  const login = (
    userData,
    token
  ) => {
    setUser(userData);
    setAccessToken(token);
  };


  // 로그아웃 시 호출
  const logout = async () => {
    try {
      await logoutRequest();

    } catch (error) {
      console.error(
        "로그아웃 요청 실패:",
        error
      );

    } finally {
      setUser(null);
      setAccessToken(null);
    }
  };


  return (
    <AuthContext.Provider
      value={{
        user,
        accessToken,
        loading,

        setAccessToken,

        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
