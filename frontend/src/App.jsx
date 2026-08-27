import {
  useEffect,
  useState,
} from "react";

import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import Login
  from "./pages/Login/Login";

import Dashboard
  from "./pages/Dashboard/Dashboard";

import {
  authFetch,
  initializeCsrf,
} from "./api/api";


function App() {

  // 로그인 사용자
  const [user, setUser] =
    useState(null);

  // Access Token
  // 브라우저 저장소가 아니라
  // React 메모리에만 저장
  const [
    accessToken,
    setAccessToken,
  ] = useState(null);

  // 로그인 상태 복구 중인지
  const [
    loading,
    setLoading,
  ] = useState(true);


  useEffect(() => {

    const restoreUser =
      async () => {

        try {

          // CSRF Cookie 초기화
          await initializeCsrf();


          // accessToken이 null이어도
          // authFetch가 refresh를 시도
          const response =
            await authFetch(
              "/api/me/",
              accessToken,
              setAccessToken
            );


          if (!response.ok) {

            setUser(null);

            setAccessToken(null);

            return;
          }


          const data =
            await response.json();


          setUser({
            username:
              data.username,

            role:
              data.role,
          });

        } catch (error) {

          console.error(
            "로그인 복구 실패:",
            error
          );

          setUser(null);

          setAccessToken(null);

        } finally {

          setLoading(false);

        }
      };


    restoreUser();

  }, []);


  if (loading) {
    return (
      <div>
        Loading...
      </div>
    );
  }


  return (
    <BrowserRouter>

      <Routes>

        <Route
          path="/"
          element={
            <Navigate
              to={
                user
                  ? "/dashboard"
                  : "/login"
              }
              replace
            />
          }
        />


        <Route
          path="/login"
          element={
            user ? (

              <Navigate
                to="/dashboard"
                replace
              />

            ) : (

              <Login
                setUser={
                  setUser
                }

                setAccessToken={
                  setAccessToken
                }
              />

            )
          }
        />


        <Route
          path="/dashboard"
          element={
            user ? (

              <Dashboard
                user={
                  user
                }

                setUser={
                  setUser
                }

                accessToken={
                  accessToken
                }

                setAccessToken={
                  setAccessToken
                }
              />

            ) : (

              <Navigate
                to="/login"
                replace
              />

            )
          }
        />

      </Routes>

    </BrowserRouter>
  );
}


export default App;