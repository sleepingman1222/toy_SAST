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
  useAuth,
} from "./auth/useAuth";


function App() {
  const {
    user,
    loading,
  } = useAuth();


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
              <Login />
            )
          }
        />


        <Route
          path="/dashboard"
          element={
            user ? (
              <Dashboard />
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