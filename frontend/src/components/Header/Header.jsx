import "./Header.css";


function Header({
  username,
  onLogout,
}) {

  return (
    <header className="header">

      <div className="header-title">
        Dashboard
      </div>


      <div className="header-user">

        <span className="username">
          {username}
        </span>


        <button
          className="logout-button"
          onClick={onLogout}
        >
          로그아웃
        </button>

      </div>

    </header>
  );
}


export default Header;