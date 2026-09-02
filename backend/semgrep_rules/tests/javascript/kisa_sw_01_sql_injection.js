async function unsafeQuery(db, userId) {
  // ruleid: kisa.sw01.javascript.sql-client-string-built-query
  return db.query(
    "SELECT * FROM users WHERE id = " + userId
  );
}


async function unsafeExecute(db, username) {
  // ruleid: kisa.sw01.javascript.sql-client-string-built-query
  return db.execute(
    "SELECT * FROM users WHERE username = '" + username + "'"
  );
}


async function safeQuery(db, userId) {
  // ok: kisa.sw01.javascript.sql-client-string-built-query
  return db.query(
    "SELECT * FROM users WHERE id = ?",
    [userId]
  );
}


async function safeExecute(db, username) {
  // ok: kisa.sw01.javascript.sql-client-string-built-query
  return db.execute(
    "SELECT * FROM users WHERE username = ?",
    [username]
  );
}
