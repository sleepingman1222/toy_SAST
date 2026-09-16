async function unsafeConcat(db, req) {
  const userId =
    req.query.id;

  // ruleid: kisa.sw01.javascript.sql-client-string-built-query
  return db.query("SELECT * FROM users WHERE id = " + userId);
}


async function unsafeTemplate(db, req) {
  const username =
    req.body.username;

  // ruleid: kisa.sw01.javascript.sql-client-string-built-query
  return db.query(`SELECT * FROM users WHERE username = '${username}'`);
}


async function unsafeIntermediate(db, req) {
  const status =
    req.params.status;

  const sql =
    "SELECT * FROM users WHERE status = '" + status + "'";

  const copiedSql =
    sql;

  // ruleid: kisa.sw01.javascript.sql-client-string-built-query
  return db.execute(copiedSql);
}


async function unsafeDirectSql(db, req) {
  const sql =
    req.body.sql;

  // ruleid: kisa.sw01.javascript.sql-client-string-built-query
  return db.query(sql);
}


async function unsafeRaw(db, req) {
  const orderBy =
    req.query.sort;

  const sql =
    `SELECT * FROM users ORDER BY ${orderBy}`;

  // ruleid: kisa.sw01.javascript.sql-client-string-built-query
  return db.raw(sql);
}


async function safeMysqlBinding(db, req) {
  const userId =
    req.query.id;

  // ok: kisa.sw01.javascript.sql-client-string-built-query
  return db.query(
    "SELECT * FROM users WHERE id = ?",
    [userId]
  );
}


async function safePgBinding(db, req) {
  const userId =
    req.query.id;

  // ok: kisa.sw01.javascript.sql-client-string-built-query
  return db.query(
    "SELECT * FROM users WHERE id = $1",
    [userId]
  );
}


async function safeHardcoded(db) {
  // ok: kisa.sw01.javascript.sql-client-string-built-query
  return db.query("SELECT id, name FROM users");
}


async function safeStructuredOrm(User, req) {
  const userId =
    req.query.id;

  // ok: kisa.sw01.javascript.sql-client-string-built-query
  return User.findOne({
    where: {
      id: userId,
    },
  });
}
