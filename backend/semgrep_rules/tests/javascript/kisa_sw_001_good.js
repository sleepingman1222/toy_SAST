function findUser(
  req,
  db
) {

  const id =
    req.query.id;

  const query =
    "SELECT * FROM users WHERE id = ?";

  db.query(
    query,
    [
      id,
    ]
  );
}