function execute(
  req
) {

  const code =
    req.query.code;

  return eval(
    code
  );
}
