function unsafe(err, res) {
  // ruleid: kisa.sw36.javascript.exception-detail-to-response
  res.status(500).send(err.stack);
}
function safe(err, res) {
  console.error(err);
  // ok: kisa.sw36.javascript.exception-detail-to-response
  res.status(500).send("internal error");
}
