function unsafe(req, res) {
  const value = req.query.value;
  // ruleid: kisa.sw13.javascript.external-input-to-response-header
  res.setHeader("X-User", value);
}
function safe(req, res) {
  // ok: kisa.sw13.javascript.external-input-to-response-header
  res.setHeader("X-User", "fixed");
}
