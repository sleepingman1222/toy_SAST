function unsafe(req) {
  // ruleid: kisa.sw15.javascript.external-input-controls-security-decision
  return req.body.role === "admin";
}
function safe(req) {
  // ok: kisa.sw15.javascript.external-input-controls-security-decision
  return req.user && req.user.role === "admin";
}
