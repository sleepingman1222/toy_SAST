function unsafe(req, res) {
  const next = req.query.next;
  // ruleid: kisa.sw07.javascript.external-input-to-redirect
  res.redirect(next);
}
function safe(req, res) {
  // ok: kisa.sw07.javascript.external-input-to-redirect
  res.redirect("/home");
}
