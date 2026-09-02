function escapeHtml(v) {
  return String(v).replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function unsafe(req, res) {
  const q = req.query.q;
  // ruleid: kisa.sw04.javascript.external-input-to-html-response
  res.send(q);
}

function safe(req, res) {
  const q = escapeHtml(req.query.q);
  // ok: kisa.sw04.javascript.external-input-to-html-response
  res.send(q);
}
