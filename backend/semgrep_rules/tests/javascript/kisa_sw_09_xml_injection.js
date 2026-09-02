const xpath = require("xpath");

function unsafe(req, doc) {
  const q = req.query.xpath;
  // ruleid: kisa.sw09.javascript.external-input-to-xpath
  return xpath.select(q, doc);
}
function safe(doc) {
  // ok: kisa.sw09.javascript.external-input-to-xpath
  return xpath.select("/users/user", doc);
}
