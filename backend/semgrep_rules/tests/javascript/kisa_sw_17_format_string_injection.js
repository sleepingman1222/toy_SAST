const util = require("util");
function unsafe(req, value) {
  const fmt = req.query.fmt;
  // ruleid: kisa.sw17.javascript.external-input-as-format-string
  return util.format(fmt, value);
}
function safe(req) {
  const value = req.query.value;
  // ok: kisa.sw17.javascript.external-input-as-format-string
  return util.format("value=%s", value);
}
