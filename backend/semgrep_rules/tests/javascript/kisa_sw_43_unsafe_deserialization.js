const serialize = require("node-serialize");
function unsafe(req) {
  const data = req.body.data;
  // ruleid: kisa.sw43.javascript.external-input-to-unsafe-deserializer
  return serialize.unserialize(data);
}
function safe(req) {
  const data = req.body.data;
  // ok: kisa.sw43.javascript.external-input-to-unsafe-deserializer
  return JSON.parse(data);
}
