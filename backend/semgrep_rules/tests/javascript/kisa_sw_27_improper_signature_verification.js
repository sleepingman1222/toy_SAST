const jwt = require("jsonwebtoken");
function unsafe(token) {
  // ruleid: kisa.sw27.javascript.decode-without-signature-verification
  return jwt.decode(token);
}
function safe(token, key) {
  // ok: kisa.sw27.javascript.decode-without-signature-verification
  return jwt.verify(token, key, { algorithms: ["RS256"] });
}
