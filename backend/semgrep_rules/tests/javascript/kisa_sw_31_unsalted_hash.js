const crypto = require("crypto");
function unsafe(password) {
  // ruleid: kisa.sw31.javascript.password-hash-without-salt
  return crypto.createHash("sha256").update(password).digest("hex");
}
function safe(password, salt) {
  // ok: kisa.sw31.javascript.password-hash-without-salt
  return crypto.scryptSync(password, salt, 64);
}
