const crypto = require("crypto");
function unsafe(data) {
  // ruleid: kisa.sw21.javascript.weak-cryptographic-algorithm
  return crypto.createHash("md5").update(data).digest("hex");
}
function safe(data) {
  // ok: kisa.sw21.javascript.weak-cryptographic-algorithm
  return crypto.createHash("sha256").update(data).digest("hex");
}
