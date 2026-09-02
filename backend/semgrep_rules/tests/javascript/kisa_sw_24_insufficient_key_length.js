const crypto = require("crypto");
function unsafe() {
  // ruleid: kisa.sw24.javascript.insufficient-rsa-key-length
  return crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
}
function safe() {
  // ok: kisa.sw24.javascript.insufficient-rsa-key-length
  return crypto.generateKeyPairSync("rsa", { modulusLength: 3072 });
}
