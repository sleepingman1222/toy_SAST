const crypto = require("crypto");
function unsafe() {
  // ruleid: kisa.sw25.javascript.insecure-random-for-security
  return Math.random();
}
function safe() {
  // ok: kisa.sw25.javascript.insecure-random-for-security
  return crypto.randomInt(0, 1000000);
}
