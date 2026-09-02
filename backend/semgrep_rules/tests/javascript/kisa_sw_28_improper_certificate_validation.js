const https = require("https");
function unsafe() {
  // ruleid: kisa.sw28.javascript.certificate-validation-disabled
  return new https.Agent({ rejectUnauthorized: false });
}
function safe() {
  // ok: kisa.sw28.javascript.certificate-validation-disabled
  return new https.Agent({ rejectUnauthorized: true });
}
