const fs = require("fs");
function unsafe(path) {
  // ruleid: kisa.sw20.javascript.world-writable-permission
  fs.chmodSync(path, 0o777);
}
function safe(path) {
  // ok: kisa.sw20.javascript.world-writable-permission
  fs.chmodSync(path, 0o600);
}
