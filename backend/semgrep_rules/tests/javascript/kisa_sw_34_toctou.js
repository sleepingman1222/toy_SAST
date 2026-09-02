const fs = require("fs");
function unsafe(path) {
  if (fs.existsSync(path)) {
    // ruleid: kisa.sw34.javascript.check-then-use-file
    return fs.readFileSync(path, "utf8");
  }
}
function safe(path) {
  // ok: kisa.sw34.javascript.check-then-use-file
  return fs.openSync(path, "wx");
}
