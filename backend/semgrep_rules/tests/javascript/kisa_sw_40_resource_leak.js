const fs = require("fs");
function unsafe(path) {
  // ruleid: kisa.sw40.javascript.open-file-descriptor-review
  const fd = fs.openSync(path, "r");
  return fd;
}
function safe(path) {
  // ok: kisa.sw40.javascript.open-file-descriptor-review
  return fs.readFileSync(path);
}
