const fs = require("fs");
const path = require("path");

function unsafe(req) {
  const file = req.query.file;
  // ruleid: kisa.sw03.javascript.external-input-to-file-path
  return fs.readFileSync(file, "utf8");
}

function safe(req, base) {
  const name = path.basename(req.query.file);
  // ok: kisa.sw03.javascript.external-input-to-file-path
  return fs.readFileSync(path.join(base, name), "utf8");
}
