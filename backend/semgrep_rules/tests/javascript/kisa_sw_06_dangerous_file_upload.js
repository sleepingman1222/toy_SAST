const fs = require("fs");

function unsafe(file, data) {
  // ruleid: kisa.sw06.javascript.unvalidated-upload-filename
  fs.writeFileSync(file.originalname, data);
}

function safe(file, generatedPath, data) {
  // ok: kisa.sw06.javascript.unvalidated-upload-filename
  fs.writeFileSync(generatedPath, data);
}
