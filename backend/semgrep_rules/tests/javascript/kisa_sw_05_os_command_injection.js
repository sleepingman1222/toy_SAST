const child_process = require("child_process");

function unsafe(req) {
  const host = req.query.host;
  // ruleid: kisa.sw05.javascript.external-input-to-command
  child_process.exec("ping " + host);
}

function safe(req) {
  const host = req.query.host;
  // ok: kisa.sw05.javascript.external-input-to-command
  child_process.execFile("ping", [host]);
}
