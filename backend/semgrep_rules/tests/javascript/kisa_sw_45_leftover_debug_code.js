function unsafe() {
  // ruleid: kisa.sw45.javascript.debug-code-leftover
  debugger;
}
function safe() {
  // ok: kisa.sw45.javascript.debug-code-leftover
  return "ok";
}
