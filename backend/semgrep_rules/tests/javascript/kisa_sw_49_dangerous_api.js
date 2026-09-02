function unsafe(data) {
  // ruleid: kisa.sw49.javascript.dangerous-api-use
  return Buffer(data);
}
function safe(data) {
  // ok: kisa.sw49.javascript.dangerous-api-use
  return Buffer.from(data);
}
