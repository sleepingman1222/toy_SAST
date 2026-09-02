function unsafe() {
  try {
    return risky();
  } catch (e) {
    // ruleid: kisa.sw38.javascript.overbroad-exception-default-return
    return null;
  }
}
function safe() {
  // ok: kisa.sw38.javascript.overbroad-exception-default-return
  return risky();
}
function risky() { return {}; }
