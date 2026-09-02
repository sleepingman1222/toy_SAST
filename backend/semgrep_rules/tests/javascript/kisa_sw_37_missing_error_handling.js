function unsafe() {
  try {
    risky();
  } catch (e) {
    // ruleid: kisa.sw37.javascript.empty-catch-block
  }
}
function safe() {
  try {
    risky();
  } catch (e) {
    // ok: kisa.sw37.javascript.empty-catch-block
    throw e;
  }
}
function risky() {}
