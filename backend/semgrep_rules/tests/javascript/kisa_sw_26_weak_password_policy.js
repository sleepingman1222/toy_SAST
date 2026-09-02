function unsafe(password) {
  // ruleid: kisa.sw26.javascript.weak-minimum-password-length
  return password.length >= 6;
}
function safe(password) {
  // ok: kisa.sw26.javascript.weak-minimum-password-length
  return password.length >= 12;
}
