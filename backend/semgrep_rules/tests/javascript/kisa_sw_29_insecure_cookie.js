function unsafe(res) {
  // ruleid: kisa.sw29.javascript.insecure-cookie-flags
  res.cookie("session", "value", { secure: false });
}
function safe(res) {
  // ok: kisa.sw29.javascript.insecure-cookie-flags
  res.cookie("session", "value", { secure: true, httpOnly: true, sameSite: "lax" });
}
