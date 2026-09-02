function unsafe(app, loginHandler) {
  // ruleid: kisa.sw33.javascript.login-route-rate-limit-review
  app.post("/login", loginHandler);
}
function safe(app, loginLimiter, loginHandler) {
  // ok: kisa.sw33.javascript.login-route-rate-limit-review
  app.post("/login", loginLimiter, loginHandler);
}
