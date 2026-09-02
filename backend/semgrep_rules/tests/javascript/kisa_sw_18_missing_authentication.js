function unsafe(app, handler) {
  // ruleid: kisa.sw18.javascript.route-without-auth-middleware-review
  app.post("/admin/delete", handler);
}

function safe(app, requireAuth, handler) {
  // ok: kisa.sw18.javascript.route-without-auth-middleware-review
  app.post("/admin/delete", requireAuth, handler);
}
