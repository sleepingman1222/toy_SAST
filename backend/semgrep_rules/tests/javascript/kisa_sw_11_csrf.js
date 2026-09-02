function unsafe(app, handler) {
  // ruleid: kisa.sw11.javascript.state-changing-route-review
  app.post("/transfer", handler);
}

function safe(app, csrf, handler) {
  // ok: kisa.sw11.javascript.state-changing-route-review
  app.post("/transfer", csrf, handler);
}
