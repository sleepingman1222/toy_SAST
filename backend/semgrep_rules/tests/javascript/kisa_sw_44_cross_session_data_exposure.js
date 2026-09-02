let currentProfile;
function unsafe(req) {
  // ruleid: kisa.sw44.javascript.request-data-to-module-global-review
  currentProfile = req.query.profile;
  return currentProfile;
}
function safe(req) {
  // ok: kisa.sw44.javascript.request-data-to-module-global-review
  return { profile: req.query.profile };
}
