async function unsafe(req, Project) {
  // ruleid: kisa.sw19.javascript.external-id-object-access-review
  return Project.findById(req.params.id);
}

async function safe(req, Project) {
  // ok: kisa.sw19.javascript.external-id-object-access-review
  return Project.findOne({ _id: req.params.id, owner: req.user.id });
}
