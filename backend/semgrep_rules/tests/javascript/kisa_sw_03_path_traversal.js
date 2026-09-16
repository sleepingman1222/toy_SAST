const fs =
  require("fs");

const path =
  require("path");


function unsafeDirectRead(req) {
  const filename =
    req.query.file;

  // ruleid: kisa.sw03.javascript.external-input-to-file-path
  return fs.readFileSync(filename, "utf8");
}


function unsafeJoin(req, base) {
  const filename =
    req.params.file;

  const target =
    path.join(base, filename);

  // ruleid: kisa.sw03.javascript.external-input-to-file-path
  return fs.readFile(target, "utf8", () => {});
}


function unsafeResolveOnly(req, base) {
  const filename =
    req.query.file;

  const target =
    path.resolve(base, filename);

  // resolve만으로는 허용 루트 이탈을 막지 않는다.
  // ruleid: kisa.sw03.javascript.external-input-to-file-path
  return fs.writeFileSync(target, "data");
}


function unsafeMultiStep(req) {
  const raw =
    req.body.path;

  const first =
    raw;

  const second =
    first;

  // ruleid: kisa.sw03.javascript.external-input-to-file-path
  return fs.unlinkSync(second);
}


async function unsafePromises(req) {
  const filename =
    req.query.file;

  // ruleid: kisa.sw03.javascript.external-input-to-file-path
  return fs.promises.readFile(filename, "utf8");
}


function safeBasename(req, base) {
  const filename =
    path.basename(req.query.file);

  const target =
    path.join(base, filename);

  // ok: kisa.sw03.javascript.external-input-to-file-path
  return fs.readFileSync(target, "utf8");
}


function safeHardcoded() {
  // ok: kisa.sw03.javascript.external-input-to-file-path
  return fs.readFileSync(
    "/srv/app/public/help.txt",
    "utf8"
  );
}


function safeUnrelatedStorage(req, storage) {
  const filename =
    req.query.file;

  // ok: kisa.sw03.javascript.external-input-to-file-path
  return storage.readFile(filename);
}
