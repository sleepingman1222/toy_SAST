function unsafe(size) {
  // ruleid: kisa.sw16.javascript.unsafe-buffer-operation-review
  return Buffer.allocUnsafe(size);
}
function safe(size) {
  // ok: kisa.sw16.javascript.unsafe-buffer-operation-review
  return Buffer.alloc(size);
}
