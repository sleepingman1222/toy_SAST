function unsafe(native, handle) {
  native.free(handle);
  // ruleid: kisa.sw41.javascript.native-handle-use-after-free-review
  return native.read(handle);
}
function safe(native, handle) {
  const value = native.read(handle);
  native.free(handle);
  // ok: kisa.sw41.javascript.native-handle-use-after-free-review
  return value;
}
