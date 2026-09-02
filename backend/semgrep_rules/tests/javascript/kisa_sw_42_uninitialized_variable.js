function unsafe(use) {
  let value;
  // ruleid: kisa.sw42.javascript.uninitialized-variable-use-review
  use(value);
}
function safe(use) {
  let value = "initialized";
  // ok: kisa.sw42.javascript.uninitialized-variable-use-review
  use(value);
}
