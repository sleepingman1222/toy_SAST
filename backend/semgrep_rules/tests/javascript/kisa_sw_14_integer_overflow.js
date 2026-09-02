function unsafe(req) {
  const value = req.query.value;
  // ruleid: kisa.sw14.javascript.external-input-to-bitwise-int
  return value | 0;
}
function safe(req) {
  const value = Number(req.query.value);
  if (!Number.isSafeInteger(value)) throw new Error("invalid");
  // ok: kisa.sw14.javascript.external-input-to-bitwise-int
  return value;
}
