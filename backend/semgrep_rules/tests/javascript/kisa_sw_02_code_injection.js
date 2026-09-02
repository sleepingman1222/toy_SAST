function unsafeEval(req) {
  const code = req.query.code;

  // ruleid: kisa.sw02.javascript.external-input-to-dynamic-code
  return eval(code);
}


function unsafeFunction(req) {
  const body = req.body.script;

  // ruleid: kisa.sw02.javascript.external-input-to-dynamic-code
  const fn = new Function(body);

  return fn();
}


function safeMapping(req) {
  const action = req.query.action;

  const handlers = {
    list: () => "list",
    detail: () => "detail",
  };

  // ok: kisa.sw02.javascript.external-input-to-dynamic-code
  return handlers[action]?.();
}
