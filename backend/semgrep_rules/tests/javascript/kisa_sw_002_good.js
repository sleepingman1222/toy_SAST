function getStatus() {

  return "OK";
}


function getVersion() {

  return "1.0";
}


function execute(
  req
) {

  const action =
    req.query.action;

  const allowedActions = {
    status: getStatus,
    version: getVersion,
  };

  const handler =
    allowedActions[action];

  if (!handler) {

    throw new Error(
      "허용되지 않은 요청입니다."
    );
  }

  return handler();
}
