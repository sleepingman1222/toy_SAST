const childProcess =
  require("child_process");

const {
  exec,
  execSync,
} = require("child_process");


function unsafeObjectExec(req) {
  const host =
    req.query.host;

  // ruleid: kisa.sw05.javascript.external-input-to-command
  return childProcess.exec("ping " + host);
}


function unsafeDestructuredExec(req) {
  const host =
    req.body.host;

  const command =
    `nslookup ${host}`;

  // ruleid: kisa.sw05.javascript.external-input-to-command
  return exec(command);
}


function unsafeMultiStep(req) {
  const host =
    req.params.host;

  const command =
    "ping " + host;

  const copiedCommand =
    command;

  // ruleid: kisa.sw05.javascript.external-input-to-command
  return execSync(copiedCommand);
}


function unsafeSpawnShellCommand(req) {
  const command =
    req.query.command;

  // ruleid: kisa.sw05.javascript.external-input-to-command
  return childProcess.spawn(command, [], { shell: true });
}


function unsafeSpawnShellArgument(req) {
  const host =
    req.query.host;

  const args = [
    "-c",
    "1",
    host,
  ];

  // ruleid: kisa.sw05.javascript.external-input-to-command
  return childProcess.spawn("ping", args, { shell: true });
}


function safeSpawnWithoutShell(req) {
  const host =
    req.query.host;

  // ok: kisa.sw05.javascript.external-input-to-command
  return childProcess.spawn(
    "ping",
    [
      "-c",
      "1",
      host,
    ],
    {
      shell: false,
    }
  );
}


function safeExecFile(req) {
  const host =
    req.query.host;

  // ok: kisa.sw05.javascript.external-input-to-command
  return childProcess.execFile(
    "ping",
    [
      "-c",
      "1",
      host,
    ]
  );
}


function safeHardcodedExec() {
  // ok: kisa.sw05.javascript.external-input-to-command
  return childProcess.exec("uptime");
}


function safeUnrelatedMethod(req) {
  const command =
    req.query.command;

  const runner = {
    exec(value) {
      return value;
    },
  };

  // ok: kisa.sw05.javascript.external-input-to-command
  return runner.exec(command);
}
