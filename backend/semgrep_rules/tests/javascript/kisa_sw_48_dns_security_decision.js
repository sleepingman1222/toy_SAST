const dns = require("dns");
function unsafe(host, trusted) {
  dns.lookup(host, (err, address) => {
    // ruleid: kisa.sw48.javascript.dns-result-used-for-security-decision-review
    if (address === trusted) console.log("trusted");
  });
}
function safe(verified) {
  // ok: kisa.sw48.javascript.dns-result-used-for-security-decision-review
  return verified;
}
