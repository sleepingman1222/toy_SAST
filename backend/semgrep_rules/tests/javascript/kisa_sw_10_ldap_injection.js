function unsafe(req, client) {
  const filter = req.query.filter;
  // ruleid: kisa.sw10.javascript.external-input-to-ldap-filter
  client.search("dc=example,dc=com", { filter }, () => {});
}
function safe(client) {
  // ok: kisa.sw10.javascript.external-input-to-ldap-filter
  client.search("dc=example,dc=com", { filter: "(uid=alice)" }, () => {});
}
