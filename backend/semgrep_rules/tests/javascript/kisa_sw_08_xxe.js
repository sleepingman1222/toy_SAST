const libxmljs = require("libxmljs");

function unsafe(xml) {
  // ruleid: kisa.sw08.javascript.unsafe-xml-external-entity
  return libxmljs.parseXml(xml, { noent: true });
}

function safe(xml) {
  // ok: kisa.sw08.javascript.unsafe-xml-external-entity
  return libxmljs.parseXml(xml, { noent: false });
}
