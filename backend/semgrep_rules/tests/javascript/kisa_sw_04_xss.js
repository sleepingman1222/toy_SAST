function unsafeExpress(req, res) {
  const value =
    req.query.q;

  // ruleid: kisa.sw04.javascript.external-input-to-html-response
  return res.send(value);
}


function unsafeExpressTemplate(req, res) {
  const name =
    req.body.name;

  const html =
    `<h1>Hello ${name}</h1>`;

  // ruleid: kisa.sw04.javascript.external-input-to-html-response
  return res.send(html);
}


function unsafeInnerHtml(req, element) {
  const value =
    req.params.value;

  // ruleid: kisa.sw04.javascript.external-input-to-html-response
  element.innerHTML = value;
}


function unsafeLocationHash(element) {
  const fragment =
    window.location.hash;

  const copied =
    fragment;

  // ruleid: kisa.sw04.javascript.external-input-to-html-response
  element.outerHTML = copied;
}


function unsafeInsertAdjacentHtml(req, element) {
  const value =
    req.query.html;

  // ruleid: kisa.sw04.javascript.external-input-to-html-response
  element.insertAdjacentHTML("beforeend", value);
}


function unsafeDocumentWrite(req) {
  const value =
    req.query.value;

  // ruleid: kisa.sw04.javascript.external-input-to-html-response
  document.write(value);
}


function unsafeUrlEncodingIsNotHtmlEscaping(req, res) {
  const value =
    req.query.q;

  const encoded =
    encodeURIComponent(value);

  // ruleid: kisa.sw04.javascript.external-input-to-html-response
  return res.send(encoded);
}


function safeTextContent(req, element) {
  const value =
    req.query.q;

  // ok: kisa.sw04.javascript.external-input-to-html-response
  element.textContent = value;
}


function safeDomPurify(req, element) {
  const value =
    req.query.html;

  const safe =
    DOMPurify.sanitize(value);

  // ok: kisa.sw04.javascript.external-input-to-html-response
  element.innerHTML = safe;
}


function safeHardcoded(res) {
  // ok: kisa.sw04.javascript.external-input-to-html-response
  return res.send("<h1>Hello</h1>");
}


function safeJson(req, res) {
  const value =
    req.query.q;

  // ok: kisa.sw04.javascript.external-input-to-html-response
  return res.json({
    value,
  });
}
