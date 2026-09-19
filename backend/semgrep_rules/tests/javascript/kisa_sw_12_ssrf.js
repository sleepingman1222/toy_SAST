const axios = require("axios");
const http = require("http");
const https = require("https");
const undici = require("undici");


function unsafeAxiosGet(req) {
  const url = req.query.url;

  // ruleid: kisa.sw12.javascript.external-input-to-http-client
  return axios.get(url);
}


function unsafeAxiosMethod(req) {
  const url = req.body["callbackUrl"];

  // ruleid: kisa.sw12.javascript.external-input-to-http-client
  return axios.post(url, { status: "ready" });
}


function unsafeFetchMultistep(req) {
  const target = req.params.url;
  const copiedTarget = target;

  // ruleid: kisa.sw12.javascript.external-input-to-http-client
  return fetch(copiedTarget);
}


function unsafeNodeHttp(req) {
  const target = req.headers["x-target-url"];

  // ruleid: kisa.sw12.javascript.external-input-to-http-client
  return http.request(target);
}


function unsafeNodeHttps(req) {
  const target = req.get("X-Target-URL");

  // ruleid: kisa.sw12.javascript.external-input-to-http-client
  return https.get(target);
}


function unsafeUndici(req) {
  const target = req.query["target"];

  // ruleid: kisa.sw12.javascript.external-input-to-http-client
  return undici.request(target);
}


function safeHardcodedAxios() {
  // ok: kisa.sw12.javascript.external-input-to-http-client
  return axios.get("https://api.example.com/status");
}


function safeHardcodedFetch() {
  // ok: kisa.sw12.javascript.external-input-to-http-client
  return fetch("https://api.example.com/status");
}
