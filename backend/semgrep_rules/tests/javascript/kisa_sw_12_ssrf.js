const axios = require("axios");
function unsafe(req) {
  const url = req.query.url;
  // ruleid: kisa.sw12.javascript.external-input-to-http-client
  return axios.get(url);
}
function safe() {
  // ok: kisa.sw12.javascript.external-input-to-http-client
  return axios.get("https://api.example.com/status");
}
