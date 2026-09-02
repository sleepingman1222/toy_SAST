const axios = require("axios");
function unsafe(payload) {
  // ruleid: kisa.sw22.javascript.cleartext-http-transport-review
  return axios.post("http://api.example.com/login", payload);
}
function safe(payload) {
  // ok: kisa.sw22.javascript.cleartext-http-transport-review
  return axios.post("https://api.example.com/login", payload);
}
