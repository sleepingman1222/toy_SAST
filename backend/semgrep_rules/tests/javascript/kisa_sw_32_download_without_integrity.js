const axios = require("axios");
async function unsafe(url) {
  // ruleid: kisa.sw32.javascript.downloaded-code-executed-review
  return eval((await axios.get(url)).data);
}
async function safe(url) {
  const data = (await axios.get(url)).data;
  // ok: kisa.sw32.javascript.downloaded-code-executed-review
  return data;
}
