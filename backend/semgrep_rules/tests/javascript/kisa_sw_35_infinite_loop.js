function unsafe() {
  // ruleid: kisa.sw35.javascript.obvious-infinite-loop
  while (true) {
    console.log("loop");
  }
}
function safe(n) {
  // ok: kisa.sw35.javascript.obvious-infinite-loop
  for (let i = 0; i < n; i++) console.log(i);
}
