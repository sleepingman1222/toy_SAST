function unsafe(items) {
  // ruleid: kisa.sw39.javascript.nullable-search-result-dereference
  return items.find(x => x.active).name;
}
function safe(items) {
  const item = items.find(x => x.active);
  // ok: kisa.sw39.javascript.nullable-search-result-dereference
  return item?.name ?? "";
}
