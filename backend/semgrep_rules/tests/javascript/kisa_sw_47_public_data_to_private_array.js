class kisa_sw_47_public_data_to_private_array {
  #items;
  constructor(items) {
    // ruleid: kisa.sw47.javascript.public-array-assigned-to-private-field
    this.#items = items;
  }
}

class Safe47 {
  #items;
  constructor(items) {
    // ok: kisa.sw47.javascript.public-array-assigned-to-private-field
    this.#items = [...items];
  }
}
