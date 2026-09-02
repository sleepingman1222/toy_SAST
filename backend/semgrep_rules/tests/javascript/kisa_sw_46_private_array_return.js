class kisa_sw_46_private_array_return {
  #items = [1, 2];

  unsafe() {
    // ruleid: kisa.sw46.javascript.private-array-return-review
    return this.#items;
  }

  safe() {
    // ok: kisa.sw46.javascript.private-array-return-review
    return [...this.#items];
  }
}
