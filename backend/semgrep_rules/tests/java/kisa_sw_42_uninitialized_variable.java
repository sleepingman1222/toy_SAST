class kisa_sw_42_uninitialized_variable {
    void unsafe(Consumer c) {
        String value;
        value = null;
        // ruleid: kisa.sw42.java.declaration-without-initializer-review
        c.accept(value);
    }
    void safe(Consumer c) {
        String value = "initialized";
        // ok: kisa.sw42.java.declaration-without-initializer-review
        c.accept(value);
    }
    interface Consumer { void accept(String v); }
}
