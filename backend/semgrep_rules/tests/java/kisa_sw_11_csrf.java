class kisa_sw_11_csrf {
    void unsafe(Object http) {
        // ruleid: kisa.sw11.java.csrf-protection-disabled
        http.csrf().disable();
    }
    void safe(Object http) {
        // ok: kisa.sw11.java.csrf-protection-disabled
        http.csrf();
    }
}
