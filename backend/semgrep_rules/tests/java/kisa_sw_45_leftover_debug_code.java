class kisa_sw_45_leftover_debug_code {
    void unsafe() {
        // ruleid: kisa.sw45.java.debug-code-leftover
        System.out.println("debug");
    }
    void safe() {
        // ok: kisa.sw45.java.debug-code-leftover
        return;
    }
}
