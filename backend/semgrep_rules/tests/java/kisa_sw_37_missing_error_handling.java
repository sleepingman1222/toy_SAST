class kisa_sw_37_missing_error_handling {
    void unsafe() {
        try {
            risky();
        } catch (Exception e) {
            // ruleid: kisa.sw37.java.empty-catch-block
        }
    }
    void safe() {
        try {
            risky();
        } catch (Exception e) {
            // ok: kisa.sw37.java.empty-catch-block
            throw new RuntimeException(e);
        }
    }
    void risky() {}
}
