class kisa_sw_38_improper_exception_handling {
    Object unsafe() {
        try {
            return risky();
        } catch (Exception e) {
            // ruleid: kisa.sw38.java.overbroad-exception-default-return
            return null;
        }
    }
    Object safe() {
        // ok: kisa.sw38.java.overbroad-exception-default-return
        return risky();
    }
    Object risky() { return new Object(); }
}
