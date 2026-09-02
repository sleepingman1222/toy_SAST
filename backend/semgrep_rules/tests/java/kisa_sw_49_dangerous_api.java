class kisa_sw_49_dangerous_api {
    void unsafe(Thread t) {
        // ruleid: kisa.sw49.java.dangerous-api-use
        t.stop();
    }
    void safe(Thread t) {
        // ok: kisa.sw49.java.dangerous-api-use
        t.interrupt();
    }
}
