class kisa_sw_26_weak_password_policy {
    boolean unsafe(String password) {
        // ruleid: kisa.sw26.java.weak-minimum-password-length
        return password.length() >= 6;
    }
    boolean safe(String password) {
        // ok: kisa.sw26.java.weak-minimum-password-length
        return password.length() >= 12;
    }
}
