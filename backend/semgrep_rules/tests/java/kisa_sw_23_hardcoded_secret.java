class kisa_sw_23_hardcoded_secret {
    // ruleid: kisa.sw23.java.hardcoded-sensitive-value
    String password = "hardcoded-password";

    // ok: kisa.sw23.java.hardcoded-sensitive-value
    String safePassword = System.getenv("APP_PASSWORD");
}
