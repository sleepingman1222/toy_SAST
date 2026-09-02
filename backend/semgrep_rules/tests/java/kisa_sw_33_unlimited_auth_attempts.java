class kisa_sw_33_unlimited_auth_attempts {
    Object login(AuthManager auth, Object token) {
        // ruleid: kisa.sw33.java.login-handler-rate-limit-review
        return auth.authenticate(token);
    }
    Object health() {
        // ok: kisa.sw33.java.login-handler-rate-limit-review
        return "ok";
    }
    interface AuthManager { Object authenticate(Object token); }
}
