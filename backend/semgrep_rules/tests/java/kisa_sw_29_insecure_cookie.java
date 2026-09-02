import jakarta.servlet.http.Cookie;
class kisa_sw_29_insecure_cookie {
    void unsafe(Cookie cookie) {
        // ruleid: kisa.sw29.java.insecure-cookie-flags
        cookie.setSecure(false);
    }
    void safe(Cookie cookie) {
        // ok: kisa.sw29.java.insecure-cookie-flags
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
    }
}
