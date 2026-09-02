import java.net.URL;
class kisa_sw_22_cleartext_sensitive_data {
    Object unsafe() throws Exception {
        // ruleid: kisa.sw22.java.cleartext-http-transport-review
        return new URL("http://api.example.com/login");
    }
    Object safe() throws Exception {
        // ok: kisa.sw22.java.cleartext-http-transport-review
        return new URL("https://api.example.com/login");
    }
}
