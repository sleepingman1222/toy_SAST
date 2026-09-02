import java.security.KeyPairGenerator;
class kisa_sw_24_insufficient_key_length {
    void unsafe() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        // ruleid: kisa.sw24.java.insufficient-rsa-key-length
        gen.initialize(1024);
    }
    void safe() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        // ok: kisa.sw24.java.insufficient-rsa-key-length
        gen.initialize(3072);
    }
}
