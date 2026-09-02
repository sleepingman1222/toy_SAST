import java.security.MessageDigest;
class kisa_sw_21_weak_crypto {
    Object unsafe() throws Exception {
        // ruleid: kisa.sw21.java.weak-cryptographic-algorithm
        return MessageDigest.getInstance("MD5");
    }
    Object safe() throws Exception {
        // ok: kisa.sw21.java.weak-cryptographic-algorithm
        return MessageDigest.getInstance("SHA-256");
    }
}
