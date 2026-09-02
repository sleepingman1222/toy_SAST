import java.security.MessageDigest;
class kisa_sw_31_unsalted_hash {
    byte[] unsafe(String password) throws Exception {
        // ruleid: kisa.sw31.java.password-hash-without-salt
        return MessageDigest.getInstance("SHA-256").digest(password.getBytes());
    }
    byte[] safe(String password, byte[] salt) throws Exception {
        // ok: kisa.sw31.java.password-hash-without-salt
        return salt;
    }
}
