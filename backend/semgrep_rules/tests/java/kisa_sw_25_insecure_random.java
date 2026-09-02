import java.util.Random;
import java.security.SecureRandom;
class kisa_sw_25_insecure_random {
    int unsafe() {
        // ruleid: kisa.sw25.java.insecure-random-for-security
        return new Random().nextInt();
    }
    int safe() {
        // ok: kisa.sw25.java.insecure-random-for-security
        return new SecureRandom().nextInt();
    }
}
