import java.security.Signature;
class kisa_sw_27_improper_signature_verification {
    void unsafe(Signature signature, byte[] sig) throws Exception {
        // ruleid: kisa.sw27.java.signature-result-ignored-review
        signature.verify(sig);
    }
    boolean safe(Signature signature, byte[] sig) throws Exception {
        // ok: kisa.sw27.java.signature-result-ignored-review
        return signature.verify(sig);
    }
}
