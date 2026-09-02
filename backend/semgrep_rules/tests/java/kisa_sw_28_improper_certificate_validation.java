import javax.net.ssl.HostnameVerifier;
class kisa_sw_28_improper_certificate_validation {
    HostnameVerifier unsafe() {
        // ruleid: kisa.sw28.java.certificate-validation-disabled
        return (host, session) -> true;
    }
    HostnameVerifier safe() {
        // ok: kisa.sw28.java.certificate-validation-disabled
        return javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier();
    }
}
