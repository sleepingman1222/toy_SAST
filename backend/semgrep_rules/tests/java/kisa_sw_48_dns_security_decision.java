import java.net.InetAddress;
class kisa_sw_48_dns_security_decision {
    boolean unsafe(String host, String trusted) throws Exception {
        InetAddress addr = InetAddress.getByName(host);
        // ruleid: kisa.sw48.java.dns-result-used-for-security-decision-review
        if (addr.getHostName().equals(trusted)) return true;
        return false;
    }
    boolean safe(boolean certificateVerified) {
        // ok: kisa.sw48.java.dns-result-used-for-security-decision-review
        return certificateVerified;
    }
}
