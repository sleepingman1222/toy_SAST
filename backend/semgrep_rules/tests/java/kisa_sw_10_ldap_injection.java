import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;

class kisa_sw_10_ldap_injection {
    Object unsafe(HttpServletRequest req, DirContext ctx) throws Exception {
        String f = req.getParameter("filter");
        // ruleid: kisa.sw10.java.external-input-to-ldap-filter
        return ctx.search("dc=example,dc=com", f, null);
    }
    Object safe(DirContext ctx) throws Exception {
        // ok: kisa.sw10.java.external-input-to-ldap-filter
        return ctx.search("dc=example,dc=com", "(uid=alice)", null);
    }
}
