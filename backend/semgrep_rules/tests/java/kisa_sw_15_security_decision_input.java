import javax.servlet.http.HttpServletRequest;
class kisa_sw_15_security_decision_input {
    boolean unsafe(HttpServletRequest req) {
        // ruleid: kisa.sw15.java.external-input-controls-security-decision
        return "admin".equals(req.getParameter("role"));
    }
    boolean safe(HttpServletRequest req) {
        // ok: kisa.sw15.java.external-input-controls-security-decision
        return req.isUserInRole("admin");
    }
}
