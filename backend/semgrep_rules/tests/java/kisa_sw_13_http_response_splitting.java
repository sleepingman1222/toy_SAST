import javax.servlet.http.*;
class kisa_sw_13_http_response_splitting {
    void unsafe(HttpServletRequest req, HttpServletResponse resp) {
        String v = req.getParameter("v");
        // ruleid: kisa.sw13.java.external-input-to-response-header
        resp.setHeader("X-User", v);
    }
    void safe(HttpServletResponse resp) {
        // ok: kisa.sw13.java.external-input-to-response-header
        resp.setHeader("X-User", "fixed");
    }
}
