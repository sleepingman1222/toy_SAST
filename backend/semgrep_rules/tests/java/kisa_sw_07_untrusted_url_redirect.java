import javax.servlet.http.*;

class kisa_sw_07_untrusted_url_redirect {
    void unsafe(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String next = req.getParameter("next");
        // ruleid: kisa.sw07.java.external-input-to-redirect
        resp.sendRedirect(next);
    }
    void safe(HttpServletResponse resp) throws Exception {
        // ok: kisa.sw07.java.external-input-to-redirect
        resp.sendRedirect("/home");
    }
}
