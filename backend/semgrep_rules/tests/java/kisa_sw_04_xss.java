import javax.servlet.http.*;

class kisa_sw_04_xss {
    void unsafe(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String q = req.getParameter("q");
        // ruleid: kisa.sw04.java.external-input-to-html-response
        resp.getWriter().write(q);
    }

    void safe(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String q = req.getParameter("q").replace("<", "&lt;").replace(">", "&gt;");
        // ok: kisa.sw04.java.external-input-to-html-response
        resp.getWriter().write(q);
    }
}
