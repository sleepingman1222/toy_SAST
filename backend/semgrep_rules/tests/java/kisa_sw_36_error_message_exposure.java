import javax.servlet.http.HttpServletResponse;
class kisa_sw_36_error_message_exposure {
    void unsafe(HttpServletResponse resp, Exception e) throws Exception {
        // ruleid: kisa.sw36.java.exception-detail-to-response
        resp.getWriter().write(e.getMessage());
    }
    void safe(HttpServletResponse resp) throws Exception {
        // ok: kisa.sw36.java.exception-detail-to-response
        resp.sendError(500, "internal error");
    }
}
