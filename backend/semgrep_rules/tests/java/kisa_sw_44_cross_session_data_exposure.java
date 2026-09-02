import javax.servlet.http.HttpServletRequest;
class kisa_sw_44_cross_session_data_exposure {
    static String profile;
    void unsafe(HttpServletRequest req) {
        // ruleid: kisa.sw44.java.request-data-to-static-state-review
        kisa_sw_44_cross_session_data_exposure.profile = req.getParameter("profile");
    }
    String safe(HttpServletRequest req) {
        // ok: kisa.sw44.java.request-data-to-static-state-review
        return req.getParameter("profile");
    }
}
