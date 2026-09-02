import javax.servlet.http.HttpServletRequest;
class kisa_sw_17_format_string_injection {
    String unsafe(HttpServletRequest req, Object value) {
        String fmt = req.getParameter("fmt");
        // ruleid: kisa.sw17.java.external-input-as-format-string
        return String.format(fmt, value);
    }
    String safe(HttpServletRequest req) {
        String value = req.getParameter("value");
        // ok: kisa.sw17.java.external-input-as-format-string
        return String.format("value=%s", value);
    }
}
