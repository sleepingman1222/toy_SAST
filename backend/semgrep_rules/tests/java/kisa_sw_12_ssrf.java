import java.net.URL;
import javax.servlet.http.HttpServletRequest;
class kisa_sw_12_ssrf {
    URL unsafe(HttpServletRequest req) throws Exception {
        String url = req.getParameter("url");
        // ruleid: kisa.sw12.java.external-input-to-http-client
        return new URL(url);
    }
    URL safe() throws Exception {
        // ok: kisa.sw12.java.external-input-to-http-client
        return new URL("https://api.example.com/status");
    }
}
