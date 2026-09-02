import javax.xml.xpath.XPath;
import javax.servlet.http.HttpServletRequest;

class kisa_sw_09_xml_injection {
    Object unsafe(HttpServletRequest req, XPath xpath, Object doc) throws Exception {
        String q = req.getParameter("xpath");
        // ruleid: kisa.sw09.java.external-input-to-xpath
        return xpath.evaluate(q, doc);
    }
    Object safe(XPath xpath, Object doc) throws Exception {
        // ok: kisa.sw09.java.external-input-to-xpath
        return xpath.evaluate("/users/user", doc);
    }
}
