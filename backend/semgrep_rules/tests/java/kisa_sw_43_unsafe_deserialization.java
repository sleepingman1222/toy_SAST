import java.io.*;
import javax.servlet.http.HttpServletRequest;
class kisa_sw_43_unsafe_deserialization {
    Object unsafe(HttpServletRequest req) throws Exception {
        String data = req.getParameter("data");
        ByteArrayInputStream in = new ByteArrayInputStream(data.getBytes());
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: kisa.sw43.java.external-input-to-object-deserialization
        return ois.readObject();
    }
    String safe(HttpServletRequest req) {
        // ok: kisa.sw43.java.external-input-to-object-deserialization
        return req.getParameter("data");
    }
}
