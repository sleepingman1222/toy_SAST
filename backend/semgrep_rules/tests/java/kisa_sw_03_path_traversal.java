import java.io.File;
import javax.servlet.http.HttpServletRequest;

class kisa_sw_03_path_traversal {
    File unsafe(HttpServletRequest request) {
        String path = request.getParameter("path");
        // ruleid: kisa.sw03.java.external-input-to-file-path
        return new File(path);
    }

    File safe(File base, HttpServletRequest request) throws Exception {
        String name = new File(request.getParameter("path")).getName();
        // ok: kisa.sw03.java.external-input-to-file-path
        return new File(base, name).getCanonicalFile();
    }
}
