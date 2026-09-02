import java.io.*;
class kisa_sw_40_resource_leak {
    int unsafe(String path) throws Exception {
        // ruleid: kisa.sw40.java.closeable-without-try-with-resources-review
        InputStream in = new FileInputStream(path);
        return in.read();
    }
    int safe(String path) throws Exception {
        // ok: kisa.sw40.java.closeable-without-try-with-resources-review
        try (InputStream in = new FileInputStream(path)) {
            return in.read();
        }
    }
}
