import java.nio.file.*;
import java.io.*;
class kisa_sw_34_toctou {
    InputStream unsafe(Path path) throws Exception {
        if (Files.exists(path)) {
            // ruleid: kisa.sw34.java.check-then-use-file
            return Files.newInputStream(path);
        }
        return null;
    }
    OutputStream safe(Path path) throws Exception {
        // ok: kisa.sw34.java.check-then-use-file
        return Files.newOutputStream(path, StandardOpenOption.CREATE_NEW);
    }
}
