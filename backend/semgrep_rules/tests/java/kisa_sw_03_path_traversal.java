import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.http.HttpServletRequest;

class kisa_sw_03_path_traversal {

    FileInputStream unsafeDirectRead(
        HttpServletRequest request
    ) throws Exception {
        String path =
            request.getParameter("path");

        // ruleid: kisa.sw03.java.external-input-to-file-path
        return new FileInputStream(path);
    }


    String unsafeResolveOnly(
        HttpServletRequest request,
        Path base
    ) throws Exception {
        String relative =
            request.getParameter("path");

        Path candidate =
            base.resolve(relative).normalize();

        // normalize만으로는 base 이탈을 막지 않는다.
        // ruleid: kisa.sw03.java.external-input-to-file-path
        return Files.readString(candidate);
    }


    byte[] unsafeMultiStep(
        HttpServletRequest request
    ) throws Exception {
        String raw =
            request.getHeader("X-File");

        String first =
            raw;

        Path candidate =
            Paths.get(first);

        // ruleid: kisa.sw03.java.external-input-to-file-path
        return Files.readAllBytes(candidate);
    }


    void unsafeDelete(
        HttpServletRequest request
    ) throws Exception {
        Path target =
            Paths.get(
                request.getParameter("target")
            );

        // ruleid: kisa.sw03.java.external-input-to-file-path
        Files.delete(target);
    }


    FileOutputStream unsafeWrite(
        HttpServletRequest request
    ) throws Exception {
        String target =
            request.getParameter("output");

        // ruleid: kisa.sw03.java.external-input-to-file-path
        return new FileOutputStream(target);
    }


    FileInputStream safeBasename(
        HttpServletRequest request,
        File base
    ) throws Exception {
        String name =
            new File(
                request.getParameter("path")
            ).getName();

        File target =
            new File(base, name);

        // ok: kisa.sw03.java.external-input-to-file-path
        return new FileInputStream(target);
    }


    String safeGetFileName(
        HttpServletRequest request,
        Path base
    ) throws Exception {
        String name =
            Paths.get(
                request.getParameter("path")
            ).getFileName().toString();

        Path target =
            base.resolve(name);

        // ok: kisa.sw03.java.external-input-to-file-path
        return Files.readString(target);
    }


    String safeHardcoded()
        throws Exception {

        // ok: kisa.sw03.java.external-input-to-file-path
        return Files.readString(
            Paths.get("/srv/app/public/help.txt")
        );
    }
}
