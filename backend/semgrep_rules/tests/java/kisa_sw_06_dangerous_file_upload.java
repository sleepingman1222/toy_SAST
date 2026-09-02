import java.io.File;
import org.springframework.web.multipart.MultipartFile;

class kisa_sw_06_dangerous_file_upload {
    void unsafe(MultipartFile upload) throws Exception {
        // ruleid: kisa.sw06.java.unvalidated-upload-filename
        upload.transferTo(new File(upload.getOriginalFilename()));
    }

    void safe(MultipartFile upload, File generated) throws Exception {
        // ok: kisa.sw06.java.unvalidated-upload-filename
        upload.transferTo(generated);
    }
}
