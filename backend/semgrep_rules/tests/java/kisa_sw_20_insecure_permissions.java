import java.io.File;
class kisa_sw_20_insecure_permissions {
    void unsafe(File file) {
        // ruleid: kisa.sw20.java.world-accessible-permission
        file.setWritable(true, false);
    }
    void safe(File file) {
        // ok: kisa.sw20.java.world-accessible-permission
        file.setWritable(true, true);
    }
}
