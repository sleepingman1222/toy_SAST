import java.net.*;
class kisa_sw_32_download_without_integrity {
    Object unsafe(String url) throws Exception {
        // ruleid: kisa.sw32.java.remote-code-loader-review
        return new URLClassLoader(new URL[]{new URL(url)});
    }
    Object safe() {
        // ok: kisa.sw32.java.remote-code-loader-review
        return getClass().getClassLoader();
    }
}
