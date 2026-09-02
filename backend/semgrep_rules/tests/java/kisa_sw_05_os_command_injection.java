import javax.servlet.http.HttpServletRequest;

class kisa_sw_05_os_command_injection {
    Process unsafe(HttpServletRequest req) throws Exception {
        String host = req.getParameter("host");
        // ruleid: kisa.sw05.java.external-input-to-command
        return Runtime.getRuntime().exec("ping " + host);
    }

    Process safe(HttpServletRequest req) throws Exception {
        String host = req.getParameter("host");
        // ok: kisa.sw05.java.external-input-to-command
        return new ProcessBuilder("ping", host).start();
    }
}
