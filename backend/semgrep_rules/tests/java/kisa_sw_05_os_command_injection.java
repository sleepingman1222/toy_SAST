import javax.servlet.http.HttpServletRequest;

class kisa_sw_05_os_command_injection {

    Process unsafeConcat(
        HttpServletRequest req
    ) throws Exception {
        String host =
            req.getParameter("host");

        // ruleid: kisa.sw05.java.external-input-to-command
        return Runtime.getRuntime().exec("ping " + host);
    }


    Process unsafeDirectCommand(
        HttpServletRequest req
    ) throws Exception {
        String command =
            req.getParameter("command");

        // ruleid: kisa.sw05.java.external-input-to-command
        return Runtime.getRuntime().exec(command);
    }


    Process unsafeIntermediate(
        HttpServletRequest req
    ) throws Exception {
        String host =
            req.getHeader("X-Host");

        String command =
            "nslookup " + host;

        String copiedCommand =
            command;

        // ruleid: kisa.sw05.java.external-input-to-command
        return Runtime.getRuntime().exec(copiedCommand);
    }


    Process unsafeDynamicExecutable(
        HttpServletRequest req
    ) throws Exception {
        String executable =
            req.getParameter("bin");

        // ruleid: kisa.sw05.java.external-input-to-command
        return new ProcessBuilder(executable, "--version").start();
    }


    Process unsafeShellCommand(
        HttpServletRequest req
    ) throws Exception {
        String host =
            req.getParameter("host");

        String command =
            "ping " + host;

        // ruleid: kisa.sw05.java.external-input-to-command
        return new ProcessBuilder("sh", "-c", command).start();
    }


    Process safeSeparatedArgument(
        HttpServletRequest req
    ) throws Exception {
        String host =
            req.getParameter("host");

        // ok: kisa.sw05.java.external-input-to-command
        return new ProcessBuilder(
            "ping",
            host
        ).start();
    }


    Process safeHardcodedRuntime()
        throws Exception {

        // ok: kisa.sw05.java.external-input-to-command
        return Runtime.getRuntime().exec("uptime");
    }


    Process safeHardcodedProcessBuilder()
        throws Exception {

        // ok: kisa.sw05.java.external-input-to-command
        return new ProcessBuilder(
            "ping",
            "127.0.0.1"
        ).start();
    }
}
