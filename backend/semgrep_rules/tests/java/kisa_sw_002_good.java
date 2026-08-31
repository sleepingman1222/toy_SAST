import javax.servlet.http.HttpServletRequest;

class CodeInjectionGood {

    public String execute(
        HttpServletRequest request
    ) {

        String action =
            request.getParameter("action");

        if (
            "status".equals(action)
        ) {

            return getStatus();
        }

        if (
            "version".equals(action)
        ) {

            return getVersion();
        }

        throw new IllegalArgumentException(
            "허용되지 않은 요청입니다."
        );
    }


    private String getStatus() {

        return "OK";
    }


    private String getVersion() {

        return "1.0";
    }
}
