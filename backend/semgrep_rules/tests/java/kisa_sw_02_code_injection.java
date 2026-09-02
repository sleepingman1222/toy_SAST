import javax.script.ScriptEngine;
import javax.servlet.http.HttpServletRequest;


public class KisaSw02CodeInjection {

    public Object unsafeParameter(
        HttpServletRequest request,
        ScriptEngine engine
    ) throws Exception {

        String code =
            request.getParameter(
                "code"
            );

        // ruleid: kisa.sw02.java.external-input-to-script-engine
        return engine.eval(
            code
        );
    }


    public Object unsafeHeader(
        HttpServletRequest request,
        ScriptEngine engine
    ) throws Exception {

        String code =
            request.getHeader(
                "X-Script"
            );

        // ruleid: kisa.sw02.java.external-input-to-script-engine
        return engine.eval(
            code
        );
    }


    public Object unsafeQueryString(
        HttpServletRequest request,
        ScriptEngine engine
    ) throws Exception {

        String query =
            request.getQueryString();

        // ruleid: kisa.sw02.java.external-input-to-script-engine
        return engine.eval(
            query
        );
    }


    public String safeValue(
        HttpServletRequest request
    ) {

        String value =
            request.getParameter(
                "value"
            );

        // ok: kisa.sw02.java.external-input-to-script-engine
        return value;
    }


    public String safeMapping(
        HttpServletRequest request
    ) {

        String action =
            request.getParameter(
                "action"
            );

        // ok: kisa.sw02.java.external-input-to-script-engine
        if (
            "list".equals(
                action
            )
        ) {
            return "list";
        }

        if (
            "detail".equals(
                action
            )
        ) {
            return "detail";
        }

        return "unknown";
    }
}