import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.http.HttpServletRequest;

class CodeInjectionBad {

    public Object execute(
        HttpServletRequest request
    ) throws Exception {

        String code =
            request.getParameter("code");

        ScriptEngineManager manager =
            new ScriptEngineManager();

        ScriptEngine engine =
            manager.getEngineByName(
                "javascript"
            );

        return engine.eval(
            code
        );
    }
}
