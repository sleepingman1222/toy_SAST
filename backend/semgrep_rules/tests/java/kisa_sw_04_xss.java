import java.io.FileWriter;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.encoder.Encode;

class kisa_sw_04_xss {

    void unsafeDirect(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws Exception {
        String value =
            request.getParameter("q");

        // ruleid: kisa.sw04.java.external-input-to-html-response
        response.getWriter().write(value);
    }


    void unsafeConcat(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws Exception {
        String name =
            request.getParameter("name");

        String html =
            "<h1>Hello " + name + "</h1>";

        // ruleid: kisa.sw04.java.external-input-to-html-response
        response.getWriter().print(html);
    }


    void unsafeIntermediateWriter(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws Exception {
        String message =
            request.getHeader("X-Message");

        String html =
            "<div>" + message + "</div>";

        PrintWriter out =
            response.getWriter();

        // ruleid: kisa.sw04.java.external-input-to-html-response
        out.println(html);
    }


    void unsafeMultipleSteps(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws Exception {
        String value =
            request.getParameter("value");

        String first =
            value;

        String second =
            first;

        // ruleid: kisa.sw04.java.external-input-to-html-response
        response.getWriter().append(second);
    }


    void safeOwaspEncoder(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws Exception {
        String value =
            request.getParameter("q");

        String safe =
            Encode.forHtml(value);

        // ok: kisa.sw04.java.external-input-to-html-response
        response.getWriter().write(safe);
    }


    void safeHardcoded(
        HttpServletResponse response
    ) throws Exception {
        // ok: kisa.sw04.java.external-input-to-html-response
        response.getWriter().write("<h1>Hello</h1>");
    }


    void safeUnrelatedFileWriter(
        HttpServletRequest request,
        FileWriter writer
    ) throws Exception {
        String value =
            request.getParameter("q");

        // ok: kisa.sw04.java.external-input-to-html-response
        writer.write(value);
    }
}
