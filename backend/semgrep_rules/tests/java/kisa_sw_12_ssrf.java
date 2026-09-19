import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpRequest;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.HttpGet;
import org.springframework.web.client.RestTemplate;


class kisa_sw_12_ssrf {
    HttpURLConnection unsafeUrlConnection(
        HttpServletRequest req
    ) throws Exception {
        String url = req.getParameter("url");

        // ruleid: kisa.sw12.java.external-input-to-http-client
        return (HttpURLConnection) new URL(url).openConnection();
    }


    HttpRequest.Builder unsafeJavaHttpClient(
        HttpServletRequest req
    ) {
        String callback = req.getHeader("X-Callback-URL");
        String copiedCallback = callback;

        // ruleid: kisa.sw12.java.external-input-to-http-client
        return HttpRequest.newBuilder(URI.create(copiedCallback));
    }


    String unsafeSpringRestTemplate(
        HttpServletRequest req,
        RestTemplate restTemplate
    ) {
        String target = req.getParameter("target");

        // ruleid: kisa.sw12.java.external-input-to-http-client
        return restTemplate.getForObject(target, String.class);
    }


    HttpGet unsafeApacheHttpClient(
        HttpServletRequest req
    ) {
        String target = req.getQueryString();

        // ruleid: kisa.sw12.java.external-input-to-http-client
        return new HttpGet(target);
    }


    URL safeHardcodedUrl() throws Exception {
        // ok: kisa.sw12.java.external-input-to-http-client
        return new URL("https://api.example.com/status");
    }


    HttpRequest.Builder safeHardcodedHttpRequest() {
        // ok: kisa.sw12.java.external-input-to-http-client
        return HttpRequest.newBuilder(
            URI.create("https://api.example.com/status")
        );
    }
}
