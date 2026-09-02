import javax.servlet.http.HttpServletRequest;
class kisa_sw_14_integer_overflow {
    int unsafe(HttpServletRequest req, int count) {
        int size = Integer.parseInt(req.getParameter("size"));
        // ruleid: kisa.sw14.java.external-input-arithmetic-review
        return size * count;
    }
    long safe(HttpServletRequest req, int count) {
        long size = Long.parseLong(req.getParameter("size"));
        // ok: kisa.sw14.java.external-input-arithmetic-review
        return Math.multiplyExact(size, count);
    }
}
