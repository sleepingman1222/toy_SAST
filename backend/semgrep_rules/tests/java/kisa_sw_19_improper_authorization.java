import javax.servlet.http.HttpServletRequest;

class kisa_sw_19_improper_authorization {
    Object unsafe(HttpServletRequest req, Repository repo) {
        // ruleid: kisa.sw19.java.external-id-object-access-review
        return repo.findById(req.getParameter("id"));
    }

    Object safe(HttpServletRequest req, Repository repo, String userId) {
        // ok: kisa.sw19.java.external-id-object-access-review
        return repo.findByIdAndOwner(req.getParameter("id"), userId);
    }

    interface Repository {
        Object findById(String id);
        Object findByIdAndOwner(String id, String owner);
    }
}
