import jakarta.annotation.PermitAll;

class kisa_sw_18_missing_authentication {
    // ruleid: kisa.sw18.java.public-sensitive-endpoint-review
    @PermitAll
    public void unsafe() {
        System.out.println("sensitive action");
    }

    public void safe() {
        // ok: kisa.sw18.java.public-sensitive-endpoint-review
        System.out.println("protected elsewhere");
    }
}
