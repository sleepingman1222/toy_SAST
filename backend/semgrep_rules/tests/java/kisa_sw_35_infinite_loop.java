class kisa_sw_35_infinite_loop {
    void unsafe() {
        // ruleid: kisa.sw35.java.obvious-infinite-loop
        while (true) {
            System.out.println("loop");
        }
    }
    void safe(int n) {
        // ok: kisa.sw35.java.obvious-infinite-loop
        for (int i = 0; i < n; i++) System.out.println(i);
    }
}
