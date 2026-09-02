class kisa_sw_46_private_array_return {
    private int[] items = {1, 2};

    public int[] unsafe() {
        // ruleid: kisa.sw46.java.private-array-return
        return items;
    }

    public int[] safe() {
        // ok: kisa.sw46.java.private-array-return
        return items.clone();
    }
}
