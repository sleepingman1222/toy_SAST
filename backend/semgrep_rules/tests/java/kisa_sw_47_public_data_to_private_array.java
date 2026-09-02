class kisa_sw_47_public_data_to_private_array {
    private int[] items;

    public kisa_sw_47_public_data_to_private_array(int[] items) {
        // ruleid: kisa.sw47.java.public-array-assigned-to-private-field
        this.items = items;
    }
}

class Safe47 {
    private int[] items;
    public Safe47(int[] items) {
        // ok: kisa.sw47.java.public-array-assigned-to-private-field
        this.items = items.clone();
    }
}
