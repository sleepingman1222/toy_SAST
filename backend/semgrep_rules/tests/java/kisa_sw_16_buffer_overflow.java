class kisa_sw_16_buffer_overflow {
    void unsafe(sun.misc.Unsafe u, long src, long dst, long size) {
        // ruleid: kisa.sw16.java.unsafe-native-memory-operation-review
        u.copyMemory(src, dst, size);
    }
    byte[] safe(byte[] src) {
        // ok: kisa.sw16.java.unsafe-native-memory-operation-review
        return java.util.Arrays.copyOf(src, src.length);
    }
}
