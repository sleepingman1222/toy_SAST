class kisa_sw_41_use_after_free {
    byte unsafe(sun.misc.Unsafe u, long addr) {
        u.freeMemory(addr);
        // ruleid: kisa.sw41.java.unsafe-use-after-free-review
        return u.getByte(addr);
    }
    byte safe(sun.misc.Unsafe u, long addr) {
        byte value = u.getByte(addr);
        u.freeMemory(addr);
        // ok: kisa.sw41.java.unsafe-use-after-free-review
        return value;
    }
}
