package com.dpi.types;

import java.util.Objects;

/**
 * Five-tuple that uniquely identifies a network flow/connection.
 * Equivalent to C++ struct FiveTuple.
 *
 * All IP addresses are stored as long (using only lower 32 bits)
 * and ports as int (using only lower 16 bits) to handle unsigned values.
 */
public final class FiveTuple {

    /** Source IP as unsigned 32-bit value stored in long. */
    public final long srcIp;
    /** Destination IP as unsigned 32-bit value stored in long. */
    public final long dstIp;
    /** Source port (0-65535). */
    public final int srcPort;
    /** Destination port (0-65535). */
    public final int dstPort;
    /** IP protocol: 6=TCP, 17=UDP. */
    public final int protocol;

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp & 0xFFFFFFFFL;
        this.dstIp    = dstIp & 0xFFFFFFFFL;
        this.srcPort  = srcPort & 0xFFFF;
        this.dstPort  = dstPort & 0xFFFF;
        this.protocol = protocol & 0xFF;
    }

    /** Returns the reverse/opposite direction tuple (for bidirectional matching). */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    // -----------------------------------------------------------------------
    // Object overrides
    // -----------------------------------------------------------------------

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp
                && srcPort == t.srcPort && dstPort == t.dstPort
                && protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        // Equivalent to C++ FiveTupleHash — combine all fields with boost-style mixing
        long h = 0;
        h = mix(h, srcIp);
        h = mix(h, dstIp);
        h = mix(h, srcPort);
        h = mix(h, dstPort);
        h = mix(h, protocol);
        return (int)(h ^ (h >>> 32));
    }

    private static long mix(long h, long value) {
        h ^= Long.hashCode(value) + 0x9e3779b97f4a7c15L + (h << 6) + (h >>> 2);
        return h;
    }

    @Override
    public String toString() {
        String proto = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : String.valueOf(protocol);
        return String.format("%s:%d -> %s:%d (%s)",
                ipToString(srcIp), srcPort,
                ipToString(dstIp), dstPort,
                proto);
    }

    /** Convert a 32-bit IP (stored as long/int) to dotted-decimal string. */
    public static String ipToString(long ip) {
        return String.format("%d.%d.%d.%d",
                (ip       ) & 0xFF,
                (ip >>>  8) & 0xFF,
                (ip >>> 16) & 0xFF,
                (ip >>> 24) & 0xFF);
    }

    /** Parse "a.b.c.d" into an unsigned 32-bit value stored as long. */
    public static long parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return 0L;
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(parts[i].trim()) & 0xFF) << (i * 8);
        }
        return result;
    }
}
