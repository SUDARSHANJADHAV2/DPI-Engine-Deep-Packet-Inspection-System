package com.dpi.types;

/**
 * Packet wrapper passed between pipeline stages (Reader → LB → FP → Output).
 * Equivalent to C++ struct PacketJob.
 *
 * All offsets are byte-indices into the {@code data} array.
 */
public class PacketJob {

    public long    packetId;
    public FiveTuple tuple;

    /** Full raw packet bytes (copy of the PCAP payload). */
    public byte[] data;

    public int ethOffset       = 0;
    public int ipOffset        = 0;
    public int transportOffset = 0;
    public int payloadOffset   = 0;
    public int payloadLength   = 0;
    public int tcpFlags        = 0;   // stored as int (unsigned byte)

    /** PCAP timestamps. */
    public long tsSec  = 0;
    public long tsUsec = 0;

    public PacketJob() {}

    /**
     * Convenience: return a view of the payload region.
     * Returns an empty array if there is no payload.
     */
    public byte[] getPayload() {
        if (payloadLength <= 0 || payloadOffset >= data.length) return new byte[0];
        int len = Math.min(payloadLength, data.length - payloadOffset);
        byte[] p = new byte[len];
        System.arraycopy(data, payloadOffset, p, 0, len);
        return p;
    }
}
