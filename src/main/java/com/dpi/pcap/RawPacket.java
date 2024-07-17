package com.dpi.pcap;

/**
 * A single raw captured packet (header + raw byte data).
 * Equivalent to C++ struct RawPacket.
 */
public class RawPacket {
    public PcapPacketHeader header = new PcapPacketHeader();
    public byte[] data;
}
