package com.dpi.pcap;

/**
 * PCAP per-packet header (16 bytes before every packet in the file).
 * Equivalent to C++ struct PcapPacketHeader.
 */
public class PcapPacketHeader {
    public long tsSec; // Timestamp seconds
    public long tsUsec; // Timestamp microseconds
    public long inclLen; // Bytes saved in file
    public long origLen; // Original packet length
}
