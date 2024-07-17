package com.dpi.pcap;

/**
 * PCAP global file header (first 24 bytes of every .pcap file).
 * Equivalent to C++ struct PcapGlobalHeader.
 */
public class PcapGlobalHeader {
    public long magicNumber; // 0xa1b2c3d4
    public int versionMajor; // Usually 2
    public int versionMinor; // Usually 4
    public int thiszone; // GMT offset (usually 0)
    public long sigfigs; // Timestamp accuracy (usually 0)
    public long snaplen; // Max captured packet length
    public long network; // Data link type (1 = Ethernet)
}
