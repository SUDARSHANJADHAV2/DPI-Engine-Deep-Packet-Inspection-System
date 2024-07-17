package com.dpi.parser;

/**
 * Human-readable parsed packet — output of PacketParser.
 * Equivalent to C++ struct ParsedPacket.
 */
public class ParsedPacket {

    // Timestamps
    public long timestampSec;
    public long timestampUsec;

    // Ethernet layer
    public String srcMac = "";
    public String destMac = "";
    public int etherType = 0; // 0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP

    // IP layer
    public boolean hasIp = false;
    public int ipVersion = 0;
    public String srcIp = "";
    public String destIp = "";
    public int protocol = 0; // 6=TCP, 17=UDP, 1=ICMP
    public int ttl = 0;

    // Transport layer
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort = 0;
    public int destPort = 0;

    // TCP-specific
    public int tcpFlags = 0;
    public long seqNumber = 0;
    public long ackNumber = 0;

    // Payload
    public int payloadLength = 0;
    /** Byte offset into the original raw packet where payload starts. */
    public int payloadOffset = 0;
}
