package com.dpi.parser;

import com.dpi.pcap.RawPacket;

/**
 * Parses raw packet bytes into a {@link ParsedPacket}.
 * Equivalent to C++ class PacketParser.
 *
 * All integer values are treated as unsigned via masking (&amp; 0xFF, 0xFFFF,
 * 0xFFFFFFFFL).
 * Big-endian (network byte order) reading is done manually without ByteBuffer
 * to stay
 * close to the original C++ logic.
 */
public class PacketParser {

    // EtherType constants
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP = 0x0806;

    // Protocol numbers
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    // TCP flag bitmasks
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    /**
     * Parse a raw packet. Returns null if parsing fails.
     */
    public static ParsedPacket parse(RawPacket raw) {
        if (raw == null || raw.data == null || raw.data.length < 14)
            return null;

        ParsedPacket p = new ParsedPacket();
        p.timestampSec = raw.header.tsSec;
        p.timestampUsec = raw.header.tsUsec;

        byte[] data = raw.data;
        int offset = 0;

        // ---- Ethernet header (14 bytes) ----
        if (!parseEthernet(data, p))
            return null;
        offset = 14;

        // ---- IPv4 ----
        if (p.etherType == ETHERTYPE_IPV4) {
            int ipHeaderLen = parseIPv4(data, offset, p);
            if (ipHeaderLen < 0)
                return null;
            offset += ipHeaderLen;

            // ---- TCP ----
            if (p.protocol == PROTO_TCP) {
                int tcpHeaderLen = parseTCP(data, offset, p);
                if (tcpHeaderLen < 0)
                    return null;
                offset += tcpHeaderLen;

                // ---- UDP ----
            } else if (p.protocol == PROTO_UDP) {
                if (!parseUDP(data, offset, p))
                    return null;
                offset += 8;
            }
        }

        // Payload
        if (offset < data.length) {
            p.payloadOffset = offset;
            p.payloadLength = data.length - offset;
        }

        return p;
    }

    // -------------------------------------------------------------------------
    // Ethernet
    // -------------------------------------------------------------------------
    private static boolean parseEthernet(byte[] data, ParsedPacket p) {
        if (data.length < 14)
            return false;
        p.destMac = macToString(data, 0);
        p.srcMac = macToString(data, 6);
        p.etherType = readUint16BE(data, 12);
        return true;
    }

    // -------------------------------------------------------------------------
    // IPv4 — returns IP header length in bytes, or -1 on error
    // -------------------------------------------------------------------------
    private static int parseIPv4(byte[] data, int offset, ParsedPacket p) {
        if (data.length < offset + 20)
            return -1;

        int versionIhl = data[offset] & 0xFF;
        p.ipVersion = (versionIhl >> 4) & 0x0F;
        if (p.ipVersion != 4)
            return -1;

        int ihl = versionIhl & 0x0F;
        int headerLen = ihl * 4;
        if (headerLen < 20 || data.length < offset + headerLen)
            return -1;

        p.ttl = data[offset + 8] & 0xFF;
        p.protocol = data[offset + 9] & 0xFF;

        // Source IP (bytes 12-15, network byte order / big-endian)
        long srcIp = readUint32BE(data, offset + 12);
        long dstIp = readUint32BE(data, offset + 16);
        p.srcIp = ipToString(srcIp);
        p.destIp = ipToString(dstIp);
        p.hasIp = true;

        return headerLen;
    }

    // -------------------------------------------------------------------------
    // TCP — returns TCP header length in bytes, or -1 on error
    // -------------------------------------------------------------------------
    private static int parseTCP(byte[] data, int offset, ParsedPacket p) {
        if (data.length < offset + 20)
            return -1;

        p.srcPort = readUint16BE(data, offset);
        p.destPort = readUint16BE(data, offset + 2);
        p.seqNumber = readUint32BE(data, offset + 4);
        p.ackNumber = readUint32BE(data, offset + 8);

        int dataOffset = (data[offset + 12] & 0xFF) >> 4;
        int headerLen = dataOffset * 4;
        if (headerLen < 20 || data.length < offset + headerLen)
            return -1;

        p.tcpFlags = data[offset + 13] & 0xFF;
        p.hasTcp = true;
        return headerLen;
    }

    // -------------------------------------------------------------------------
    // UDP — always 8-byte header
    // -------------------------------------------------------------------------
    private static boolean parseUDP(byte[] data, int offset, ParsedPacket p) {
        if (data.length < offset + 8)
            return false;
        p.srcPort = readUint16BE(data, offset);
        p.destPort = readUint16BE(data, offset + 2);
        p.hasUdp = true;
        return true;
    }

    // -------------------------------------------------------------------------
    // String helpers
    // -------------------------------------------------------------------------

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0)
                sb.append(':');
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    /** IPv4 stored as unsigned 32-bit in long, laid out as octets. */
    public static String ipToString(long ip) {
        return String.format("%d.%d.%d.%d",
                (ip) & 0xFF,
                (ip >> 8) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 24) & 0xFF);
    }

    public static String protocolToString(int proto) {
        return switch (proto) {
            case PROTO_ICMP -> "ICMP";
            case PROTO_TCP -> "TCP";
            case PROTO_UDP -> "UDP";
            default -> "Unknown(" + proto + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0)
            sb.append("SYN ");
        if ((flags & TCP_ACK) != 0)
            sb.append("ACK ");
        if ((flags & TCP_FIN) != 0)
            sb.append("FIN ");
        if ((flags & TCP_RST) != 0)
            sb.append("RST ");
        if ((flags & TCP_PSH) != 0)
            sb.append("PSH ");
        if ((flags & TCP_URG) != 0)
            sb.append("URG ");
        String s = sb.toString().trim();
        return s.isEmpty() ? "none" : s;
    }

    // -------------------------------------------------------------------------
    // Byte-order helpers (big-endian / network byte order)
    // -------------------------------------------------------------------------

    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    public static long readUint32BE(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
                | ((long) (data[offset + 1] & 0xFF) << 16)
                | ((long) (data[offset + 2] & 0xFF) << 8)
                | (long) (data[offset + 3] & 0xFF);
    }

    /** Read 3-byte big-endian unsigned integer. */
    public static int readUint24BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 16)
                | ((data[offset + 1] & 0xFF) << 8)
                | (data[offset + 2] & 0xFF);
    }
}
