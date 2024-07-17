package com.dpi;

import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.RawPacket;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Simple packet analyzer entry point.
 * Reads a PCAP file and prints per-packet summaries.
 * Equivalent to C++ src/main.cpp.
 *
 * Usage: java com.dpi.Main <pcap_file> [max_packets]
 */
public class Main {

    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0  (Java)  ");
        System.out.println("====================================\n");

        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String filename = args[0];
        int maxPackets = args.length >= 2 ? Integer.parseInt(args[1]) : -1;

        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(filename))
                System.exit(1);

            System.out.println("\n--- Reading packets ---");

            RawPacket raw;
            int packetCount = 0, parseErrors = 0;

            while ((raw = reader.readNextPacket()) != null) {
                packetCount++;

                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed != null) {
                    printPacketSummary(parsed, packetCount);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    parseErrors++;
                }

                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }

            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.println("  Total packets read:  " + packetCount);
            System.out.println("  Parse errors:        " + parseErrors);
            System.out.println("====================================");
        }
    }

    private static void printPacketSummary(ParsedPacket pkt, int num) {
        System.out.println("\n========== Packet #" + num + " ==========");

        // Timestamp
        LocalDateTime ts = LocalDateTime.ofInstant(
                Instant.ofEpochSecond(pkt.timestampSec), ZoneId.systemDefault());
        System.out.printf("Time: %s.%06d%n", ts.format(TS_FMT), pkt.timestampUsec);

        // Ethernet
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        String etherTypeStr = switch (pkt.etherType) {
            case PacketParser.ETHERTYPE_IPV4 -> String.format("0x%04x (IPv4)", pkt.etherType);
            case PacketParser.ETHERTYPE_IPV6 -> String.format("0x%04x (IPv6)", pkt.etherType);
            case PacketParser.ETHERTYPE_ARP -> String.format("0x%04x (ARP)", pkt.etherType);
            default -> String.format("0x%04x", pkt.etherType);
        };
        System.out.println("  EtherType:       " + etherTypeStr);

        // IP
        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }

        // TCP
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }

        // UDP
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
        }

        // Payload preview
        if (pkt.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java com.dpi.Main <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file");
        System.out.println("  max_packets - (Optional) Max number of packets to display");
        System.out.println("\nExamples:");
        System.out.println("  java com.dpi.Main capture.pcap");
        System.out.println("  java com.dpi.Main capture.pcap 10");
    }
}
