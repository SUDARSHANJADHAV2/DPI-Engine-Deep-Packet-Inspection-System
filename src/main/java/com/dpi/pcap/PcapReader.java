package com.dpi.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads binary PCAP files in both native and byte-swapped formats.
 * Equivalent to C++ class PcapReader.
 *
 * Java uses signed bytes, so all reads are masked with & 0xFF (byte),
 * & 0xFFFF (short), 0xFFFFFFFFL (int→long) where necessary.
 */
public class PcapReader implements Closeable {

    private static final long PCAP_MAGIC_NATIVE = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    private DataInputStream in;
    private PcapGlobalHeader globalHeader;
    private boolean needsByteSwap = false;
    private boolean open = false;

    /** Open a PCAP file for reading. Returns true on success. */
    public boolean open(String filename) {
        try {
            in = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));
            return readGlobalHeader(filename);
        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename + " — " + e.getMessage());
            return false;
        }
    }

    private boolean readGlobalHeader(String filename) throws IOException {
        byte[] buf = new byte[24];
        int read = in.read(buf);
        if (read < 24) {
            System.err.println("Error: Could not read PCAP global header from " + filename);
            return false;
        }

        // Peek at magic number (first 4 bytes, little-endian)
        long magicLE = ((long) (buf[0] & 0xFF))
                | ((long) (buf[1] & 0xFF) << 8)
                | ((long) (buf[2] & 0xFF) << 16)
                | ((long) (buf[3] & 0xFF) << 24);

        if (magicLE == PCAP_MAGIC_NATIVE) {
            needsByteSwap = false;
        } else if (magicLE == PCAP_MAGIC_SWAPPED) {
            needsByteSwap = true;
        } else {
            System.err.printf("Error: Invalid PCAP magic number: 0x%08X%n", magicLE);
            return false;
        }

        ByteBuffer bb = ByteBuffer.wrap(buf);
        bb.order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

        globalHeader = new PcapGlobalHeader();
        globalHeader.magicNumber = bb.getInt() & 0xFFFFFFFFL;
        globalHeader.versionMajor = bb.getShort() & 0xFFFF;
        globalHeader.versionMinor = bb.getShort() & 0xFFFF;
        globalHeader.thiszone = bb.getInt();
        globalHeader.sigfigs = bb.getInt() & 0xFFFFFFFFL;
        globalHeader.snaplen = bb.getInt() & 0xFFFFFFFFL;
        globalHeader.network = bb.getInt() & 0xFFFFFFFFL;

        System.out.println("Opened PCAP file: " + filename);
        System.out.printf("  Version: %d.%d%n", globalHeader.versionMajor, globalHeader.versionMinor);
        System.out.printf("  Snaplen: %d bytes%n", globalHeader.snaplen);
        System.out.printf("  Link type: %d%s%n", globalHeader.network,
                globalHeader.network == 1 ? " (Ethernet)" : "");

        open = true;
        return true;
    }

    /**
     * Read the next packet from the file.
     * 
     * @return the packet, or null if end-of-file or error.
     */
    public RawPacket readNextPacket() {
        if (!open)
            return null;
        try {
            byte[] hdrBuf = new byte[16];
            int r = in.read(hdrBuf);
            if (r < 16)
                return null; // EOF

            ByteBuffer bb = ByteBuffer.wrap(hdrBuf);
            bb.order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

            RawPacket pkt = new RawPacket();
            pkt.header.tsSec = bb.getInt() & 0xFFFFFFFFL;
            pkt.header.tsUsec = bb.getInt() & 0xFFFFFFFFL;
            pkt.header.inclLen = bb.getInt() & 0xFFFFFFFFL;
            pkt.header.origLen = bb.getInt() & 0xFFFFFFFFL;

            // Sanity check
            if (pkt.header.inclLen > globalHeader.snaplen || pkt.header.inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + pkt.header.inclLen);
                return null;
            }

            pkt.data = new byte[(int) pkt.header.inclLen];
            int totalRead = 0;
            while (totalRead < pkt.data.length) {
                int n = in.read(pkt.data, totalRead, pkt.data.length - totalRead);
                if (n < 0) {
                    System.err.println("Error: Unexpected EOF while reading packet data");
                    return null;
                }
                totalRead += n;
            }
            return pkt;
        } catch (EOFException e) {
            return null;
        } catch (IOException e) {
            return null;
        }
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public boolean isOpen() {
        return open;
    }

    public boolean needsByteSwap() {
        return needsByteSwap;
    }

    @Override
    public void close() {
        open = false;
        if (in != null) {
            try {
                in.close();
            } catch (IOException ignored) {
            }
            in = null;
        }
    }
}
