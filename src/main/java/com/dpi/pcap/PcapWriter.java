package com.dpi.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes binary PCAP files (little-endian, native magic).
 * Equivalent to the output-file writing in C++ DPIEngine.
 */
public class PcapWriter implements Closeable {

    private DataOutputStream out;
    private boolean open = false;

    /** Open (create/truncate) a PCAP output file. Returns true on success. */
    public boolean open(String filename) {
        try {
            out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
            open = true;
            return true;
        } catch (IOException e) {
            System.err.println("[PcapWriter] Cannot open output file: " + e.getMessage());
            return false;
        }
    }

    /** Write a global header that mirrors the source PCAP. */
    public boolean writeGlobalHeader(PcapGlobalHeader src) {
        if (!open)
            return false;
        try {
            ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt((int) (src.magicNumber & 0xFFFFFFFFL));
            bb.putShort((short) (src.versionMajor & 0xFFFF));
            bb.putShort((short) (src.versionMinor & 0xFFFF));
            bb.putInt(src.thiszone);
            bb.putInt((int) (src.sigfigs & 0xFFFFFFFFL));
            bb.putInt((int) (src.snaplen & 0xFFFFFFFFL));
            bb.putInt((int) (src.network & 0xFFFFFFFFL));
            out.write(bb.array());
            return true;
        } catch (IOException e) {
            System.err.println("[PcapWriter] Error writing global header: " + e.getMessage());
            return false;
        }
    }

    /** Write a single packet (header + data). */
    public synchronized void writePacket(long tsSec, long tsUsec, byte[] data) {
        if (!open || data == null)
            return;
        try {
            ByteBuffer bb = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt((int) (tsSec & 0xFFFFFFFFL));
            bb.putInt((int) (tsUsec & 0xFFFFFFFFL));
            bb.putInt(data.length);
            bb.putInt(data.length);
            out.write(bb.array());
            out.write(data);
        } catch (IOException e) {
            System.err.println("[PcapWriter] Error writing packet: " + e.getMessage());
        }
    }

    public void flush() {
        if (out != null) {
            try {
                out.flush();
            } catch (IOException ignored) {
            }
        }
    }

    @Override
    public void close() {
        open = false;
        if (out != null) {
            try {
                out.flush();
                out.close();
            } catch (IOException ignored) {
            }
            out = null;
        }
    }
}
