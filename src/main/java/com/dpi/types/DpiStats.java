package com.dpi.types;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Global engine statistics — all fields are atomic for concurrent access.
 * Equivalent to C++ struct DPIStats.
 */
public class DpiStats {

    public final AtomicLong totalPackets       = new AtomicLong(0);
    public final AtomicLong totalBytes         = new AtomicLong(0);
    public final AtomicLong forwardedPackets   = new AtomicLong(0);
    public final AtomicLong droppedPackets     = new AtomicLong(0);
    public final AtomicLong tcpPackets         = new AtomicLong(0);
    public final AtomicLong udpPackets         = new AtomicLong(0);
    public final AtomicLong otherPackets       = new AtomicLong(0);
    public final AtomicLong activeConnections  = new AtomicLong(0);
}
